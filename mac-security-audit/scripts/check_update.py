#!/usr/bin/env python3
"""Explicitly check or prepare an official skill update. Never install or execute it."""
import argparse
import datetime as dt
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import queue
import re
import stat
import sys
import threading
import time
import unicodedata
import urllib.error
import urllib.parse
import urllib.request
import zipfile

sys.dont_write_bytecode = True

REPOSITORY = 'hc85233221/codex-security-audit'
SKILL = 'mac-security-audit'
API = 'https://api.github.com/repos/' + REPOSITORY
REPO_URL = 'https://github.com/' + REPOSITORY
VERSION_RE = re.compile(r'(0|[1-9][0-9]{0,5})\.(0|[1-9][0-9]{0,5})\.(0|[1-9][0-9]{0,5})\Z')
SHA_RE = re.compile(r'[0-9a-f]{40}\Z')
MAX_JSON = 256 * 1024
MAX_ARCHIVE = 10 * 1024 * 1024
MAX_FILE = 2 * 1024 * 1024
MAX_ENTRIES = 500
REQUEST_DEADLINE = 30


class UpdateError(ValueError):
    pass


def version(value):
    if not isinstance(value, str) or not VERSION_RE.fullmatch(value):
        raise UpdateError('invalid_version')
    return tuple(int(part) for part in value.split('.'))


def allowed_url(url):
    """Only exact public repository API routes and commit-pinned archives."""
    try:
        parsed = urllib.parse.urlsplit(url)
        if parsed.scheme != 'https' or parsed.username or parsed.password or parsed.port or parsed.query or parsed.fragment:
            return False
    except ValueError: return False
    if parsed.hostname == 'api.github.com':
        base = '/repos/' + REPOSITORY + '/'
        if not parsed.path.startswith(base): return False
        route = parsed.path[len(base):]
        return bool(route == 'releases/latest' or
                    re.fullmatch(r'git/ref/tags/v[0-9]+\.[0-9]+\.[0-9]+', route) or
                    re.fullmatch(r'git/tags/[0-9a-f]{40}', route))
    return (parsed.hostname == 'codeload.github.com' and
            bool(re.fullmatch('/' + re.escape(REPOSITORY) + r'/zip/[0-9a-f]{40}', parsed.path)))


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        # Both GitHub API and codeload have direct canonical endpoints.
        # Refuse redirects rather than sending any request to a new origin.
        raise UpdateError('redirect_refused')


def fetch_bytes(url, limit):
    """No credentials, cookies, environment proxies, retries or arbitrary URLs."""
    if not allowed_url(url): raise UpdateError('source_not_allowed')
    mailbox = queue.Queue(maxsize=1)
    def worker():
        try:
            opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
            request = urllib.request.Request(url, headers={
                'User-Agent': 'codex-security-audit-explicit-update',
                'Accept': 'application/vnd.github+json' if url.startswith(API) else 'application/zip',
                'Accept-Encoding': 'identity'})
            deadline = time.monotonic() + REQUEST_DEADLINE
            with opener.open(request, timeout=10) as response:
                if response.geturl() != url or response.status != 200:
                    raise UpdateError('unexpected_download_response')
                if response.headers.get('Content-Encoding', 'identity') != 'identity':
                    raise UpdateError('encoded_response_refused')
                length = response.headers.get('Content-Length')
                if length and (not length.isdigit() or int(length) > limit):
                    raise UpdateError('download_size_limit')
                parts = []; total = 0
                while True:
                    if time.monotonic() > deadline: raise UpdateError('download_timeout')
                    block = response.read(min(65536, limit + 1 - total))
                    if not block: break
                    total += len(block)
                    if total > limit: raise UpdateError('download_size_limit')
                    parts.append(block)
            mailbox.put((True, b''.join(parts)))
        except Exception as exc:
            reason = str(exc) if isinstance(exc, UpdateError) else 'network_unavailable'
            mailbox.put((False, reason))
    # A bounded wait also covers a resolver that does not honor socket timeout.
    threading.Thread(target=worker, daemon=True).start()
    try: ok, result = mailbox.get(timeout=REQUEST_DEADLINE + 1)
    except queue.Empty: raise UpdateError('download_timeout')
    if not ok: raise UpdateError(result)
    return result


def fetch_json(url, fetcher=fetch_bytes):
    try:
        raw = fetcher(url, MAX_JSON)
        if len(raw) > MAX_JSON: raise UpdateError('metadata_size_limit')
        result = json.loads(raw.decode('utf-8'))
    except (UnicodeError, json.JSONDecodeError, RecursionError):
        raise UpdateError('invalid_release_metadata')
    if not isinstance(result, dict): raise UpdateError('invalid_release_metadata')
    return result


def commit_for_tag(tag, fetcher=fetch_bytes):
    if not isinstance(tag, str) or not tag.startswith('v'): raise UpdateError('invalid_tag')
    version(tag[1:])
    record = fetch_json(API + '/git/ref/tags/' + tag, fetcher)
    if record.get('ref') != 'refs/tags/' + tag: raise UpdateError('tag_mismatch')
    obj = record.get('object', {})
    for _ in range(4):
        sha = obj.get('sha') if isinstance(obj, dict) else None
        if not isinstance(sha, str) or not SHA_RE.fullmatch(sha): raise UpdateError('invalid_commit')
        if obj.get('type') == 'commit': return sha
        if obj.get('type') != 'tag': raise UpdateError('invalid_tag_target')
        record = fetch_json(API + '/git/tags/' + sha, fetcher)
        if record.get('sha') != sha: raise UpdateError('annotated_tag_mismatch')
        obj = record.get('object', {})
    raise UpdateError('tag_depth_limit')


def anchored_supported():
    return (os.name != 'nt' and hasattr(os, 'O_NOFOLLOW') and os.open in os.supports_dir_fd
            and os.scandir in os.supports_fd and os.stat in os.supports_dir_fd)


def cloud_or_reparse(info):
    return bool(getattr(info, 'st_file_attributes', 0) & (0x400 | 0x1000 | 0x40000 | 0x400000)) or bool(getattr(info, 'st_flags', 0) & 0x40000000)


def open_local_directory(path):
    """Anchor every ancestor from /; never resolve path symlinks before opening."""
    if not anchored_supported(): raise UpdateError('anchored_local_comparison_unavailable')
    path = Path(os.path.abspath(str(path)))
    fd = os.open(path.anchor, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for component in path.parts[1:]:
            before = os.stat(component, dir_fd=fd, follow_symlinks=False)
            if not stat.S_ISDIR(before.st_mode) or cloud_or_reparse(before):
                raise UpdateError('local_redirected_entry')
            child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            opened = os.fstat(child)
            if (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino) or cloud_or_reparse(opened):
                os.close(child)
                raise UpdateError('local_entry_changed')
            os.close(fd); fd = child
        result = fd; fd = None
        return result
    finally:
        if fd is not None: os.close(fd)


def read_local_file(directory_fd, name, limit):
    before = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size > limit or cloud_or_reparse(before):
        raise UpdateError('local_special_or_large_file')
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory_fd)
    try:
        opened = os.fstat(fd)
        if ((before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino) or
                not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1 or cloud_or_reparse(opened)):
            raise UpdateError('local_entry_changed')
        with os.fdopen(fd, 'rb', closefd=False) as stream: body = stream.read(limit + 1)
        after = os.fstat(fd)
        if ((opened.st_size, opened.st_mtime_ns, opened.st_ctime_ns, opened.st_nlink) !=
                (after.st_size, after.st_mtime_ns, after.st_ctime_ns, after.st_nlink) or len(body) != before.st_size or cloud_or_reparse(after)):
            raise UpdateError('local_entry_changed')
        return body
    finally: os.close(fd)


def local_version(skill_dir):
    fd = None
    try:
        fd = open_local_directory(Path(skill_dir).expanduser())
        raw = read_local_file(fd, 'VERSION', 64)
        value = raw.decode('ascii').strip(); version(value)
        return value
    except (OSError, UnicodeError, ValueError): return None
    finally:
        if fd is not None: os.close(fd)


def check_latest(skill_dir, baseline_version=None, fetcher=fetch_bytes):
    current = local_version(skill_dir)
    if baseline_version is not None:
        version(baseline_version)
        if current and current != baseline_version: raise UpdateError('baseline_version_mismatch')
        current = current or baseline_version
    data = fetch_json(API + '/releases/latest', fetcher)
    tag = data.get('tag_name')
    if data.get('draft') is not False or data.get('prerelease') is not False:
        raise UpdateError('release_not_stable')
    if not isinstance(tag, str) or not tag.startswith('v'): raise UpdateError('invalid_tag')
    latest = tag[1:]; latest_tuple = version(latest)
    if data.get('html_url') != REPO_URL + '/releases/tag/' + tag:
        raise UpdateError('release_source_mismatch')
    sha = commit_for_tag(tag, fetcher)
    state = ('local_version_unknown' if current is None else 'update_available' if version(current) < latest_tuple
             else 'up_to_date' if version(current) == latest_tuple else 'local_newer')
    return {'repository': REPOSITORY, 'current_version': current,
            'latest_version': latest, 'tag': tag, 'commit': sha, 'status': state,
            'release_url': REPO_URL + '/releases/tag/' + tag,
            'install_url': REPO_URL + '/tree/' + tag + '/' + SKILL,
            'checked_at': dt.datetime.now(dt.timezone.utc).isoformat(),
            'installed_files_modified': False, 'background_updates': False,
            'local_modifications': 'not_checked'}


def valid_relative(name):
    if not isinstance(name, str) or not name or len(name) > 512 or '\\' in name or ':' in name:
        raise UpdateError('invalid_archive_path')
    if any(ord(char) < 32 or ord(char) == 127 for char in name): raise UpdateError('invalid_archive_path')
    parts = name.split('/')
    if any(part in ('', '.', '..') or part.endswith((' ', '.')) for part in parts):
        raise UpdateError('invalid_archive_path')
    if len(parts) > 20 or any(len(part) > 240 for part in parts): raise UpdateError('archive_path_limit')
    if any(re.fullmatch(r'(?i)(con|prn|aux|nul|com[0-9]|lpt[0-9])(?:\..*)?', part) for part in parts):
        raise UpdateError('reserved_archive_path')
    return PurePosixPath(name)


def archive_skill(payload, commit):
    """Validate all archive entries before extracting only checksummed skill files."""
    if len(payload) > MAX_ARCHIVE or not SHA_RE.fullmatch(commit): raise UpdateError('archive_size_or_commit')
    root = 'codex-security-audit-' + commit
    files = {}; seen = set(); total = 0
    try:
        with zipfile.ZipFile(io.BytesIO(payload)) as archive:
            entries = archive.infolist()
            if len(entries) > MAX_ENTRIES: raise UpdateError('archive_entry_limit')
            for item in entries:
                if item.orig_filename != item.filename: raise UpdateError('invalid_archive_path')
                raw = item.filename[:-1] if item.is_dir() else item.filename
                path = valid_relative(raw)
                if path.parts[0] != root: raise UpdateError('archive_root_mismatch')
                folded = unicodedata.normalize('NFC', raw).casefold()
                if folded in seen: raise UpdateError('duplicate_archive_path')
                seen.add(folded)
                mode = item.external_attr >> 16
                if stat.S_IFMT(mode) not in (0, stat.S_IFDIR if item.is_dir() else stat.S_IFREG):
                    raise UpdateError('archive_special_file')
                if item.flag_bits & 1: raise UpdateError('encrypted_archive')
                if item.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED):
                    raise UpdateError('archive_compression_refused')
                if item.file_size > MAX_FILE or item.file_size < 0: raise UpdateError('archive_file_limit')
                total += item.file_size
                if total > MAX_ARCHIVE: raise UpdateError('archive_expansion_limit')
                if item.file_size > 65536 and item.file_size > max(item.compress_size, 1) * 250:
                    raise UpdateError('archive_compression_ratio')
                if item.is_dir():
                    if item.file_size: raise UpdateError('archive_directory_data')
                    continue
                if len(path.parts) < 2: raise UpdateError('archive_root_file')
                rel = '/'.join(path.parts[1:])
                with archive.open(item) as stream: body = stream.read(MAX_FILE + 1)
                if len(body) != item.file_size: raise UpdateError('archive_size_mismatch')
                files[rel] = body
    except (zipfile.BadZipFile, RuntimeError, OSError, NotImplementedError, EOFError):
        raise UpdateError('invalid_archive')
    manifest = files.get('SHA256SUMS.txt')
    if manifest is None or len(manifest) > 65536: raise UpdateError('missing_source_checksums')
    expected = {}
    try: lines = manifest.decode('utf-8').splitlines()
    except UnicodeError: raise UpdateError('invalid_source_checksums')
    for line in lines:
        matched = re.fullmatch(r'([0-9a-f]{64})  (.+)', line)
        if not matched: raise UpdateError('invalid_source_checksums')
        digest, name = matched.groups(); path = valid_relative(name)
        if path.parts[0] != SKILL or len(path.parts) < 2 or name in expected:
            raise UpdateError('invalid_source_checksums')
        expected[name] = digest
    actual = {name: body for name, body in files.items() if name.startswith(SKILL + '/')}
    if not actual or set(actual) != set(expected): raise UpdateError('source_manifest_mismatch')
    if SKILL + '/SKILL.md' not in actual: raise UpdateError('missing_skill_entrypoint')
    folded_files = {unicodedata.normalize('NFC', name).casefold() for name in files}
    for name, body in actual.items():
        if hashlib.sha256(body).hexdigest() != expected[name]: raise UpdateError('source_checksum_mismatch')
        # A file cannot also be an ancestor directory, even on other OSes.
        if any(unicodedata.normalize('NFC', str(parent)).casefold() in folded_files
               for parent in PurePosixPath(name).parents if str(parent) != '.'):
            raise UpdateError('archive_file_directory_collision')
    return {name[len(SKILL) + 1:]: body for name, body in actual.items()}


def download_skill(commit, fetcher=fetch_bytes):
    return archive_skill(fetcher('https://codeload.github.com/' + REPOSITORY + '/zip/' + commit, MAX_ARCHIVE), commit)


def installed_comparison(skill_dir, baseline):
    """Compare only installed skill files; never follow a redirected entry."""
    root = Path(skill_dir).expanduser().absolute()
    unavailable = {'status': 'unverified', 'changed': [], 'missing': [], 'extra': [], 'reason': 'local_source_unavailable'}
    if not anchored_supported():
        unavailable['reason'] = 'anchored_local_comparison_unavailable'
        return unavailable
    rootfd = None; seen = {}; extra = []; count = 0
    try:
        rootfd = open_local_directory(root)
        def walk(fd, parts):
            nonlocal count
            if len(parts) > 20: raise UpdateError('local_path_limit')
            with os.scandir(fd) as iterator:
                for entry in iterator:
                    count += 1
                    if count > MAX_ENTRIES: raise UpdateError('local_entry_limit')
                    rel = '/'.join(parts + [entry.name])
                    before = entry.stat(follow_symlinks=False)
                    if stat.S_ISLNK(before.st_mode) or cloud_or_reparse(before): raise UpdateError('local_redirected_entry')
                    if stat.S_ISDIR(before.st_mode):
                        if not any(name.startswith(rel + '/') for name in baseline): extra.append(rel + '/')
                        child = os.open(entry.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                        try:
                            after = os.fstat(child)
                            if (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino) or cloud_or_reparse(after): raise UpdateError('local_entry_changed')
                            walk(child, parts + [entry.name])
                        finally: os.close(child)
                    elif rel not in baseline:
                        extra.append(rel)
                    else:
                        seen[rel] = hashlib.sha256(read_local_file(fd, entry.name, MAX_FILE)).hexdigest()
        walk(rootfd, [])
        expected = {name: hashlib.sha256(body).hexdigest() for name, body in baseline.items()}
        changed = sorted(name for name in seen if seen[name] != expected[name])
        missing = sorted(set(expected) - set(seen))
        return {'status': 'matches_published_version' if not changed and not missing and not extra else 'local_changes',
                'changed': changed, 'missing': missing, 'extra': sorted(extra)}
    except (OSError, UpdateError): return unavailable
    finally:
        if rootfd is not None: os.close(rootfd)


def create_private_stage(target):
    """Return a descriptor for a newly created directory in an anchored parent."""
    parentfd = open_local_directory(target.parent)
    fd = None
    try:
        os.mkdir(target.name, 0o700, dir_fd=parentfd)
        before = os.stat(target.name, dir_fd=parentfd, follow_symlinks=False)
        fd = os.open(target.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parentfd)
        opened = os.fstat(fd)
        if ((before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino) or
                not stat.S_ISDIR(opened.st_mode) or stat.S_IMODE(opened.st_mode) & 0o077 or cloud_or_reparse(opened)):
            raise UpdateError('staging_directory_changed')
        result = fd; fd = None
        return result
    finally:
        os.close(parentfd)
        if fd is not None: os.close(fd)


def write_stage_file(rootfd, parts, body):
    fd = os.dup(rootfd)
    try:
        for part in parts[:-1]:
            try: os.mkdir(part, 0o700, dir_fd=fd)
            except FileExistsError: pass
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            opened = os.fstat(child)
            if cloud_or_reparse(opened) or stat.S_IMODE(opened.st_mode) & 0o077:
                os.close(child); raise UpdateError('staging_directory_changed')
            os.close(fd); fd = child
        newfd = os.open(parts[-1], os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=fd)
        with os.fdopen(newfd, 'wb') as stream: stream.write(body)
    finally: os.close(fd)


def prepare_update(skill_dir, output_dir, baseline_version=None, fetcher=fetch_bytes):
    result = check_latest(skill_dir, baseline_version, fetcher)
    if result['status'] in ('up_to_date', 'local_newer'):
        result['prepared'] = False
        return result
    if not anchored_supported(): raise UpdateError('safe_staging_unavailable')
    target = Path(output_dir).expanduser().absolute()
    for protected in (Path(skill_dir).expanduser().absolute(), Path(__file__).resolve().parent.parent):
        try: target.resolve().relative_to(protected.resolve())
        except ValueError: pass
        else: raise UpdateError('staging_inside_installed_skill')
    candidate = download_skill(result['commit'], fetcher)
    try: candidate_version = candidate['VERSION'].decode('ascii').strip()
    except (KeyError, UnicodeError): raise UpdateError('candidate_version_missing')
    if candidate_version != result['latest_version']: raise UpdateError('candidate_version_mismatch')
    comparison = {'status': 'unverified', 'changed': [], 'missing': [], 'extra': [], 'reason': 'current_version_unknown'}
    baseline_commit = None
    if result['current_version']:
        try:
            baseline_commit = commit_for_tag('v' + result['current_version'], fetcher)
            baseline = download_skill(baseline_commit, fetcher)
            comparison = installed_comparison(skill_dir, baseline)
        except UpdateError:
            comparison['reason'] = 'published_baseline_unavailable'
    # Parent must already exist; no path-based mkdir traversal or automatic
    # creation of unverified ancestors. All writes below use anchored handles.
    stagefd = create_private_stage(target)
    staged = target / 'candidate' / SKILL
    result.update(prepared=True, stage_path=str(staged), baseline_commit=baseline_commit,
                  local_modifications=comparison, storage='POSIX anchored new directory 0700; files 0600',
                  candidate_sha256={name: hashlib.sha256(body).hexdigest() for name, body in candidate.items()},
                  replacement_eligible=comparison['status'] == 'matches_published_version' and result['status'] == 'update_available',
                  instruction='尚未安裝。先核對版本、候選差異與本機變更；保留備份，僅在使用者已要求更新且本機未修改時由 Codex 完成替換。',
                  trust_note='校驗碼與來源來自同一 GitHub 儲存庫，只驗證一致性，不證明程式安全或維護者帳號未受入侵。')
    try:
        for name, body in candidate.items():
            write_stage_file(stagefd, ('candidate', SKILL) + PurePosixPath(name).parts, body)
        receipt = (json.dumps(result, ensure_ascii=False, indent=2) + '\n').encode('utf-8')
        write_stage_file(stagefd, ('prepared-update.json',), receipt)
        namedfd = open_local_directory(target)
        try:
            original = os.fstat(stagefd); named = os.fstat(namedfd)
            if (original.st_dev, original.st_ino) != (named.st_dev, named.st_ino):
                raise UpdateError('staging_directory_changed')
        finally: os.close(namedfd)
    finally: os.close(stagefd)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument('--check', action='store_true', help='Check latest stable release; no local changes (default).')
    mode.add_argument('--prepare', action='store_true', help='Download validated candidate; never replace installed files.')
    parser.add_argument('--installed-skill', type=Path, default=Path(__file__).resolve().parent.parent)
    parser.add_argument('--baseline-version', help='Explicit claimed old version only when VERSION is absent; still verifies full baseline.')
    parser.add_argument('--output-dir', type=Path, help='New private staging directory outside installed skill; required for --prepare.')
    args = parser.parse_args()
    if args.prepare != bool(args.output_dir): parser.error('--output-dir is required only with --prepare.')
    try:
        result = (prepare_update(args.installed_skill, args.output_dir, args.baseline_version) if args.prepare
                  else check_latest(args.installed_skill, args.baseline_version))
        print(json.dumps(result, ensure_ascii=False, indent=2))
    except (UpdateError, OSError, ValueError):
        print(json.dumps({'status': 'unavailable', 'message': '更新來源或檔案未通過檢查；未修改安裝版。請保留原版本並稍後查證。'}, ensure_ascii=False))
        return 1
    return 0


if __name__ == '__main__': sys.exit(main())
