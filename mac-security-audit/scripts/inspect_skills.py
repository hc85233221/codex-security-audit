#!/usr/bin/env python3
"""Read-only, bounded static triage of local skill packages; stdlib only.

This is a review aid, not a malware detector or a proof of trust. It never
imports or runs inspected code, follows symlinks, reads usage logs, or prints
source excerpts. The only write is a new, user-selected JSON report.
"""
import argparse
import collections
import datetime
import errno
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
from audit_io import is_redirected

SKIP_DIRS = {
    '.git', 'node_modules', '__pycache__', '.venv', 'venv', 'env', 'vendor',
    'dist', 'build', 'assets', 'outputs', 'output', 'sessions', 'history',
    'credentials', 'secrets', 'keys', 'fixtures', 'testdata', 'tests',
}
SUFFIXES = {'.md', '.py', '.sh', '.bash', '.zsh', '.js', '.mjs', '.cjs', '.ts', '.ps1'}
SENSITIVE_NAME = re.compile(
    r'(^\.env(?:\.|$)|^(?:auth|credentials?|secrets?|tokens?|passwords?)(?:[._-]|$)|'
    r'^id_(?:rsa|ed25519|ecdsa|dsa)(?:\.|$)|\.(?:pem|p12|pfx|key|keychain|sqlite|db)$)', re.I)
NEGATION = re.compile(
    r"\b(?:never|avoid|forbid|prohibit|don't|do not|must not|should not|not allowed)\b|"
    r'不得|不要|禁止|不可|不能|不應|勿|避免', re.I)
EXAMPLE = re.compile(r'\b(?:example|sample|test|fixture|illustration)\b|例如|範例|示例|測試', re.I)
RULES = [
    ('download_to_interpreter', 'Downloaded content is piped to an interpreter.',
     r'\b(?:curl|wget)\b[^\n]{0,1000}\|\s*(?:(?:sudo|env)\s+)?(?:ba|z|da)?sh\b|\b(?:curl|wget)\b[^\n]{0,1000}\|\s*python[\d.]*\b'),
    ('destructive_operation', 'Destructive filesystem or disk operation needs scope review.',
     r'\brm\s+(?:(?:--[^\s]+|-[A-Za-z]+)\s+)*-[A-Za-z]*[rf][A-Za-z]*\b|\b(?:shutil\.rmtree|os\.remove|os\.unlink)\s*\(|\bdiskutil\s+(?:erase|partition)|\bmkfs\b'),
    ('permission_widening', 'Broad write permissions or security controls may be changed.',
     r'\bchmod\b[^\n]{0,160}(?:\b0?777\b|\b[ao]\+w\b)|\b(?:spctl\s+--(?:master|global)-disable|csrutil\s+disable)|socketfilterfw[^\n]{0,100}--setglobalstate\s+(?:off|0)\b'),
    ('validation_bypass', 'Certificate or quarantine validation bypass needs review.',
     r'\b(?:curl|wget)\b[^\n]{0,120}(?:--insecure|--no-check-certificate|\s-k(?:\s|$))|\bverify\s*=\s*False\b|\bxattr\b[^\n]{0,160}-[a-z]*d[a-z]*\s+com\.apple\.quarantine'),
    ('credential_source', 'Mentions a potentially sensitive credential source; no value collected.',
     r'(?:[~/]|\b)\.ssh/(?:id_(?:rsa|ed25519|ecdsa|dsa))|\.aws/credentials|(?:[~/]|[\x22\x27])\.env(?:[\x22\x27/\s.]|$)|\bauth\.json\b|\bsecurity\s+find-(?:generic|internet)-password|\b(?:Login Data|Cookies\.binarycookies)\b'),
    ('outbound_data_api', 'Has an outbound data submission capability; destination and authorization need review.',
     r'\b(?:requests|httpx|session|client)\.(?:post|put|patch)\s*\(|\bcurl\b[^\n]{0,300}(?:--data|--upload-file|\s-d\s|\s-F\s)|\bmethod\s*:\s*[\x22\x27](?:POST|PUT|PATCH)[\x22\x27]'),
    ('instruction_override', 'Instruction may override prior rules, conceal actions, or bypass approval.',
     r'\b(?:ignore|disregard|override)\s+(?:(?:all|any|the)\s+)?(?:previous|prior|system|developer)\s+(?:instructions?|prompts?|rules?)|\b(?:do not|don\x27t|never)\s+(?:tell|inform|notify)\s+(?:the\s+)?user|\b(?:bypass|skip)\s+(?:all\s+)?(?:approval|confirmation|permission)\b|忽略(?:所有|之前|先前|系統|開發者).{0,12}(?:指令|規則)|(?:不要|不得)告訴使用者'),
    ('obfuscated_execution', 'Decoding and dynamic execution appear close together.',
     r'(?:\b(?:exec|eval)\s*\([^\n]{0,500}(?:b64decode|fromhex|atob)|(?:b64decode|fromhex|atob)[^\n]{0,500}\b(?:exec|eval)\s*\()'),
    ('broad_trigger', 'Skill discovery language may match unrelated requests.',
     r'\b(?:every|all|any)\s+(?:user\s+)?(?:requests?|tasks?|conversations?|prompts?)\b|任何(?:使用者)?(?:請求|任務)|所有(?:使用者)?(?:請求|任務)'),
    ('possible_embedded_secret', 'A private-key marker or token-shaped literal is present; value omitted and authenticity unverified.',
     r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----|\bAKIA[0-9A-Z]{16}\b|\bgh[pousr]_[A-Za-z0-9]{30,}\b|\bsk-(?:proj-)?[A-Za-z0-9_-]{32,}\b'),
]
COMPILED = [(rid, desc, re.compile(pattern, re.I)) for rid, desc, pattern in RULES]
COMPILED += [(rid, desc, re.compile(pattern, re.I)) for rid, desc, pattern in [
    ('windows_download_execute', 'Downloaded PowerShell content may be executed; inspect context.',
     r'(?:Invoke-WebRequest|Invoke-RestMethod|DownloadString|\biwr\b|\birm\b)[^\n]{0,500}(?:Invoke-Expression|\biex\b)|(?:Invoke-Expression|\biex\b)[^\n]{0,500}(?:DownloadString|Invoke-WebRequest|Invoke-RestMethod|\biwr\b|\birm\b)'),
    ('windows_destructive_operation', 'Windows removal command needs scope review.',
     r'\bRemove-Item\b[^\n]{0,200}-(?:Recurse|Force)\b|\bFormat-Volume\b|\bClear-Disk\b'),
    ('windows_security_change', 'Windows protection or execution policy change needs review.',
     r'\bSet-MpPreference\b[^\n]{0,150}-Disable|\bSet-NetFirewallProfile\b[^\n]{0,150}-Enabled\s+(?:False|\$false|0)|\b(?:Set-ExecutionPolicy|ExecutionPolicy)\b[^\n]{0,100}\b(?:Bypass|Unrestricted)\b'),
]]


def within(path, root):
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def fs_error(error, path, phase):
    reason = ('permission_denied' if error.errno in {errno.EACCES, errno.EPERM}
              else 'disappeared' if error.errno == errno.ENOENT else 'io_error')
    return {'path': str(path), 'phase': phase, 'reason': reason}


def walk_safe(root, stats, errors=None):
    """No symlink traversal, dependency crawling, or hidden credential files."""
    def onerror(error):
        stats['directory_read_errors'] += 1
        if errors is not None:
            errors.append(fs_error(error, error.filename or root, 'directory_inventory'))

    for base, dirs, files in os.walk(root, followlinks=False, onerror=onerror):
        kept = []
        for name in dirs:
            p = Path(base) / name
            if name in SKIP_DIRS or SENSITIVE_NAME.search(name):
                stats['excluded_directories'] += 1
            else:
                try:
                    if is_redirected(p):
                        stats['symlink_directories_skipped'] += 1
                    else:
                        kept.append(name)
                except OSError as error:
                    onerror(error)
        dirs[:] = kept
        for name in sorted(files):
            p = Path(base) / name
            try:
                if is_redirected(p):
                    stats['symlink_files_skipped'] += 1
                    continue
            except OSError as error:
                onerror(error)
                continue
            if SENSITIVE_NAME.search(name):
                stats['sensitive_named_files_skipped'] += 1
                continue
            yield p


def read_bounded(path, max_bytes, stats):
    # O_NOFOLLOW also protects against a file being replaced by a symlink
    # between inventory and read. It is available on macOS and Linux.
    fd = None
    try:
        before = os.lstat(path)
        if not stat.S_ISREG(before.st_mode) or is_redirected(path):
            stats['nonregular_files_skipped'] += 1
            return None
        # Never block opening a FIFO/device substituted after lstat. fstat
        # below verifies the opened object again before any content is read.
        fd = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0)
                     | getattr(os, 'O_NONBLOCK', 0))
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            stats['nonregular_files_skipped'] += 1
            return None
        if (info.st_dev, info.st_ino) != (before.st_dev, before.st_ino):
            stats['changed_during_open_files_skipped'] += 1
            return None
        if info.st_size > max_bytes:
            stats['oversized_files_skipped'] += 1
            return None
        with os.fdopen(fd, 'rb') as stream:
            fd = None
            data = stream.read(max_bytes + 1)
        if len(data) > max_bytes or b'\x00' in data:
            stats['binary_or_oversized_files_skipped'] += 1
            return None
        return data.decode('utf-8', errors='strict')
    except (OSError, UnicodeError):
        stats['unreadable_or_nonutf8_files'] += 1
        return None
    finally:
        if fd is not None:
            os.close(fd)


def scan_text(text, relative_path):
    findings = []
    lines = text.splitlines()
    is_markdown = Path(relative_path).suffix.lower() == '.md'
    in_fence = False
    for index, line in enumerate(lines):
        if is_markdown and line.lstrip().startswith(('```', '~~~')):
            in_fence = not in_fence
        # Context is only a review aid. Negation/examples are NOT suppressed:
        # syntax and natural-language checks cannot prove safe intent.
        context = '\n'.join(lines[max(0, index - 2):index + 1])
        for rid, desc, regex in COMPILED:
            if rid == 'broad_trigger' and not (str(relative_path) == 'SKILL.md' and index < 30):
                continue
            if not regex.search(line):
                continue
            tags = []
            if NEGATION.search(context):
                tags.append('prohibition_or_negative_context')
            if EXAMPLE.search(context):
                tags.append('example_or_test_context')
            if in_fence:
                tags.append('markdown_code_block')
            if not is_markdown and line.lstrip().startswith(('#', '//', '*')):
                tags.append('comment_context')
            findings.append({
                'file': str(relative_path), 'line': index + 1,
                'rule': rid, 'status': 'review_signal', 'reason': desc,
                'context_tags': tags, 'source_excerpt': 'omitted',
            })
    if (Path(relative_path).suffix.lower() in {'.sh', '.bash', '.zsh', '.py'}
            and re.search(r'\b(?:curl|wget)\b|\burllib\.request\.urlretrieve\s*\(', text)
            and re.search(r'\bchmod\b[^\n]{0,120}\+x|\bsubprocess\.(?:run|Popen|call)\s*\(|\b(?:bash|sh)\s+[\x22\x27]?\$', text)):
        findings.append({
            'file': str(relative_path), 'line': None,
            'rule': 'download_and_execution_capabilities_in_file', 'status': 'review_signal',
            'reason': 'Download and execution capabilities coexist; no execution of downloaded bytes has been established.',
            'context_tags': ['file_level_cooccurrence_only'], 'source_excerpt': 'omitted',
        })
    return findings


def audit(roots, max_bytes, max_files, exclude=None):
    stats = collections.Counter()
    inventory, findings, coverage = [], [], []
    seen_skills, seen_files = set(), set()
    excluded_paths = [Path(p).expanduser().absolute() for p in (exclude or [])]
    for root_arg in roots:
        before_stats = stats.copy()
        root_errors = []
        root = Path(root_arg).expanduser()
        try:
            symlink_root = is_redirected(root)
        except OSError as error:
            stats['root_metadata_errors'] += 1
            coverage.append({'root': str(root), 'status': 'unavailable',
                             'errors': [fs_error(error, error.filename or root, 'root_metadata')]})
            continue
        if symlink_root:
            coverage.append({'root': str(root), 'status': 'symlink_root_skipped'})
            continue
        root = root.absolute()
        try:
            root_info = os.lstat(root)
        except OSError as error:
            detail = fs_error(error, root, 'root_metadata')
            stats['root_metadata_errors'] += 1
            coverage.append({'root': str(root),
                             'status': 'missing' if error.errno == errno.ENOENT else 'unavailable',
                             'errors': [detail]})
            continue
        if not stat.S_ISDIR(root_info.st_mode):
            coverage.append({'root': str(root), 'status': 'not_directory'})
            continue
        skills = sorted(p for p in walk_safe(root, stats, root_errors) if p.name == 'SKILL.md')
        root_summary = {'root': str(root), 'status': 'scanned', 'skill_files_discovered': len(skills),
                        'skill_packages_excluded': 0, 'files_scanned': 0, 'review_signals': 0,
                        'errors': root_errors}
        coverage.append(root_summary)
        for entry in skills:
            if any(within(entry, p) for p in excluded_paths):
                root_summary['skill_packages_excluded'] += 1
                continue
            if str(entry) in seen_skills:
                continue
            seen_skills.add(str(entry))
            package = entry.parent
            info = {'skill_directory': str(package), 'name_from_directory': package.name,
                    'usage_status': 'unknown', 'removal_recommendation': 'none_without_usage_and_owner_confirmation',
                    'files_scanned': 0, 'review_signals': 0,
                    'scan_status': 'scanned'}
            try:
                entry_info = os.lstat(entry)
                package_info = os.lstat(package)
            except OSError as error:
                stats['package_metadata_errors'] += 1
                detail = fs_error(error, error.filename or entry, 'package_metadata')
                root_errors.append(detail)
                info.update({'scan_status': 'unavailable', 'error': detail})
                inventory.append(info)
                continue
            if not stat.S_ISREG(entry_info.st_mode) or not stat.S_ISDIR(package_info.st_mode):
                stats['nonregular_entrypoints_skipped'] += 1
                info['scan_status'] = 'nonregular_entrypoint_or_directory_skipped'
                inventory.append(info)
                continue
            info['entrypoint_mode'] = stat.filemode(entry_info.st_mode)
            info['directory_mode'] = stat.filemode(package_info.st_mode)
            package_findings = []
            for target, metadata in [(package, package_info), (entry, entry_info)]:
                if os.name != 'nt' and metadata.st_mode & stat.S_IWOTH:
                    package_findings.append({
                        'file': '.' if target == package else 'SKILL.md', 'line': None,
                        'rule': 'world_writable_skill', 'status': 'confirmed_configuration',
                        'reason': 'Other local accounts can write this skill entrypoint or its directory.',
                        'context_tags': [], 'source_excerpt': 'omitted'})
            # A package boundary is its SKILL.md directory; dependencies and
            # unrelated sibling configuration never enter the scan.
            package_error_start = len(root_errors)
            for path in walk_safe(package, stats, root_errors):
                if str(path) in seen_files or path.suffix.lower() not in SUFFIXES:
                    continue
                if stats['files_scanned'] >= max_files:
                    stats['file_limit_reached'] = 1
                    info['scan_status'] = 'partial_due_to_file_limit'
                    root_summary['status'] = 'partial_due_to_file_limit'
                    break
                if any(parent != package and (parent / 'SKILL.md').is_file()
                       for parent in path.parents if within(parent, package) and parent != package):
                    continue
                seen_files.add(str(path))
                text = read_bounded(path, max_bytes, stats)
                if text is None:
                    continue
                stats['files_scanned'] += 1
                info['files_scanned'] += 1
                root_summary['files_scanned'] += 1
                if path == entry:
                    info['entrypoint_sha256'] = hashlib.sha256(text.encode('utf-8')).hexdigest()
                file_findings = scan_text(text, path.relative_to(package))
                package_findings.extend(file_findings)
            if len(root_errors) > package_error_start:
                info['scan_status'] = ('partial_due_to_read_errors' if info['files_scanned']
                                       else 'unavailable_due_to_read_errors')
            rules = {f['rule'] for f in package_findings}
            if {'credential_source', 'outbound_data_api'} <= rules:
                package_findings.append({
                    'file': 'SKILL.md', 'line': None,
                    'rule': 'credential_and_outbound_capabilities_in_package',
                    'status': 'review_signal',
                    'reason': 'Both capabilities exist somewhere in the package; no data flow or exfiltration has been established.',
                    'context_tags': ['package_level_cooccurrence_only'], 'source_excerpt': 'omitted',
                })
            for item in package_findings:
                item['skill_directory'] = str(package)
            info['review_signals'] = len(package_findings)
            root_summary['review_signals'] += len(package_findings)
            inventory.append(info)
            findings.extend(package_findings)
        root_summary['skip_counts'] = {
            key: stats[key] - before_stats[key]
            for key in stats if ('skipped' in key or 'unreadable' in key or 'excluded' in key or 'errors' in key)
            and stats[key] - before_stats[key] > 0
        }
        if any(root_summary['skip_counts'].get(key, 0) for key in
               ['oversized_files_skipped', 'binary_or_oversized_files_skipped', 'unreadable_or_nonutf8_files',
                'nonregular_files_skipped', 'changed_during_open_files_skipped', 'nonregular_entrypoints_skipped']):
            if root_summary['status'] == 'scanned':
                root_summary['status'] = 'scanned_with_reported_skips'
        if root_errors:
            root_summary['status'] = ('unavailable' if any(
                item['path'] == str(root) and item['phase'] == 'directory_inventory'
                for item in root_errors) else 'partial_due_to_read_errors')
        elif root_summary['skip_counts'].get('nonregular_entrypoints_skipped'):
            root_summary['status'] = 'scanned_with_reported_skips'
    return {
        'schema_version': 1, 'module': 'skill_static_triage',
        'generated_at': datetime.datetime.now(datetime.timezone.utc).isoformat(),
        'mode': 'read_only_static', 'network_requests': 0, 'inspected_code_executed': False,
        'scope': coverage, 'excluded_paths': [str(p) for p in excluded_paths],
        'limits': {'max_file_bytes': max_bytes, 'max_scanned_files': max_files},
        'summary': {'skill_packages': len(inventory), 'review_signals': len(findings), 'files_scanned': stats['files_scanned'],
                    'confirmed_malware_findings': None, **dict(stats)},
        'rule_counts': dict(collections.Counter(f['rule'] for f in findings)),
        'inventory': inventory, 'findings': findings,
        'limitations': [
            'Review signals are not evidence of malware; manually confirm intent, authorization, actual callers, and data flow.',
            'Comments, examples, and prohibitions remain visible as tagged signals, not convictions.',
            'Source text and credential values are never included in the report. Credential-named files are excluded.',
            'No dependencies, binary assets, symlink targets, sessions, browser history, authentication stores, or usage logs are inspected.',
            'A cached skill may not be installed, enabled, or in use. Cached versions are separate packages.',
            'No reliable use-event source was inspected. File modification/access time is not a usage count.',
            'No conclusion about network destinations, actual secret transfer, signatures, or package provenance follows from this scan.',
            'Only bounded UTF-8 text files with allowed suffixes are inspected; absent signals are not a clean bill of health.',
        ],
        'unused_skill_review': {
            'status': 'usage_unknown', 'automatic_delete': False,
            'suggested_questions': [
                'Which skills do you recognize and still need?',
                'Which skills duplicate another tool or were installed only for a completed one-off task?',
                'Do any other skills or workflows depend on the proposed removal target?',
            ],
            'safe_next_step': 'Review selected exact skill names with the owner; uninstall only after specific authorization. Do not manually remove plugin cache dependencies.',
        },
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', action='append', required=True, help='Skill or plugin-cache root; repeat for multiple roots.')
    parser.add_argument('--output', required=True, help='Path for a NEW private JSON report; existing paths are not overwritten.')
    parser.add_argument('--max-file-bytes', type=int, default=512 * 1024)
    parser.add_argument('--max-files', type=int, default=10000)
    parser.add_argument('--exclude', action='append', default=[], help='Exact subtree to exclude, such as this audit skill; repeat as needed.')
    args = parser.parse_args(argv)
    if not (1 <= args.max_file_bytes <= 8 * 1024 * 1024 and 1 <= args.max_files <= 100000):
        parser.error('Limits must be positive and within 8 MiB per file / 100000 files.')
    out = Path(args.output).expanduser().absolute()
    if out.exists() or out.is_symlink():
        parser.error('Output already exists; choose a new report path.')
    if not out.parent.is_dir():
        parser.error('Output parent must already exist.')
    for root in args.root:
        if within(out, Path(root).expanduser().absolute()):
            parser.error('Keep the report outside the scanned skill roots.')
    result = audit(args.root, args.max_file_bytes, args.max_files, args.exclude)
    # Exclusive creation, no overwrite and permissions private from creation.
    fd = os.open(out, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'w', encoding='utf-8') as stream:
        json.dump(result, stream, ensure_ascii=False, indent=2)
        stream.write('\n')
    print(json.dumps({'report': str(out), 'summary': result['summary'], 'rule_counts': result['rule_counts']}, ensure_ascii=False))
    return 0


if __name__ == '__main__':
    sys.exit(main())
