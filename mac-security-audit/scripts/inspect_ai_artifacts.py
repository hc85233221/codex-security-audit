#!/usr/bin/env python3
"""Bounded, local-only AI configuration and recent artifact security triage."""
import argparse
import collections
import datetime as dt
import json
import os
from pathlib import Path
import platform
import re
import stat
import sys
import time

sys.dont_write_bytecode = True
from audit_io import is_redirected, write_new
from ai_artifact_rules import scan_lines

MAX_ENTRIES = 2000
MAX_FILES = 200
MAX_DEPTH = 3
MAX_FILE_BYTES = 256 * 1024
MAX_TOTAL_BYTES = 4 * 1024 * 1024
MAX_FINDINGS = 500
MAX_SECONDS = 20
CODE_SUFFIXES = {'.py', '.sh', '.bash', '.zsh', '.command', '.ps1', '.bat', '.cmd', '.js', '.mjs', '.cjs', '.ts', '.tsx', '.jsx', '.html', '.htm', '.svg', '.vbs', '.rb', '.php', '.go', '.rs', '.java', '.c', '.cpp', '.cs'}
MODEL_SUFFIXES = {'.pkl', '.pickle', '.pt', '.pth', '.ckpt', '.safetensors', '.gguf', '.onnx', '.bin'}
PICKLE_SUFFIXES = {'.pkl', '.pickle', '.pt', '.pth', '.ckpt'}
MEDIA_SUFFIXES = {'.png', '.jpg', '.jpeg', '.webp', '.gif', '.mp3', '.wav', '.mp4', '.mov', '.pdf', '.docx', '.xlsx', '.pptx', '.zip', '.dmg', '.exe', '.msi', '.ipynb'}
PRIVATE = re.compile(r'(^\.env(?:\.|$)|(?:^|[._\s-])(?:auth|credential|credentials|secret|secrets|password|passwords|token|tokens|history|session|sessions|conversation|conversations|chat|chats|message|messages|dialog|dialogs|dialogue|dialogues|transcript|transcripts|thread|threads)(?:[._\s-]|\d|$)|聊天|對話|对话|会话|會話|逐字稿|轉錄|转录|^id_(?:rsa|ed25519|ecdsa|dsa)(?:\.|$)|\.(?:pem|p12|pfx|key|keychain|sqlite|sqlite3|db|jsonl|log)$)', re.I)
SKIP_DIRS = {'.git', 'node_modules', '__pycache__', '.venv', 'venv', 'env', 'vendor', 'cache', 'caches', 'sessions', 'history', 'credentials', 'secrets', 'keys', 'testdata', 'fixtures', 'tests', 'site-packages', 'backups', 'reports', 'private', 'models', 'weights'}
SKIP_FILES = {'report.html', 'report.json', 'manifest.json', 'target.json'}
PRIVATE_REPORT = re.compile(r'(?:健檢|稽核)(?:報告|結果)|^(?:private[-_]?reports?|audit[-_]?reports?)(?:[._-]|$)', re.I)
WORKFLOW_NAME = re.compile(r'(?:workflow|comfy|mcp|^config\.|^settings\.|\.flow\.)', re.I)
PROMPT_NAME = re.compile(r'^(?:AGENTS|CLAUDE|SKILL)\.md$|^(?:system[_-]?)?prompt(?:[._-].*)?\.(?:md|txt)$', re.I)
BIDI = re.compile('[\u202a-\u202e\u2066-\u2069]')


def display(value, limit=600):
    # File names are untrusted data. Escape control characters and cap labels.
    return ''.join(c if c >= ' ' and c != '\x7f' and not BIDI.search(c) else '\\u%04x' % ord(c) for c in str(value))[:limit]


def cloud(info):
    return bool(getattr(info, 'st_file_attributes', 0) & (0x400 | 0x1000 | 0x40000 | 0x400000)) or bool(getattr(info, 'st_flags', 0) & 0x40000000)


def within(path, root):
    try: path.relative_to(root); return True
    except ValueError: return False


def absolute(path):
    # Do not resolve symlinks. Reject traversal spellings rather than normalize
    # them through an attacker-controlled symlink.
    result = Path(path).expanduser().absolute()
    if '..' in result.parts: raise ValueError('parent_traversal')
    return result


def anchor_available(host):
    return host != 'Windows' and os.name != 'nt' and hasattr(os, 'O_NOFOLLOW') and os.open in os.supports_dir_fd and os.scandir in os.supports_fd


def open_dir(path):
    """Anchor every ancestor from filesystem root, not just the final directory."""
    path = absolute(path)
    fd = os.open(path.anchor, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for part in path.parts[1:]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd); fd = child
            info = os.fstat(fd)
            if not stat.S_ISDIR(info.st_mode) or cloud(info): raise ValueError('directory_unavailable')
        return fd
    except BaseException:
        os.close(fd); raise


def child_dir(root_fd, parts):
    fd = os.dup(root_fd)
    try:
        for part in parts:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd); fd = child
            if cloud(os.fstat(fd)): raise ValueError('cloud_placeholder')
        return fd
    except BaseException:
        os.close(fd); raise


def read_text(directory_fd, name, before, counters):
    if directory_fd is None: return None, 'metadata_only_platform'
    if not stat.S_ISREG(before.st_mode) or cloud(before): return None, 'nonregular_or_cloud'
    if before.st_nlink != 1: return None, 'hardlink_skipped'
    if before.st_size > MAX_FILE_BYTES: return None, 'file_size_limit'
    if counters['files_read'] >= MAX_FILES or counters['bytes_read'] + before.st_size > MAX_TOTAL_BYTES: return None, 'content_budget'
    fd = None
    try:
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | getattr(os, 'O_NONBLOCK', 0), dir_fd=directory_fd)
        opened = os.fstat(fd)
        if not stat.S_ISREG(opened.st_mode) or cloud(opened) or opened.st_nlink != 1 or (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino): return None, 'changed_or_redirected'
        if opened.st_size > MAX_FILE_BYTES or counters['bytes_read'] + opened.st_size > MAX_TOTAL_BYTES: return None, 'content_budget'
        remaining = MAX_TOTAL_BYTES - counters['bytes_read']
        with os.fdopen(fd, 'rb') as f:
            fd = None
            raw = f.read(min(MAX_FILE_BYTES + 1, remaining))
            after = os.fstat(f.fileno())
        counters['bytes_read'] += len(raw)
        counters['files_read'] += 1
        if (opened.st_size, opened.st_mtime_ns, opened.st_ctime_ns, opened.st_nlink) != (after.st_size, after.st_mtime_ns, after.st_ctime_ns, after.st_nlink): return None, 'changed_during_read'
        if len(raw) > MAX_FILE_BYTES or len(raw) != after.st_size or b'\0' in raw: return None, 'binary_or_changed'
        return raw.decode('utf-8-sig'), 'scanned'
    except (OSError, UnicodeError, ValueError): return None, 'unreadable_text'
    finally:
        if fd is not None: os.close(fd)


def config_sources(home, host):
    result = [('Codex 設定', home / '.codex/config.toml'), ('Cursor MCP 設定', home / '.cursor/mcp.json'), ('Claude Code 設定', home / '.claude/settings.json')]
    if host == 'Darwin': result.append(('Claude Desktop 設定', home / 'Library/Application Support/Claude/claude_desktop_config.json'))
    elif host == 'Windows': result.append(('Claude Desktop 設定', home / 'AppData/Roaming/Claude/claude_desktop_config.json'))
    return result


def kind_of(path):
    suffix = path.suffix.lower()
    if suffix in MODEL_SUFFIXES: return 'model_metadata', False
    if suffix in CODE_SUFFIXES: return ('active_document' if suffix in {'.html', '.htm', '.svg'} else 'code'), True
    if PROMPT_NAME.search(path.name): return 'ai_instruction', True
    if suffix in {'.json', '.yaml', '.yml', '.toml'} and WORKFLOW_NAME.search(path.name): return 'workflow', True
    if suffix in MEDIA_SUFFIXES: return 'generated_candidate_metadata', False
    return None, False


def make_check(identifier, category, title, rows, coverage, findings):
    signals = [x for x in findings if x['group'] == identifier]
    subset = [x for x in rows if x['group'] == identifier]
    read = sum(bool(x['content_read']) for x in subset)
    readable = any(c['group'] == identifier and c['status'] in ('bounded', 'partial') for c in coverage)
    status = 'review' if subset or readable else 'unknown'
    summary = '檢視 %d 個項目，文字檢查 %d 個，保留 %d 筆待複核線索。' % (len(subset), read, len(signals)) if status == 'review' else '未取得可判讀項目，不能認定沒有風險。'
    priority = {'info': 0, 'low': 1, 'medium': 2, 'high': 3}
    severity = max((x.get('severity', 'info') for x in signals), key=lambda x: priority.get(x, 0), default='info')
    return {'id': 'ai_artifacts.' + identifier, 'category': category, 'title': title, 'status': status,
            'severity': severity, 'summary': summary, 'short_summary': summary,
            'impact': 'AI 設定、工作流與生成程式可能影響資料存取及執行範圍；來源或規則命中本身不代表惡意。',
            'actions': ['優先複核下載執行、敏感資訊存取與外傳的組合；確認用途後再決定是否修改。', '沒有執行或上傳受檢內容；需要更深入檢查時，另指定檔案與範圍。'],
            'evidence': [{'source': '來源與覆蓋', 'detail': json.dumps([c for c in coverage if c['group'] == identifier], ensure_ascii=False)},
                         {'source': '靜態線索；無原文或敏感值', 'detail': json.dumps(signals, ensure_ascii=False)}],
            'limitations': ['規則只提供人工複核線索；註解、測試與禁止事項可能誤報。', '修改日期只用來限縮近期範圍，不能證明檔案由 AI 產生。', '未讀影像、影音、文件、筆記本輸出或模型內容，也未解壓、執行、載入模型或驗證外洩。'],
            'terms': ['static_analysis', 'prompt_injection', 'metadata']}


def collect(home=None, roots=None, days=14, exclude=None, host=None):
    home = absolute(home or Path.home()); host = host or platform.system()
    if not 1 <= days <= 90: raise ValueError('invalid_days')
    roots = [absolute(p) for p in (roots if roots is not None else [home / 'Downloads'])]
    exclusions = [absolute(p) for p in (exclude or [])] + [Path(__file__).absolute().parent.parent]
    anchored = anchor_available(host)
    start = time.monotonic(); deadline = start + MAX_SECONDS
    counters = collections.Counter(); inventory = []; findings = []; coverage = []
    seen = set(); cutoff = time.time() - days * 86400

    def add_signal(rule, title, severity, row, line=None, tags=None):
        counters['signals_observed'] += 1
        row['signal_count'] += 1
        if len(findings) >= MAX_FINDINGS:
            counters['findings_omitted'] += 1; return
        findings.append({'rule': rule, 'title': title, 'severity': severity, 'line': line,
                         'path': row['path'], 'source': row['source'], 'group': row['group'],
                         'status': 'review_signal', 'context_tags': tags or [], 'source_excerpt': 'omitted'})

    def inspect_one(path, source, group, kind, read_allowed, info, fd):
        identity = (info.st_dev, info.st_ino)
        if identity in seen: counters['duplicate_files_skipped'] += 1; return
        seen.add(identity)
        row = {'name': display(path.name), 'path': display(path), 'source': source, 'kind': kind,
               'group': group, 'scan_status': 'metadata_only', 'signal_count': 0, 'content_read': False,
               'provenance': 'known_ai_config' if group == 'config' else 'unknown',
               'modified_at': dt.datetime.fromtimestamp(info.st_mtime, dt.timezone.utc).isoformat(), 'size_bytes': info.st_size}
        inventory.append(row); counters['files_considered'] += 1
        if BIDI.search(path.name): add_signal('filename_direction', '檔名含方向控制字元', 'medium', row)
        if host != 'Windows' and info.st_mode & 0o002: add_signal('world_writable', '其他本機帳號可寫入此檔案', 'medium', row)
        if path.suffix.lower() in PICKLE_SUFFIXES: add_signal('model_load_review', '模型或序列化格式載入前需確認來源', 'medium', row)
        if info.st_nlink != 1:
            row['scan_status'] = 'hardlink_skipped'; counters['hardlink_skipped'] += 1; return
        if read_allowed:
            text, result = read_text(fd, path.name, info, counters)
            row['scan_status'] = result
            if text is not None:
                row['content_read'] = True
                local, limited = scan_lines(text, is_config=(group == 'config'))
                if limited: row['scan_status'] = 'partial_text_limit'; counters['text_limits'] += 1
                for signal in local:
                    add_signal(signal['rule'], signal['title'], signal['severity'], row, signal['line'], signal['context_tags'])
            else: counters[result] += 1

    for source, path in config_sources(home, host):
        row = {'source': source, 'path': display(path), 'group': 'config', 'status': 'unavailable', 'mode': 'bounded_static_text' if anchored else 'metadata_only'}
        coverage.append(row); fd = None
        try:
            if time.monotonic() >= deadline: row['status'] = 'time_limit'; continue
            if any(within(path, p) for p in exclusions): row['status'] = 'excluded'; continue
            if anchored:
                fd = open_dir(path.parent)
                info = os.stat(path.name, dir_fd=fd, follow_symlinks=False)
            else:
                if is_redirected(path): row['status'] = 'redirected_skipped'; continue
                info = path.lstat()
            if not stat.S_ISREG(info.st_mode) or cloud(info): row['status'] = 'nonregular_or_cloud_skipped'; continue
            inspect_one(path, source, 'config', 'ai_config', True, info, fd)
            row['status'] = 'bounded' if anchored and inventory[-1]['content_read'] else 'partial'
        except FileNotFoundError: row['status'] = 'absent'
        except (OSError, ValueError, OverflowError): row['status'] = 'unavailable'
        finally:
            if fd is not None: os.close(fd)

    # Cursor instruction directory is only inventoried. It is not a general
    # recursive reader of hidden AI data, conversations or package caches.
    rule_root = home / '.cursor/rules'
    source_roots = [('Cursor 指令中繼資料', rule_root, True)] + [('近期候選檔案', p, False) for p in roots]
    for source, root, metadata_rules in source_roots:
        row = {'source': source, 'root': display(root), 'group': 'generated', 'status': 'unavailable', 'entries_considered': 0, 'items_reported': 0,
               'days': None if metadata_rules else days, 'mode': 'metadata_only' if metadata_rules or not anchored else 'bounded_static_text'}
        coverage.append(row); root_fd = None; initial_inventory = len(inventory); initial_findings = len(findings)
        try:
            if any(within(root, p) for p in exclusions): row['status'] = 'excluded'; continue
            if anchored:
                root_fd = open_dir(root); root_info = os.fstat(root_fd)
            else:
                if is_redirected(root): row['status'] = 'redirected_skipped'; continue
                root_info = root.lstat()
                if not stat.S_ISDIR(root_info.st_mode) or cloud(root_info): row['status'] = 'nonregular_or_cloud_skipped'; continue
            row['status'] = 'bounded'; stack = [((), 0)]; before = counters.copy()
            while stack:
                if time.monotonic() >= deadline or counters['entries_considered'] >= MAX_ENTRIES or len(inventory) >= MAX_FILES:
                    row['status'] = 'partial'; counters['traversal_limit'] += 1; break
                parts, depth = stack.pop(); directory = root.joinpath(*parts); directory_fd = None
                try:
                    if anchored:
                        directory_fd = child_dir(root_fd, parts); entries = os.scandir(directory_fd)
                    else: entries = os.scandir(directory)
                    with entries:
                        for entry in entries:
                            if time.monotonic() >= deadline or counters['entries_considered'] >= MAX_ENTRIES or len(inventory) >= MAX_FILES:
                                row['status'] = 'partial'; counters['traversal_limit'] += 1; break
                            counters['entries_considered'] += 1
                            path = directory / entry.name
                            if entry.name.startswith('.') or entry.name.casefold() in SKIP_DIRS or PRIVATE.search(entry.name) or PRIVATE_REPORT.search(entry.name) or entry.name.casefold() in SKIP_FILES or any(within(path, p) for p in exclusions):
                                counters['excluded_entries'] += 1; continue
                            try:
                                info = os.stat(entry.name, dir_fd=directory_fd, follow_symlinks=False) if anchored else entry.stat(follow_symlinks=False)
                                if stat.S_ISLNK(info.st_mode) or cloud(info): counters['redirected_or_cloud_skipped'] += 1; continue
                                if stat.S_ISDIR(info.st_mode):
                                    if anchored and depth < MAX_DEPTH and not metadata_rules: stack.append((parts + (entry.name,), depth + 1))
                                    else: counters['directories_not_descended'] += 1
                                    continue
                                if not stat.S_ISREG(info.st_mode): counters['special_files_skipped'] += 1; continue
                                if not metadata_rules and info.st_mtime < cutoff: counters['outside_date_range'] += 1; continue
                                kind, read_allowed = ('ai_instruction_metadata', False) if metadata_rules else kind_of(path)
                                if kind is None: counters['unsupported_files_skipped'] += 1; continue
                                inspect_one(path, display(root), 'generated', kind, read_allowed and not metadata_rules, info, directory_fd)
                            except (OSError, ValueError, OverflowError): counters['metadata_errors'] += 1; row['status'] = 'partial'
                except (OSError, ValueError): counters['directory_errors'] += 1; row['status'] = 'partial'
                finally:
                    if directory_fd is not None: os.close(directory_fd)
            if not anchored:
                after = root.lstat()
                if is_redirected(root) or (root_info.st_dev, root_info.st_ino) != (after.st_dev, after.st_ino):
                    del inventory[initial_inventory:]; del findings[initial_findings:]
                    row['status'] = 'unavailable'; counters['changed_source_discarded'] += 1
                else: row['status'] = 'partial'
            delta = counters - before
            row['entries_considered'] = delta['entries_considered']; row['items_reported'] = len(inventory) - initial_inventory
            row['skips'] = {k: v for k, v in delta.items() if k.endswith('_skipped') or k.endswith('_limit') or k in ('text_limits', 'metadata_errors', 'directory_errors', 'directories_not_descended', 'content_budget', 'file_size_limit', 'unreadable_text', 'changed_during_read', 'binary_or_changed', 'changed_or_redirected')}
            if row['skips'] and row['status'] == 'bounded': row['status'] = 'partial'
        except FileNotFoundError: row['status'] = 'absent'
        except (OSError, ValueError): row['status'] = 'unavailable'
        finally:
            if root_fd is not None: os.close(root_fd)

    limitations = ['只檢查固定 AI 設定白名單及指定的近期候選目錄；不是整顆磁碟掃描。',
                   '最多 2000 筆目錄項目、200 個回報項目、深度 3、每檔 256 KiB、總文字 4 MiB、20 秒；最多 500 筆線索。',
                   '近期以修改時間篩選，並不證明 AI 生成；也不讀 AI 聊天、操作歷史、私人文件、憑證或模型內容。',
                   '設定、程式、網頁與 SVG 只作有限文字規則比對；所有原文、端點及敏感值不保留。',
                   '圖片、影音、文件、模型與筆記本只看中繼資料；未檢測其內嵌內容、個資、著作權或完整惡意行為。',
                   'Windows 缺少同等目錄控制代碼介面時，只盤點頂層中繼資料，不讀文字或遞迴；尚未實機驗證。']
    checks = [make_check('config', 'skills', 'AI 設定與權限線索', inventory, coverage, findings), make_check('generated', 'files', '近期 AI 相關與生成候選檔案', inventory, coverage, findings)]
    partial = any(c['status'] not in ('bounded', 'absent', 'excluded') for c in coverage) or bool(counters['findings_omitted'])
    summary = dict(counters); summary.update(items_reported=len(inventory), findings_reported=len(findings), config_items=sum(r['group'] == 'config' for r in inventory), generated_items=sum(r['group'] == 'generated' for r in inventory))
    return {'schema_version': '3.1', 'module': 'ai_artifacts', 'platform': host,
            'observed_at': dt.datetime.now(dt.timezone.utc).isoformat(), 'coverage_status': 'partial' if partial else 'bounded',
            'checks': checks, 'inventories': {'ai_artifacts': inventory}, 'findings': findings, 'coverage': coverage,
            'summary': summary, 'limitations': limitations, 'network_requests': False, 'inspected_code_executed': False,
            'source_text_retained': False, 'settings_modified': False, 'traversal_guard': 'anchored_directory_handles' if anchored else 'top_level_metadata_only'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--home', type=Path, default=Path.home())
    parser.add_argument('--root', type=Path, action='append', help='Authorized recent artifact directory; replaces Downloads default')
    parser.add_argument('--exclude', type=Path, action='append', default=[])
    parser.add_argument('--days', type=int, choices=range(1, 91), default=14, metavar='1..90')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    output_fd = None
    try:
        home = absolute(args.home); roots = [absolute(p) for p in (args.root if args.root is not None else [home / 'Downloads'])]
        target = absolute(args.output)
        if is_redirected(target) or not target.parent.is_dir() or target.exists(): raise ValueError('output_invalid')
        if os.name != 'nt' and target.parent.stat().st_mode & 0o077: raise ValueError('output_not_private')
        if any(within(target, r) for r in roots + [Path(__file__).absolute().parent.parent]): raise ValueError('output_inside_scan')
        if anchor_available(platform.system()):
            output_fd = open_dir(target.parent)
            before = os.fstat(output_fd)
            if before.st_mode & 0o077: raise ValueError('output_not_private')
        result = collect(home, roots, args.days, args.exclude)
        if output_fd is not None:
            # The report may take time to collect. Do not follow an output
            # directory replaced meanwhile, even by another same-user process.
            check_fd = open_dir(target.parent)
            try:
                after = os.fstat(check_fd)
                if (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino): raise ValueError('output_changed')
            finally: os.close(check_fd)
            fd = os.open(target.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                         0o600, dir_fd=output_fd)
            with os.fdopen(fd, 'w', encoding='utf-8', newline='\n') as stream:
                stream.write(json.dumps(result, ensure_ascii=False, indent=2) + '\n')
        else:
            if is_redirected(target): raise ValueError('output_changed')
            write_new(target, result)
    except (OSError, ValueError): parser.error('Choose a new private output file outside scanned roots; raw source/error details are never printed.')
    finally:
        if output_fd is not None: os.close(output_fd)
    print('AI configuration and recent artifact triage completed; source text and credentials not retained.')


if __name__ == '__main__': main()
