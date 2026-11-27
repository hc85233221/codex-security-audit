#!/usr/bin/env python3
"""Bounded static script triage. Never executes scripts, reads histories, or remedies."""
import argparse
import collections
import datetime as dt
import itertools
import json
import os
from pathlib import Path
import re
import stat
import sys
sys.dont_write_bytecode = True
from audit_io import is_redirected, write_new
from inspect_skills import read_bounded, scan_text, SENSITIVE_NAME, SKIP_DIRS

SUFFIXES = {'.py', '.sh', '.bash', '.zsh', '.command', '.ps1', '.bat', '.cmd', '.js', '.mjs', '.cjs', '.vbs', '.applescript', '.scpt', '.ts'}
MAX_FILES = 300
MAX_BYTES = 1024 * 1024
MAX_ENTRIES = 2000
MAX_LINES = 10000
MAX_FINDINGS = 1000


def script_findings(text, relative):
    findings = scan_text(text, relative)
    extra = [
        ('script_interpreter_delegation', r'\bdo shell script\b|\bWScript\.Shell\b|\bShellExecute\b',
         'Delegates execution to a shell or other program; check the selected command and authorization.'),
        ('batch_destructive_operation', r'\b(?:del|erase)\b[^\n]{0,150}/[sq]\b|\b(?:rd|rmdir)\b[^\n]{0,150}/s\b|\bformat\s+[a-z]:',
         'Batch removal or formatting capability needs exact scope review.'),
        ('startup_registration', r'\bschtasks\b[^\n]{0,150}/create\b|\bRegister-ScheduledTask\b|\blaunchctl\s+(?:load|bootstrap)\b',
         'Can register a scheduled or background job; confirm purpose and frequency.'),
    ]
    for index, line in enumerate(text.splitlines()):
        for rule, pattern, reason in extra:
            if re.search(pattern, line, re.I):
                findings.append({'file': str(relative), 'line': index + 1, 'rule': rule,
                                 'status': 'review_signal', 'reason': reason,
                                 'context_tags': ['comment_context'] if line.lstrip().startswith(('#', '//', "'", 'REM ')) else [],
                                 'source_excerpt': 'omitted'})
    return findings


def collect(roots):
    stats = collections.Counter()
    inventory, findings, coverage = [], [], []
    seen = set()
    for root_arg in roots:
        root = Path(root_arg).expanduser().absolute()
        row = {'root': str(root), 'status': 'complete', 'entries_considered': 0, 'scripts_scanned': 0, 'skips': {}}
        coverage.append(row)
        before = stats.copy()
        try:
            if is_redirected(root):
                row['status'] = 'redirected_root_skipped'
                continue
            info = root.lstat()
            if not stat.S_ISDIR(info.st_mode):
                row['status'] = 'not_directory'
                continue
        except FileNotFoundError:
            row['status'] = 'absent'
            continue
        except OSError:
            row['status'] = 'unavailable'
            continue
        stack = [(root, 0)]
        while stack:
            directory, depth = stack.pop()
            if stats['entries_considered'] >= MAX_ENTRIES or stats['scripts_scanned'] >= MAX_FILES:
                row['status'] = 'partial_limit'
                break
            try:
                if is_redirected(directory):
                    stats['redirected_entries_skipped'] += 1
                    continue
                with os.scandir(directory) as entries:
                    for entry in entries:
                        if stats['entries_considered'] >= MAX_ENTRIES or stats['scripts_scanned'] >= MAX_FILES:
                            row['status'] = 'partial_limit'
                            break
                        stats['entries_considered'] += 1
                        path = Path(entry.path)
                        if entry.name.casefold() in SKIP_DIRS or entry.name.startswith('.') or SENSITIVE_NAME.search(entry.name):
                            stats['excluded_names'] += 1
                            continue
                        try:
                            if is_redirected(path):
                                stats['redirected_entries_skipped'] += 1
                                continue
                            if entry.is_dir(follow_symlinks=False):
                                if depth < 2:
                                    stack.append((path, depth + 1))
                                else:
                                    stats['depth_limited_directories'] += 1
                                continue
                            if path.suffix.lower() not in SUFFIXES:
                                continue
                            if str(path) in seen:
                                continue
                            seen.add(str(path))
                            skipped_before = stats.copy()
                            text = read_bounded(path, MAX_BYTES, stats)
                            if text is None:
                                inventory.append({'name': path.name, 'path': str(path), 'source': str(root),
                                                  'signal_count': None, 'scan_status': 'not_read',
                                                  'skip_reason': dict(stats - skipped_before)})
                                continue
                            lines = text.splitlines()
                            if len(lines) > MAX_LINES:
                                stats['line_limited_files'] += 1
                            local = script_findings('\n'.join(lines[:MAX_LINES]), path.relative_to(root))
                            stats['scripts_scanned'] += 1
                            stats['signals_observed'] += len(local)
                            available = MAX_FINDINGS - len(findings)
                            for item in local[:max(0, available)]:
                                item['source'] = str(root)
                                findings.append(item)
                            if len(local) > available:
                                stats['findings_omitted_by_limit'] += len(local) - max(0, available)
                            inventory.append({'name': path.name, 'path': str(path), 'source': str(root),
                                              'signal_count': len(local), 'scan_status': 'line_limited' if len(lines) > MAX_LINES else 'scanned'})
                        except OSError:
                            stats['metadata_errors'] += 1
            except OSError:
                stats['directory_errors'] += 1
                row['status'] = 'partial_read_errors'
        delta = stats - before
        row['entries_considered'] = delta['entries_considered']
        row['scripts_scanned'] = delta['scripts_scanned']
        row['skips'] = {k:v for k,v in delta.items() if k not in ('entries_considered', 'scripts_scanned', 'signals_observed')}
        material_skips = set(row['skips']) - {'excluded_names'}
        if material_skips and row['status'] == 'complete':
            row['status'] = 'partial_reported_skips'
    partial = any(r['status'] not in ('complete', 'absent') for r in coverage)
    has_source = any(r['status'] == 'complete' or r['scripts_scanned'] for r in coverage)
    status = 'review' if stats['scripts_scanned'] else 'review' if has_source else 'unknown'
    limits = ['只掃描指定資料夾，最多 2000 筆目錄項目、300 個文字腳本、每檔 1 MiB／前 10000 行、子資料夾深度 2。',
              '略過敏感名稱、隱藏項目、相依套件、符號連結／reparse point、二進位及非 UTF-8 檔案；未掃描不等於安全。',
              '最多保留 1000 筆規則線索；截斷及略過範圍會記錄。規則命中須人工檢查上下文，不是惡意程式判決。',
              '沒有執行、載入、隔離或刪除受檢腳本，也沒有讀取指令歷史。']
    summary = '讀取 %s 個文字腳本，觀察到 %s 筆需人工複核的規則線索。' % (stats['scripts_scanned'], stats['signals_observed']) if has_source else '無法取得可檢查的腳本來源；不能推論沒有腳本或沒有風險。'
    check = {'id': 'files.scripts', 'category': 'files', 'title': '電腦腳本靜態檢測', 'status': status,
             'severity': 'medium' if stats['signals_observed'] else 'info', 'summary': summary,
             'impact': '腳本可批次操作檔案、下載程式或傳送資料。需要知道其用途、來源與實際執行方式。',
             'actions': ['按檔案與行號複核下載執行、刪除、權限變更、憑證存取及外傳能力。', '有需要再明確指定其他腳本資料夾；不要直接擴展成整顆磁碟。'],
             'evidence': [{'source': '限定來源與覆蓋', 'detail': json.dumps(coverage, ensure_ascii=False)},
                          {'source': '靜態規則線索（未保留程式內容）', 'detail': json.dumps(findings, ensure_ascii=False)}],
             'limitations': limits, 'terms': ['script', 'static_analysis']}
    return {'schema_version': '2.0', 'module': 'scripts', 'observed_at': dt.datetime.now(dt.timezone.utc).isoformat(),
            'coverage_status': 'partial' if partial else 'complete', 'checks': [check], 'inventories': {'scripts': inventory},
            'summary': dict(stats), 'coverage': coverage, 'findings': findings, 'limitations': limits,
            'inspected_code_executed': False, 'source_text_retained': False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--home', type=Path, default=Path.home())
    parser.add_argument('--root', type=Path, action='append', help='Explicit directory; replaces defaults, bounded depth')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    home = args.home.expanduser().absolute()
    roots = args.root or [home / 'Scripts', home / '.local/bin', home / 'Downloads']
    data = collect(roots)
    args.output.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    write_new(args.output, data)
    print(json.dumps({'status': 'completed', 'coverage_status': data['coverage_status'], 'scripts_scanned': data['summary'].get('scripts_scanned', 0)}))


if __name__ == '__main__':
    main()
