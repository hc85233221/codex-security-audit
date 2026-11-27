#!/usr/bin/env python3
"""Read one Spotlight recency attribute from bounded known app directories."""
import argparse
from concurrent.futures import ThreadPoolExecutor
import datetime as dt
import json
import os
from pathlib import Path
import platform
import re
import stat
import subprocess
import sys
import time

sys.dont_write_bytecode = True
from audit_io import is_redirected, write_new

MAX_APPS = 300
MAX_ENTRIES = 800
QUERY_TIMEOUT = 1.5
TOTAL_SECONDS = 45
SOURCE = 'Spotlight / LaunchServices'


def safe_name(name):
    return re.sub(r'[\x00-\x1f\x7f\u202a-\u202e\u2066-\u2069]', '', str(name))[:180]


def read_last_opened(path, deadline, now=None):
    """The single allowed metadata key is LastUsedDate; never query history arrays."""
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        return {'status': 'time_limit', 'last_opened_at': None}
    try:
        before = path.lstat()
        if not stat.S_ISDIR(before.st_mode) or is_redirected(path):
            return {'status': 'redirected_or_invalid_app', 'last_opened_at': None}
        proc = subprocess.run(['/usr/bin/mdls', '-raw', '-name', 'kMDItemLastUsedDate', str(path)],
                              capture_output=True, timeout=min(QUERY_TIMEOUT, remaining))
        if proc.returncode != 0 or len(proc.stdout) > 200:
            return {'status': 'unavailable', 'last_opened_at': None}
        after = path.lstat()
        if is_redirected(path) or (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino):
            return {'status': 'changed_during_query', 'last_opened_at': None}
        value = proc.stdout.decode('utf-8', errors='strict').strip()
        if value in ('(null)', 'null', ''):
            return {'status': 'not_recorded', 'last_opened_at': None}
        parsed = dt.datetime.strptime(value, '%Y-%m-%d %H:%M:%S %z').astimezone(dt.timezone.utc)
        if parsed > (now or dt.datetime.now(dt.timezone.utc)) + dt.timedelta(minutes=5):
            return {'status': 'timestamp_in_future', 'last_opened_at': None}
        return {'status': 'recorded', 'last_opened_at': parsed.isoformat()}
    except subprocess.TimeoutExpired:
        return {'status': 'timeout', 'last_opened_at': None}
    except (OSError, UnicodeError, ValueError):
        return {'status': 'unavailable', 'last_opened_at': None}


def collect(home=None, roots=None):
    now = dt.datetime.now(dt.timezone.utc)
    if platform.system() != 'Darwin':
        return {'status': 'unsupported', 'coverage_status': 'not_checked',
                'observed_at': now.isoformat(), 'reason': 'Spotlight recency query requires macOS.'}
    home = Path(home or Path.home()).expanduser().absolute()
    # roots is an internal fixture seam, never a CLI option for arbitrary files.
    roots = roots or [Path('/Applications'), home / 'Applications']
    candidates, coverage, seen = [], [], set()
    total_entries = 0
    for root in roots:
        root = Path(root).absolute()
        row = {'root': str(root), 'status': 'complete', 'entries_considered': 0, 'apps_selected': 0, 'skipped': 0}
        coverage.append(row)
        try:
            if is_redirected(root):
                row['status'] = 'redirected_root_skipped'; continue
            if not stat.S_ISDIR(root.lstat().st_mode):
                row['status'] = 'not_directory'; continue
            with os.scandir(root) as entries:
                for entry in entries:
                    if total_entries >= MAX_ENTRIES or len(candidates) >= MAX_APPS:
                        row['status'] = 'partial_limit'; break
                    total_entries += 1; row['entries_considered'] += 1
                    if not entry.name.lower().endswith('.app'):
                        continue
                    path = Path(entry.path)
                    try:
                        if is_redirected(path) or not entry.is_dir(follow_symlinks=False):
                            row['skipped'] += 1; continue
                        info = path.lstat(); identity = (info.st_dev, info.st_ino)
                        if identity in seen:
                            row['skipped'] += 1; continue
                        seen.add(identity)
                        candidates.append(path); row['apps_selected'] += 1
                    except OSError:
                        row['skipped'] += 1
            if row['skipped'] and row['status'] == 'complete':
                row['status'] = 'partial_skipped'
        except FileNotFoundError:
            row['status'] = 'absent'
        except OSError:
            row['status'] = 'unavailable'
    deadline = time.monotonic() + TOTAL_SECONDS
    with ThreadPoolExecutor(max_workers=4) as pool:
        details = list(pool.map(lambda p: read_last_opened(p, deadline, now), candidates))
    inventory = []
    for path, item in zip(candidates, details):
        inventory.append({'name': safe_name(path.stem), 'last_opened_at': item['last_opened_at'],
                          'last_opened_status': item['status'], 'source': SOURCE,
                          'application_root': str(path.parent),
                          'state': '有最近開啟紀錄' if item['status'] == 'recorded' else '最近開啟時間未知'})
    inventory.sort(key=lambda item: (item['last_opened_at'] or '', item['name']), reverse=True)
    recorded = sum(item['last_opened_status'] == 'recorded' for item in inventory)
    failed = sum(item['last_opened_status'] not in ('recorded', 'not_recorded') for item in inventory)
    partial = failed or any(row['status'] not in ('complete', 'absent') for row in coverage)
    missing = len(inventory) - recorded
    limits = ['只查 /Applications 與使用者 Applications 的頂層 App，最多 300 個；未遞迴或讀私人文件。',
              '最近開啟由 LaunchServices 留下，可能未涵蓋其他啟動方式；缺值不代表沒用過。',
              '這不是使用次數、時數或常用排名；未讀取開啟歷史陣列，也未收集不明期間的 useCount。']
    check = {'id': 'apps.recent_opened', 'category': 'apps', 'title': '程式最近開啟',
             'status': 'review' if recorded else 'unknown', 'severity': 'info',
             'summary': '取得 %d 個程式的最近開啟時間；%d 個仍未知。' % (recorded, missing),
             'impact': '可協助辨認最近開啟過的程式，但不能判斷使用頻率或是否應刪除。',
             'actions': ['在程式清單查看最近開啟線索；常用排名仍需有期間的使用統計。'],
             'evidence': [{'source': '/usr/bin/mdls — kMDItemLastUsedDate only',
                           'detail': json.dumps({'coverage': coverage, 'apps_queried': len(inventory),
                                                 'recorded': recorded, 'unknown': missing, 'query_errors': failed}, ensure_ascii=False)}],
             'limitations': limits, 'terms': ['usage']}
    return {'schema_version': '2.1', 'module': 'recent_apps', 'platform': 'Darwin',
            'observed_at': now.isoformat(), 'coverage_status': 'partial' if partial else 'complete',
            'checks': [check], 'inventories': {'apps': inventory}, 'coverage': coverage,
            'summary': {'apps_queried': len(inventory), 'recorded': recorded, 'unknown': missing, 'query_errors': failed},
            'limitations': limits, 'source': SOURCE}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--home', type=Path, default=Path.home())
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    result = collect(args.home)
    args.output.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    write_new(args.output, result)
    print(json.dumps({'coverage_status': result['coverage_status'], 'summary': result.get('summary', {})}))


if __name__ == '__main__':
    main()
