#!/usr/bin/env python3
"""Read-only Mac process names and user launchd state; no command lines or changes."""
import argparse
import datetime as dt
import json
import os
from pathlib import Path
import platform
import re
import subprocess
import sys
sys.dont_write_bytecode = True
from audit_io import write_new


def query(argv):
    try:
        p = subprocess.run(argv, capture_output=True, timeout=15)
        if p.returncode or len(p.stdout) > 4 * 1024 * 1024:
            return {'status': 'unavailable'}
        return {'status': 'ok', 'text': p.stdout.decode('utf-8', errors='replace')}
    except (OSError, subprocess.TimeoutExpired):
        return {'status': 'unavailable'}


def clean(value, limit=220):
    return re.sub(r'[\x00-\x1f\x7f\u202a-\u202e\u2066-\u2069]', '', value)[:limit]


def process_snapshot(result, uid=None):
    if result.get('status') != 'ok':
        return [], {'status': 'unavailable'}
    uid = os.getuid() if uid is None else uid
    items, errors = [], 0
    lines = result.get('text', '').splitlines()
    for line in lines[:4000]:
        parts = line.strip().split(None, 3)
        if len(parts) != 4 or not parts[0].isdigit() or not parts[1].isdigit():
            errors += 1
            continue
        pid, owner, state, command = parts
        # ps comm is the executable name/path, never arguments. Keep basename only.
        name = clean(command.rsplit('/', 1)[-1]) or '未識別程序'
        owner_kind = '目前使用者' if int(owner) == uid else '系統 root' if owner == '0' else '其他系統或使用者帳號'
        phase = {'R': '正在運行', 'S': '睡眠／等待', 'I': '閒置', 'T': '暫停', 'Z': '已結束等待回收', 'U': '等待系統資源'}.get(state[0], '其他程序狀態')
        items.append({'name': name, 'state': owner_kind + '；' + phase, 'source': 'ps（執行中的程序）', 'pid': int(pid)})
    return items, {'status': 'partial' if errors or len(lines) > 4000 else 'complete', 'observed_count': len(items),
                   'unparsed_lines': errors, 'truncated': len(lines) > 4000}


def service_snapshot(result):
    if result.get('status') != 'ok':
        return [], {'status': 'unavailable'}
    lines = result.get('text', '').splitlines()
    if not lines or not lines[0].startswith('PID'):
        return [], {'status': 'unavailable', 'reason': 'unexpected_header'}
    items, errors, active = [], 0, 0
    for line in lines[1:1001]:
        parts = line.split('\t')
        if len(parts) != 3:
            errors += 1
            continue
        pid, last_status, label = parts
        if not (pid == '-' or pid.isdigit()) or not re.fullmatch(r'-?\d+', last_status):
            errors += 1
            continue
        running = pid.isdigit()
        active += int(running)
        items.append({'name': clean(label), 'state': '目前執行' if running else '已登錄；目前未執行',
                      'source': 'launchctl（目前使用者服務）', 'pid': int(pid) if running else None,
                      'last_exit_status': int(last_status)})
    return items, {'status': 'partial' if errors or len(lines) > 1001 else 'complete', 'observed_count': len(items),
                   'running_count': active, 'unparsed_lines': errors, 'truncated': len(lines) > 1001}


def collect():
    if platform.system() != 'Darwin':
        return {'status': 'unsupported', 'reason': 'Mac background collector only; Windows uses its system collector.'}
    processes, ps_coverage = process_snapshot(query(['/bin/ps', '-axo', 'pid=,uid=,stat=,comm=']))
    services, launch_coverage = service_snapshot(query(['/bin/launchctl', 'list']))
    limits = ['這是當下的程序與目前使用者 launchd 快照，非歷史紀錄；程序會隨時出現或結束。',
              '程序包含前景與背景工作，名稱不能證明來源或惡意；沒有拿執行中清單推論常用程式。',
              '最多 4000 個程序與 1000 個使用者服務；未列系統服務全部設定、環境變數、完整參數或私人操作內容。',
              '服務前次結束碼非零可能是正常生命週期或舊錯誤，不能直接判為入侵。未停止、啟動或更動任何服務。']
    checks = []
    for key, title, rows, scope, source in [('processes', '系統與背景程序快照', processes, ps_coverage, 'ps pid / uid class / stat / comm'),
                                           ('services', '目前使用者背景服務', services, launch_coverage, 'launchctl list（PID、結束碼、標籤）')]:
        available = scope['status'] in ('complete', 'partial')
        checks.append({'id': 'apps.background.' + key, 'category': 'apps', 'title': title,
                       'status': 'review' if available else 'unknown', 'severity': 'info',
                       'summary': '取得 %s 筆%s；請先核對用途，不依名稱判斷惡意。' % (len(rows), '程序' if key == 'processes' else '服務') if available else '無法取得本項資料；不是沒有背景工作。',
                       'impact': '背景工作可能提供同步、更新或遠端連線；需要與你實際使用的軟體核對。',
                       'actions': ['先核對不認識的名稱、軟體來源及用途；不自動停止系統或使用者服務。', '有具體疑慮時，再比對本報告的啟動設定與網路入口。'],
                       'evidence': [{'source': source, 'detail': json.dumps(scope, ensure_ascii=False)}],
                       'limitations': limits, 'terms': ['background_process', 'startup']})
    return {'schema_version': '2.0', 'module': 'background', 'platform': 'Darwin',
            'observed_at': dt.datetime.now(dt.timezone.utc).isoformat(),
            'coverage_status': 'complete' if ps_coverage['status'] == launch_coverage['status'] == 'complete' else 'partial',
            'checks': checks, 'inventories': {'background': processes + services},
            'process_coverage': ps_coverage, 'service_coverage': launch_coverage, 'limitations': limits}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--home', type=Path, default=Path.home(), help='Accepted for runner consistency; no history paths are read')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    data = collect()
    args.output.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    write_new(args.output, data)
    print(json.dumps({'status': data.get('status', 'completed'), 'coverage_status': data.get('coverage_status')}))


if __name__ == '__main__':
    main()
