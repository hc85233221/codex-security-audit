#!/usr/bin/env python3
"""Bounded macOS follow-up: backup status, App ACLs, and metadata gaps.

No backup mounting, source writes, app execution, credential reads, or repair.
"""
import argparse
import datetime as dt
import itertools
import json
import os
from pathlib import Path
import platform
import plistlib
import re
import stat
import subprocess
import sys
from xml.parsers.expat import ExpatError

sys.dont_write_bytecode = True
from audit_io import is_redirected, write_new
from inspect_connectivity import safe_regular_read

MAX_ENTRIES = 300
MAX_ACL_APPS = 20
BACKUP_NAMES = {
    'carbon copy cloner.app': '備份工具', 'superduper!.app': '備份工具',
    'backblaze.app': '備份工具', 'arq.app': '備份工具',
    'duplicati.app': '備份工具', 'duplicacy web edition.app': '備份工具',
    'chronosync.app': '備份工具', 'crashplan.app': '備份工具',
    'idrive.app': '備份工具', 'acronis true image.app': '備份工具',
    'get backup pro.app': '備份工具', 'timemachineeditor.app': '備份輔助工具',
    'google drive.app': '同步工具', 'dropbox.app': '同步工具',
    'onedrive.app': '同步工具', 'microsoft onedrive.app': '同步工具',
}


def clean(value, limit=180):
    return re.sub(r'[\x00-\x1f\x7f\u202a-\u202e\u2066-\u2069]', '', str(value))[:limit]


def query(argv, timeout=15):
    try:
        p = subprocess.run(argv, capture_output=True, timeout=timeout)
        if len(p.stdout) > 256 * 1024 or len(p.stderr) > 256 * 1024:
            return {'status': 'unavailable', 'reason': 'output_limit'}
        # Raw output stays internal; consumers retain only whitelist summaries.
        return {'status': 'ok' if p.returncode == 0 else 'unavailable',
                'text': p.stdout.decode('utf-8', errors='replace'),
                'error_text': p.stderr.decode('utf-8', errors='replace')}
    except subprocess.TimeoutExpired:
        return {'status': 'unavailable', 'reason': 'timeout'}
    except OSError:
        return {'status': 'unavailable', 'reason': 'command_unavailable'}


def backup_status(result, destinations):
    """Only parse non-identifying status flags. Never retain URLs, IDs or paths."""
    status = {'status': 'unknown', 'running': None, 'latest_success': 'not_checked'}
    text = result.get('text', '')
    running = re.search(r'^\s*Running\s*=\s*([01])\s*;', text, re.M)
    if result.get('status') == 'ok' and running:
        status.update(status='observed', running=running.group(1) == '1')
    dest_text = destinations.get('text', '') + '\n' + destinations.get('error_text', '')
    if re.search(r'No destinations configured', dest_text, re.I):
        status['destination_status'] = 'none_configured'
        status['destination_count'] = 0
    elif destinations.get('status') == 'ok':
        kinds = re.findall(r'^\s*Kind\s*:\s*(Local|Network)\s*$', dest_text, re.M)
        status['destination_status'] = 'configured' if kinds else 'unknown'
        status['destination_count'] = len(kinds) if kinds else None
        status['destination_kinds'] = kinds
    else:
        status['destination_status'] = 'unknown'
        status['destination_count'] = None
    return status


def acl_metadata(app, info, runner=query):
    result = runner(['/bin/ls', '-lde', str(app)])
    if result.get('status') != 'ok':
        return {'name': clean(app.name), 'mode': stat.filemode(info.st_mode),
                'acl_status': 'unknown', 'effective_write_test': 'not_performed'}
    # ACL principal names are not needed for this first check; retain allow/deny
    # and rights only. A '+' marker with missing entries must stay unknown.
    lines = result.get('text', '').splitlines()
    first = lines[0].split()[0] if lines and lines[0].split() else ''
    entries = []
    for line in lines[1:]:
        if re.match(r'^\s*\d+:', line):
            match = re.search(r'\b(allow|deny)\s+([A-Za-z_,]+)\s*$', line)
            entries.append({'action': match.group(1), 'rights': match.group(2)} if match else {'action': 'unparsed', 'rights': 'unknown'})
    recognized = bool(first) and first[0] == 'd'
    acl_status = 'entries_present' if entries else 'not_listed' if recognized and '+' not in first else 'unknown'
    return {'name': clean(app.name), 'mode': stat.filemode(info.st_mode),
            'world_writable': bool(info.st_mode & stat.S_IWOTH), 'acl_status': acl_status,
            'acl_entry_count': len(entries), 'acl_entries': entries[:80],
            'acl_truncated': len(entries) > 80, 'effective_write_test': 'not_performed'}


def inspect_apps(home, roots=None, runner=query):
    roots = roots or [(Path('/Applications'), '/Applications'),
                      (Path('/System/Applications'), '/System/Applications'),
                      (home / 'Applications', '~/Applications')]
    coverage, fallback, acls, tools_found = [], [], [], []
    for root, label in roots:
        row = {'source': label, 'status': 'complete', 'app_candidates': 0,
               'metadata_unavailable': 0, 'acl_candidates': 0}
        coverage.append(row)
        try:
            if is_redirected(root):
                row['status'] = 'redirected_root_skipped'; continue
            entries = list(itertools.islice(root.iterdir(), MAX_ENTRIES + 1))
            if len(entries) > MAX_ENTRIES: row['status'] = 'partial_limit'
        except FileNotFoundError:
            row['status'] = 'absent'; continue
        except OSError:
            row['status'] = 'unavailable'; continue
        for app in entries[:MAX_ENTRIES]:
            if app.suffix.lower() != '.app': continue
            row['app_candidates'] += 1
            try:
                info = app.lstat()
                redirect = is_redirected(app)
                if not stat.S_ISDIR(info.st_mode) and not redirect:
                    reason = '不是標準程式資料夾'
                elif redirect:
                    reason = '連結項目，未追蹤目標'
                else:
                    if app.name.casefold() in BACKUP_NAMES:
                        tools_found.append({'name':clean(app.stem), 'type':BACKUP_NAMES[app.name.casefold()], 'source':label})
                    if info.st_mode & stat.S_IWOTH:
                        row['acl_candidates'] += 1
                        if len(acls) < MAX_ACL_APPS:
                            item = acl_metadata(app, info, runner)
                            item['source'] = label
                            acls.append(item)
                        else:
                            row['status'] = 'partial_acl_limit'
                    try:
                        data = plistlib.loads(safe_regular_read(app/'Contents/Info.plist'))
                        if not isinstance(data, dict): raise ValueError('invalid_metadata')
                        continue
                    except FileNotFoundError:
                        reason = '缺少標準 Info.plist'
                    except PermissionError:
                        reason = '中繼資料存取受限'
                    except (ValueError, OSError, plistlib.InvalidFileException, ExpatError, OverflowError):
                        reason = '中繼資料格式或安全讀取條件不符'
            except OSError:
                reason = '程式中繼資料無法取得'
            row['metadata_unavailable'] += 1
            fallback.append({'name':clean(app.stem), 'version':'未知', 'source':label,
                             'state':'僅取得名稱；'+reason, 'metadata_status':'name_only'})
    return {'coverage':coverage,'apps':fallback,'acl_items':acls,'backup_candidates':tools_found}


def check(identifier, category, title, status, summary, evidence, actions, limits, terms=None, severity='info'):
    return {'id':identifier,'category':category,'title':title,'status':status,'severity':severity,
            'summary':summary,'impact':'','actions':actions,'evidence':evidence,
            'limitations':limits,'terms':terms or []}


def collect(home, roots=None, runner=query):
    apps = inspect_apps(home, roots, runner)
    backup = backup_status(runner(['/usr/bin/tmutil','status']), runner(['/usr/bin/tmutil','destinationinfo']))
    backup_limits = ['只讀 Time Machine 狀態與目的地摘要；不掛載磁碟、啟動備份、讀取備份檔案或修改排程。',
                     '不呼叫 latestbackup：部分系統會隱含嘗試掛載目的地。最近成功日期與還原能力仍需在介面確認。',
                     '只找常見備份／同步程式名稱；沒有找到不代表沒有其他備份，安裝或同步也不代表備份成功。']
    current = '目前正在備份。' if backup['running'] is True else '目前沒有備份工作執行。' if backup['running'] is False else '目前備份工作狀態未知。'
    backup_check = check('supplemental.backup_status','backup','備份狀態補查','unknown',
                         current+' 尚未確認可還原的備份。',
                         [{'source':'tmutil status / destinationinfo（僅白名單摘要）','detail':json.dumps(backup,ensure_ascii=False)},
                          {'source':'常見備份／同步程式名稱','detail':json.dumps(apps['backup_candidates'],ensure_ascii=False)}],
                         ['在正在使用的備份工具查看最近成功日期，並確認可還原。'],backup_limits,['backup'])
    writable = [x for x in apps['acl_items'] if x.get('world_writable')]
    acl_known = any(x['acl_status']!='unknown' for x in apps['acl_items'])
    acl_check = check('supplemental.app_acl','apps','程式資料夾權限補查','attention' if writable else 'review' if acl_known else 'unknown',
                      '已補查 %d 個權限過寬的程式資料夾。' % len(apps['acl_items']) if apps['acl_items'] else '本次未取得需要補查 ACL 的程式資料夾。',
                      [{'source':'ls -lde / lstat（只讀頂層）','detail':json.dumps(apps['acl_items'],ensure_ascii=False)},
                       {'source':'掃描範圍','detail':json.dumps(apps['coverage'],ensure_ascii=False)}],
                      ['先核對官方安裝／更新需求，再決定修復方式；不要直接遞迴改權限。'],
                      ['只補查頂層權限，沒有測試寫入或檢查所有套件內檔案。',
                       'ACL 沒有列出，不等於已測試所有帳號的實際寫入能力；過寬權限也不等於程式惡意。'],
                      ['acl','permissions'], 'high' if writable else 'info')
    missing = len(apps['apps'])
    any_read = any(x['status'] in ('complete','partial_limit','partial_acl_limit') for x in apps['coverage'])
    metadata_check = check('supplemental.app_metadata','apps','程式清單補齊','review' if any_read else 'unknown',
                           '補列 %d 個僅能取得名稱的項目；版本仍未知。' % missing if any_read else '未能讀取程式目錄，無法補列名稱。',
                           [{'source':'App 資料夾名稱與 Info.plist 安全讀取結果','detail':json.dumps(apps['apps'],ensure_ascii=False)}],
                           ['需要核對特定程式版本時，另外查看該程式的官方更新介面。'],
                           ['未追蹤連結、開啟程式或解析啟動參數；非標準資料不等於惡意。',
                            '補列名稱不代表已完成版本、來源或簽章驗證。'],['signature'])
    return {'schema_version':'2.1','module':'supplemental','platform':'Darwin',
            'observed_at':dt.datetime.now().astimezone().isoformat(),'coverage_status':'partial',
            'checks':[backup_check,acl_check,metadata_check], 'inventories':{'apps':apps['apps']},
            'backup_status':backup,'app_acl':apps['acl_items'],'app_coverage':apps['coverage'],
            'backup_candidates':apps['backup_candidates'],
            'limitations':['局部唯讀補查；無外部帳號存取、備份掛載或防護設定變更。']}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--home',type=Path,default=Path.home())
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    if platform.system()!='Darwin':
        data={'status':'unsupported','coverage_status':'not_checked','reason':'Mac supplemental collector only.'}
    else:
        data=collect(args.home.expanduser().absolute())
    write_new(args.output,data)
    print(json.dumps({'coverage_status':data['coverage_status'],'output':str(args.output)},ensure_ascii=False))


if __name__=='__main__':main()
