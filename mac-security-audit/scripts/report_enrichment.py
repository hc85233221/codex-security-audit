"""Merge dated, bounded local supplements without duplicating findings."""
import copy
import datetime as dt
import json
import hashlib
import os
from pathlib import Path
import stat
from audit_io import is_redirected


def read_json_bounded(path, limit=16*1024*1024, with_digest=False):
    path=Path(path).expanduser().absolute()
    if path.suffix.lower()!='.json' or path.name.lower() in {'auth.json','credentials.json','tokens.json','secrets.json'}:
        raise ValueError('Only audit JSON files are accepted.')
    if is_redirected(path): raise ValueError('Redirected report source is not accepted.')
    before=path.lstat()
    if not stat.S_ISREG(before.st_mode) or before.st_size>limit: raise ValueError('Report source is not a bounded regular file.')
    fd=os.open(path,os.O_RDONLY|getattr(os,'O_NOFOLLOW',0)|getattr(os,'O_NONBLOCK',0))
    with os.fdopen(fd,'rb') as stream:
        opened=os.fstat(stream.fileno())
        if not stat.S_ISREG(opened.st_mode) or (opened.st_dev,opened.st_ino)!=(before.st_dev,before.st_ino):
            raise ValueError('Report source changed.')
        raw=stream.read(limit+1); after=os.fstat(stream.fileno())
    if len(raw)>limit or (opened.st_size,opened.st_mtime_ns,opened.st_ctime_ns)!=(after.st_size,after.st_mtime_ns,after.st_ctime_ns):
        raise ValueError('Report source changed or exceeds limit.')
    data=json.loads(raw.decode('utf-8'),parse_constant=lambda _: (_ for _ in ()).throw(ValueError('Nonfinite JSON.')))
    return (data,hashlib.sha256(raw).hexdigest()) if with_digest else data


def timestamp(value):
    if not isinstance(value,str): raise ValueError('Supplement needs its observation time.')
    parsed=dt.datetime.fromisoformat(value.replace('Z','+00:00'))
    if parsed.tzinfo is None: raise ValueError('Observation time must include a timezone.')
    return parsed


def validate_module(data):
    if not isinstance(data,dict) or data.get('module') not in ('manual_ui','supplemental','recent_apps','codex_usage','exposure','ai_artifacts'):
        raise ValueError('Unsupported supplement module.')
    timestamp(data.get('observed_at'))
    checks=data.get('checks',[])
    if not isinstance(checks,list) or len(checks)>40: raise ValueError('Invalid supplemental checks.')
    ids=set()
    for item in checks:
        if not isinstance(item,dict): raise ValueError('Invalid supplemental check.')
        if not isinstance(item.get('id'),str) or item['id'] in ids: raise ValueError('Invalid or duplicate check ID.')
        ids.add(item['id'])
        if item.get('status') not in ('pass','attention','review','unknown','not_checked'):
            raise ValueError('Invalid check status.')
        if item.get('category') not in ('system','backup','network','devices','apps','skills','browser','files'):
            raise ValueError('Invalid category.')
        if not isinstance(item.get('summary'),str) or not isinstance(item.get('title'),str):
            raise ValueError('Missing check description.')
        for key in ('actions','limitations','terms'):
            if key in item and (not isinstance(item[key],list) or not all(isinstance(x,str) for x in item[key])):
                raise ValueError('Invalid text list.')
        if not isinstance(item.get('evidence',[]),list): raise ValueError('Invalid evidence.')
        if data['module']=='manual_ui' and item['id'] not in {'manual.privacy','manual.login_items','manual.sharing','manual.lock_screen'}:
            raise ValueError('Manual UI source may only supply observed local UI checks.')
        if data['module']=='codex_usage' and (item['id']!='usage.skills' or item['category']!='skills' or item['status']!='unknown'):
            raise ValueError('Codex source review may only document unknown skill frequency.')
        if data['module']=='exposure' and not item['id'].startswith('exposure.'):
            raise ValueError('Exposure checks cannot replace unrelated findings.')
        if data['module']=='ai_artifacts' and (not item['id'].startswith('ai_artifacts.') or
                item['category'] not in ('skills','files') or item['status']=='pass'):
            raise ValueError('AI file triage cannot replace unrelated checks or certify safety.')
    if data['module']=='ai_artifacts':
        inventories=data.get('inventories',{})
        if not isinstance(inventories,dict) or set(inventories)-{'ai_artifacts'}:
            raise ValueError('AI file triage cannot replace unrelated inventories.')
        rows=inventories.get('ai_artifacts',[])
        if not isinstance(rows,list) or len(rows)>2000 or any(not isinstance(row,dict) for row in rows):
            raise ValueError('Invalid AI file inventory.')
    if data['module']=='codex_usage':
        if data.get('inventories'): raise ValueError('Codex source review cannot supply device inventory.')
        review=data.get('usage_review',{})
        if not isinstance(review,dict) or any(not isinstance(v,str) for v in review.values()):
            raise ValueError('Invalid Codex source review.')
        if set(review)-{'source','period_start','period_end','evidence_note'}:
            raise ValueError('Unsupported Codex source review field.')
        for field in ('period_start','period_end'):
            if field in review: timestamp(review[field])
    return data


def app_identity(row):
    source=row.get('application_root',row.get('source',''))
    # Different home-directory spellings from the bounded collectors refer to
    # the same per-user app root. Do not merge other roots merely by app name.
    if source.startswith('/Users/') and source.endswith('/Applications'):
        source='~/Applications'
    return (str(row.get('name','')).casefold(),source)


def enrich_report(report, modules):
    report=copy.deepcopy(report)
    checks=report['checks']; by_id={c['id']:c for c in checks}; dates=[]; manual=None
    merged={'supplemental.backup_status':'mac.backup','supplemental.app_acl':'mac.app_permissions',
            'manual.login_items':'mac.startup'}
    for name in ('supplemental','recent_apps','manual_ui','codex_usage','exposure','ai_artifacts'):
        data=modules.get(name)
        if data is not None and not isinstance(data,dict): raise ValueError('Invalid supplement module.')
        execution=next((x for x in report.get('manifest',{}).get('modules',[]) if x.get('module')==name),None)
        explicitly_added=any(x.get('module')==name for x in report.get('manifest',{}).get('supplements',[]))
        failed_data=data and (data.get('status') in ('failed','unsupported','timeout','unavailable') or data.get('coverage_status') in ('not_checked','failed','unavailable'))
        if failed_data or (execution and execution.get('status')!='completed' and not explicitly_added) or (execution and not data):
            report['scope'].append({'module':name,'status':'unavailable','detail':'補查模組未完成，不能當成沒有問題。'})
            checks.append({'id':'module.'+name,'category':'files' if name=='ai_artifacts' else 'apps','title':'AI 檔案檢查未完成' if name=='ai_artifacts' else '本機補查未完成','status':'unknown','severity':'info',
                           'summary':'模組 '+name+' 未取得可判讀結果。','actions':[],'evidence':[],'limitations':[],'terms':[]})
            continue
        if not data:
            if name=='ai_artifacts':
                report['scope'].append({'module':name,'status':'not_selected','detail':'本次未執行 AI 設定與近期檔案檢查。'})
                checks.append({'id':'module.ai_artifacts','category':'files','title':'AI 設定與近期檔案','status':'not_checked','severity':'info',
                               'summary':'本次尚未取得 AI 檔案檢查資料。','actions':['需要時指定近期生成檔案的資料夾，再做唯讀檢查。'],
                               'evidence':[],'limitations':['沒有遍歷整顆磁碟或讀取聊天內容。'],'terms':['ai_provenance']})
            continue
        validate_module(data)
        if data['module'] != name:
            raise ValueError('Supplement module name does not match its source.')
        dates.append(timestamp(data['observed_at']))
        if name=='manual_ui': manual=data
        report['scope'].append({'module':{'supplemental':'備份與程式補查','recent_apps':'程式最近開啟','manual_ui':'系統設定補查','codex_usage':'Codex 使用來源補查','exposure':'管理、代理與登入設定','ai_artifacts':'AI 設定與近期檔案'}[name],
                                'status':'partial' if data.get('coverage_status')=='partial' else 'completed',
                                'detail':'觀察時間：'+data['observed_at']+'；'+str(data.get('coverage_status','bounded'))})
        for original in data.get('checks',[]):
            item=copy.deepcopy(original); item['observed_at']=data['observed_at']
            item.setdefault('evidence',[]).insert(0,{'source':'本次補查時間','detail':data['observed_at']})
            target=by_id.get(merged.get(item['id'],item['id']))
            if name=='codex_usage' and target and report.get('usage',{}).get('skills',{}).get('status')=='available':
                target.setdefault('evidence',[]).extend(item.get('evidence',[]))
                target.setdefault('limitations',[]).extend(item.get('limitations',[]))
                continue
            if item['id'] in merged and target:
                # Supplemental unknown backup reliability must not erase an
                # observed missing Time Machine destination, nor imply success.
                target.setdefault('evidence',[]).extend(item.get('evidence',[]))
                target.setdefault('limitations',[]).extend(item.get('limitations',[]))
                target['supplemented_at']=data['observed_at']
                if item['id']=='supplemental.app_acl':
                    target['actions']=item.get('actions',target.get('actions',[]))
                if item['id']=='manual.login_items':
                    target['short_summary']=item.get('short_summary',item['summary'])
                continue
            if target:
                checks[checks.index(target)]=item
            else: checks.append(item)
            by_id[item['id']]=item
        if name=='ai_artifacts':
            # A supplement is a newly observed bounded scope, not an additive
            # lifetime inventory; keep no stale rows or duplicated file counts.
            report.setdefault('inventories',{})['ai_artifacts']=copy.deepcopy(data.get('inventories',{}).get('ai_artifacts',[]))
        if name=='codex_usage':
            usage=report.setdefault('usage',{}).setdefault('skills',{'status':'unknown','items':[]})
            if usage.get('status')!='available':
                usage.update(copy.deepcopy(data.get('usage_review',{})))
                usage['status']='unknown'
                usage['items']=[]
                usage['limitations']=[line for c in data.get('checks',[]) for line in c.get('limitations',[])]
                for request in report.get('access_requests',[]):
                    if request.get('id')=='usage':
                        request['reason']='已補查授權的 Codex 使用來源，仍未取得完整使用次數。'
                        request['request']='若你原本已有其他聚合統計，可再由 Codex 核對；目前保留盤點與最近開啟資料。'
        app_index={app_identity(row):row for row in report['inventories'].get('apps',[])}
        for original in data.get('inventories',{}).get('apps',[]):
            row=copy.deepcopy(original); key=app_identity(row); target=app_index.get(key)
            if name=='recent_apps':
                if target is None:
                    row['source']=row.get('application_root','未提供'); row['version']='未知'
                    row['state']='僅有最近開啟中繼資料'; target=row
                    report['inventories']['apps'].append(target); app_index[key]=target
                for field in ('last_opened_at','last_opened_status'):
                    target[field]=original.get(field)
                target['last_opened_source']=original.get('source')
                target['last_opened_observed_at']=data['observed_at']
            elif target is None:
                report['inventories']['apps'].append(row); app_index[key]=row
    if dates: report['meta']['supplemented_at']=max(dates).isoformat()
    if manual:
        privacy=by_id.get('manual.privacy',{})
        if privacy.get('status') not in ('unknown','not_checked'):
            report['access_requests']=[r for r in report.get('access_requests',[]) if r.get('id')!='privacy']
        report['access_requests'].extend(copy.deepcopy(manual.get('follow_up_requests',[])))
        if manual.get('user_decisions',{}).get('account_review')=='deferred_by_user':
            account=by_id.get('manual.accounts')
            if account:
                account['summary']='依你的選擇，帳號安全稍後再查。'
                account['short_summary']=account['summary']; account['actions']=[]
                account['evidence']=[{'source':'使用者本次範圍選擇','detail':'先補本機，帳號稍後再查。'}]
        if manual.get('user_decisions',{}).get('other_backup')=='unknown_to_user':
            backup=by_id.get('mac.backup')
            if backup: backup['evidence'].append({'source':'使用者回覆','detail':'不確定是否有其他備份；未將此回覆解讀成沒有備份。'})
            for request in report.get('access_requests',[]):
                if request.get('id')=='backup':
                    request['reason']='你尚不確定有無其他備份；本機補查仍未取得成功備份證據。'
                    request['request']='後續可確認備份工具與成功日期，或另外安排建立備份。'
    short={
        'mac.startup':'已取得開機設定，請核對用途。',
        'mac.listeners':'有程式接受連線，請核對用途與範圍。',
        'mac.traffic':'已取短暫流量，無法判斷過去外洩。',
        'mac.logins':'只取得登入摘要，未涵蓋完整操作紀錄。',
        'mac.files':'已做有限範圍盤點，未掃描檔案內容。',
        'mac.credential_permissions':'只查檔案權限，未讀憑證內容。',
        'usage.skills':'缺少使用統計，無法判斷常用程度。',
        'usage.apps':'缺少使用統計，最近開啟不等於使用頻率。',
    }
    for item in checks:
        if item['id']=='mac.updates' and item['status']=='attention':
            item.setdefault('short_summary','有可用更新，先備份再安排。')
        # Keep unknown/failed summaries intact; never convert missing evidence
        # into a short positive sentence.
        if item['id'].startswith('usage.'):
            if item['status']=='unknown': item.setdefault('short_summary',short[item['id']])
        elif item['id'] in short and item['status'] not in ('unknown','not_checked'):
            item.setdefault('short_summary',short[item['id']])
    report['meta']['version']='3.1.0'
    report['meta']['scope_note']='唯讀檢查，未修改設定。報告留在本機。'
    return report
