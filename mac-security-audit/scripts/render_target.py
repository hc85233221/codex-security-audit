#!/usr/bin/env python3
"""Render an explicitly requested target review, without scanning anything."""
import argparse
import copy
import datetime as dt
import hashlib
from pathlib import Path
import sys
sys.dont_write_bytecode = True
from audit_io import private_directory, write_new
from report_enrichment import read_json_bounded, timestamp
from report_model import GLOSSARY, check, ev, render_html


def build_target_report(raw, storage_security=None, demo=False):
    if not isinstance(raw, dict) or raw.get('kind') not in ('link', 'website', 'folder'):
        raise ValueError('A supported target review is required.')
    timestamp(raw.get('observed_at'))
    if raw.get('status') not in ('review', 'unknown', 'attention'):
        raise ValueError('Target triage cannot claim a safety verdict.')
    for field in ('target_display', 'summary'):
        if not isinstance(raw.get(field), str): raise ValueError('Missing target description.')
    if not isinstance(raw.get('network_performed'), bool):
        raise ValueError('Network observation must be explicit.')
    findings=raw.get('findings', [])
    limitations=raw.get('limitations', [])
    if not isinstance(findings, list) or len(findings)>1000:
        raise ValueError('Findings must be bounded.')
    if not isinstance(limitations,list) or not all(isinstance(v,str) for v in limitations):
        raise ValueError('Invalid limitations.')
    checks=[]
    category='files' if raw['kind']=='folder' else 'network'
    for index, finding in enumerate(findings):
        if not isinstance(finding, dict) or not all(isinstance(finding.get(k),str) for k in ('title','detail')):
            raise ValueError('Invalid finding.')
        action=finding.get('action', '核對來源與實際用途，再決定是否開啟。')
        if not isinstance(action,str): raise ValueError('Invalid action.')
        severity=finding.get('severity','info')
        if severity=='critical': severity='high'
        if severity not in ('high','medium','low','info'): severity='info'
        status=finding.get('status',raw['status'])
        if status not in ('attention','review','unknown'): status='review'
        item=check('target.finding.'+str(index+1),category,finding['title'],status,finding['detail'],
                   '這是指定範圍內的線索，仍需核對上下文；不代表已確認惡意。',
                   [action],[ev('指定目標',raw['target_display']),ev('觀察時間',raw['observed_at'])],
                   severity=severity)
        item['observed_at']=raw['observed_at'];checks.append(item)
    if not checks:
        checks.append(check('target.coverage',category,'初步檢查結果',raw['status'],raw['summary'],
                            '沒有線索不等於安全認證；請連同檢查範圍與限制判讀。',
                            ['確認來源與用途；需要深入檢查時再指定範圍。'],
                            [ev('觀察時間',raw['observed_at'])],limitations=limitations))
    now=dt.datetime.now().astimezone().isoformat()
    kind_label={'link':'連結','website':'網站','folder':'資料夾'}[raw['kind']]
    return {
        'schema_version':'2.0',
        'meta':{'title':kind_label+'檢查報告','version':'3.0.0','mode':'target','platform':'指定目標',
                'observed_at':raw['observed_at'],'generated_at':now,'demo':bool(demo),
                'scope_note':'只檢查使用者指定目標，未更改目標或建立監控。'},
        'target_review':copy.deepcopy(raw),'checks':checks,
        'inventories':{k:[] for k in ('skills','apps','scripts','background','devices','extensions')},
        'usage':{k:{'status':'unknown','items':[]} for k in ('skills','apps')},'metrics':{},
        'glossary':[{'id':i,'term':t,'explanation':e} for i,t,e in GLOSSARY],
        'scope':[{'module':'指定'+kind_label,'status':'partial','detail':raw['summary']}],
        'limitations':limitations,'access_requests':[],
        'raw_modules':{'target':copy.deepcopy(raw)},
        'manifest':{'version':'3.0.0','mode':'target','generated_at':raw['observed_at'],
                    'read_only_scope':True,'report_storage':storage_security,
                    'network_performed':raw['network_performed'],
                    'limits':'Bounded target triage, not malware clearance or a vulnerability scan.'}}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input',type=Path,required=True)
    parser.add_argument('--output-dir',type=Path,required=True)
    parser.add_argument('--demo',action='store_true')
    args=parser.parse_args()
    try:
        raw,digest=read_json_bounded(args.input,with_digest=True)
        report=build_target_report(raw,demo=args.demo)
        scripts=Path(__file__).resolve().parent
        out=args.output_dir.expanduser().absolute()
        try: out.resolve().relative_to(scripts.parent.resolve())
        except ValueError: pass
        else: raise ValueError('Keep reports outside the shared skill.')
        storage=private_directory(out)
        report['manifest']['report_storage']=storage
        report['manifest']['target_source_sha256']=digest
        template=(scripts.parent/'assets/report.html').read_text(encoding='utf-8')
        report['manifest']['template_sha256']=hashlib.sha256(template.encode('utf-8')).hexdigest()
        write_new(out/'target.json',raw)
        write_new(out/'manifest.json',report['manifest'])
        write_new(out/'report.json',report)
        write_new(out/'report.html',render_html(report,template),False)
    except (OSError,ValueError,TypeError,KeyError,RecursionError):
        parser.error('Invalid target report or output is not a new private location.')
    print('Target report rendered without scanning or connecting.')


if __name__=='__main__': main()
