#!/usr/bin/env python3
"""Generate clearly labeled synthetic UI examples; never inspect this computer."""
import argparse
import sys
sys.dont_write_bytecode = True
import datetime as dt
from pathlib import Path
from audit_io import private_directory, write_new
from report_model import build_report, check, ev, render_html


def demo_model():
    now=dt.datetime.now().astimezone(); start=now-dt.timedelta(days=14)
    cases=[
        ('defender','system','即時防毒保護','pass','示範：Defender 即時保護已開啟。','defender'),
        ('firewall','system','網路防火牆','pass','示範：三個網路設定檔的防火牆均開啟。','firewall'),
        ('encryption','system','磁碟資料加密','unknown','示範：無權限確認磁碟加密；保留資訊缺口。','bitlocker'),
        ('updates','system','系統更新','review','示範：只有安裝紀錄，尚未比對可用安全更新。',''),
        ('backup','backup','備份成功與還原','attention','示範：使用者回報尚未建立獨立備份。','backup'),
        ('wifi','network','目前 Wi-Fi 連線保護','pass','示範：目前連線使用 WPA3。','wifi'),
        ('bluetooth','devices','藍牙與連線裝置','review','示範：有 2 個連線裝置，請核對是否認識。','bluetooth'),
        ('listeners','network','程式連線入口','review','示範：測試工具有 1 個綁定所有介面的入口。','listener'),
        ('startup','apps','背景啟動程式','review','示範：有 3 個使用者啟動項目，需確認用途。','permissions'),
        ('background','apps','背景程序與服務','review','示範：已列出程序與服務快照，需核對用途。','background_process'),
        ('files','files','近期下載檔案','review','示範：一筆安裝檔需核對官方來源，未判定惡意。','signature')]
    checks=[check('demo.'+i,c,t,s,summary,'此處是介面示範，並未讀取任何電腦。',
                  ['此為假資料：正式使用請執行 run_audit.py，再按實機證據判讀。'],
                  [ev('人工編寫的示範資料','不代表任何實際裝置狀態。')],
                  severity='high' if s=='attention' else 'medium' if s=='review' else 'info',terms=[term] if term else [])
            for i,c,t,s,summary,term in cases]
    modules={
        'system':{'checks':checks,'inventories':{
            'apps':[{'name':n,'version':'示範','source':'示範程式清單','state':s} for n,s in [('文件編輯器','目前執行中'),('視訊會議','已安裝'),('繪圖工具','目前執行中')]],
            'devices':[{'name':'示範鍵盤','type':'Bluetooth','state':'目前已連線'},{'name':'示範耳機','type':'Bluetooth','state':'目前已連線'}],
            'background':[{'name':'示範同步服務','state':'目前執行中','source':'示範服務清單','pid':1234},
                          {'name':'示範列印服務','state':'目前未執行','source':'示範服務清單','pid':None}]}},
        'scripts':{'checks':[check('demo.scripts','files','電腦腳本靜態檢測','review','示範：一個腳本包含需要人工複核的操作。',
                  '只示範如何呈現規則線索，並非惡意判決。',['核對操作目標與實際用途。'],
                  [ev('人工示範','整理工具.ps1：第 10 行 Remove-Item；未執行。')],terms=['script','static_analysis'])],
                  'inventories':{'scripts':[{'name':'整理工具.ps1','path':'示範腳本資料夾','source':'人工示範','signal_count':1},
                                            {'name':'報表工具.py','path':'示範腳本資料夾','source':'人工示範','signal_count':0}]}},
        'skills':{'summary':{'skill_packages':4,'files_scanned':24,'review_signals':3},'inventory':[
            {'name_from_directory':n,'skill_directory':'示範來源','review_signals':count} for n,count in [('document-helper',0),('spreadsheet-helper',1),('image-helper',0),('legacy-helper',2)]],
            'findings':[{'skill_directory':'legacy-helper','file':'scripts/example.py','line':12,'rule':'destructive_operation','status':'review_signal','context_tags':['example'],'source_excerpt':'omitted'}]},
        'browser':{'profiles':[{'browser':'示範瀏覽器','profile':'示範設定檔','cookies':{'status':'read_only_ok','total':1200,'expired_rows':140,'expires_more_than_365_days_from_now':90},
                               'extensions':[{'name_untrusted':'示範擴充功能','requested_sensitive_permissions':['cookies'],'review_flags':['broad_or_sensitive_requested_permissions']}]}],
                   'coverage_totals':{'discovered_profiles':2},'coverage_status':'partial'}}
    usage={k:{'status':'available','source':'人工編寫示範，非真實使用紀錄','period_start':start.isoformat(),'period_end':now.isoformat(),
              'unit':'invocations' if k=='skills' else 'launches',
              'limitation':'所有數字均為假資料，不可據此刪除任何程式或技能。',
              'items':[{'name':name,'count':count} for name,count in rows]}
           for k,rows in [('skills',[('document-helper',28),('spreadsheet-helper',18),('image-helper',7),('legacy-helper',0)]),
                          ('apps',[('文件編輯器',32),('視訊會議',16),('繪圖工具',11)])]}
    manifest={'platform':'Windows','generated_at':now.isoformat(),'modules':[{'module':n,'status':'completed','coverage_status':'synthetic_demo'} for n in modules]}
    report=build_report(modules,manifest,usage=usage,demo=True)
    report['meta']['title']='電腦資安健檢 · 示範報告'
    report['metrics']['traffic']={'interval_seconds':3,'items':[{'name':'示範同步程式','sent_bytes':320000,'received_bytes':180000},{'name':'示範瀏覽器','sent_bytes':40000,'received_bytes':230000}]}
    return report


def main():
    parser=argparse.ArgumentParser(description=__doc__); parser.add_argument('--output-dir',type=Path,required=True)
    args=parser.parse_args(); out=args.output_dir.expanduser().absolute(); private_directory(out)
    report=demo_model(); write_new(out/'report.json',report)
    template=(Path(__file__).resolve().parent.parent/'assets/report.html').read_text(encoding='utf-8')
    write_new(out/'report.html',render_html(report,template),False)
    print('Synthetic demo created; no device audit performed.')

if __name__=='__main__': main()
