#!/usr/bin/env python3
"""Add explicitly collected supplements to an existing report; no new device scan."""
import argparse
import copy
import datetime as dt
import hashlib
from pathlib import Path
import sys
sys.dont_write_bytecode=True
from audit_io import private_directory, write_new
from report_enrichment import read_json_bounded, validate_module
from report_model import build_report, render_html


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--base-report',type=Path,required=True)
    parser.add_argument('--supplement',type=Path,action='append',default=[])
    parser.add_argument('--output-dir',type=Path,required=True)
    args=parser.parse_args()
    try:
        original,base_digest=read_json_bounded(args.base_report,with_digest=True)
        if not isinstance(original,dict) or not all(isinstance(original.get(k),dict) for k in ('raw_modules','manifest','meta')):
            raise ValueError('Base report requires module evidence and manifest.')
        modules=copy.deepcopy(original['raw_modules']); manifest=copy.deepcopy(original['manifest'])
        seen=set()
        for path in args.supplement:
            module=validate_module(read_json_bounded(path)); name=module['module']
            if name in seen: raise ValueError('Duplicate supplement module.')
            seen.add(name); modules[name]=module
        allowed_modules=('system','browser','skills','scripts','connectivity','background','supplemental','recent_apps','manual_ui','codex_usage','exposure','ai_artifacts')
        if any(name not in allowed_modules for name in modules):
            raise ValueError('Unsupported report module name.')
        scripts=Path(__file__).resolve().parent
        out=args.output_dir.expanduser().absolute()
        if out==args.base_report.expanduser().absolute().parent: raise ValueError('Use a new output directory.')
        try: out.relative_to(scripts.parent)
        except ValueError: pass
        else: raise ValueError('Output must be outside the shared skill.')
        manifest['report_storage']=private_directory(out)
        manifest['version']='3.1.0'
        manifest['base_observed_at']=original['meta'].get('observed_at')
        manifest['generated_at']=original['meta'].get('observed_at',manifest.get('generated_at'))
        manifest['rendered_at']=dt.datetime.now().astimezone().isoformat()
        manifest['base_report_sha256']=base_digest
        template_bytes=(scripts.parent/'assets/report.html').read_bytes()
        manifest['template_sha256']=hashlib.sha256(template_bytes).hexdigest()
        manifest['renderer_sha256']={name:hashlib.sha256((scripts/name).read_bytes()).hexdigest()
                                    for name in ('report_model.py','report_enrichment.py','enrich_report.py')}
        manifest['supplements']=[{'module':name,'observed_at':modules[name]['observed_at'],'coverage_status':modules[name].get('coverage_status','bounded')}
                                 for name in ('supplemental','recent_apps','manual_ui','codex_usage','exposure','ai_artifacts') if name in modules]
        report=build_report(modules,manifest,original.get('usage'),demo=bool(original['meta'].get('demo')))
        write_new(out/'manifest.json',manifest); write_new(out/'report.json',report)
        for name,data in modules.items():
            # Module names were allowlisted before any report output was created.
            write_new(out/(name+'.json'),data)
        write_new(out/'report.html',render_html(report,template_bytes.decode('utf-8')),False)
        write_new(out/'補查摘要.txt','原檢查時間：'+str(report['meta'].get('observed_at'))+'\n補查時間：'+str(report['meta'].get('supplemented_at','無新增資料'))+
                  '\n此報告保留原檢查來源；只加入有時間與來源的本機補查。沒有重掃全部來源或修改受檢設定。',False)
    except (OSError,ValueError,TypeError,KeyError,RecursionError):
        parser.error('Report/supplement invalid, unavailable, redirected, or output is not a new private location.')
    print('Updated report generated; original evidence and observation dates preserved.')

if __name__=='__main__': main()
