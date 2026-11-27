#!/usr/bin/env python3
"""Run bounded read-only modules and write a new private report directory."""
import argparse
from concurrent.futures import ThreadPoolExecutor
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import platform
import signal
import subprocess
import sys
sys.dont_write_bytecode = True
from audit_io import private_directory, WindowsJob, is_redirected
from report_model import build_report, render_html
from usage_metrics import load_usage, UsageValidationError


def write_new(path, value, is_json=True):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'w', encoding='utf-8') as handle:
        handle.write(json.dumps(value, ensure_ascii=False, indent=2) if is_json else value)
        handle.write('\n')


def execute_module(job):
    name, argv, report_path = job
    bound = None
    try:
        worker = Path(__file__).resolve().parent / 'module_worker.py'
        wrapped = [argv[0], '-E', '-S', '-B', str(worker), Path(argv[2]).name] + argv[3:]
        proc = subprocess.Popen(wrapped, stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                text=True, start_new_session=os.name != 'nt')
        if os.name == 'nt':
            try:
                bound = WindowsJob(proc)
            except OSError:
                proc.kill(); proc.wait(timeout=5)
                return {'module': name, 'status': 'process_boundary_unavailable', 'report': report_path.name}
    except OSError as error:
        return {'module': name, 'status': 'failed_to_start', 'error_type': type(error).__name__, 'report': report_path.name}
    try:
        proc.communicate(input='go\n', timeout=240)
        result = {'module': name, 'status': 'completed' if proc.returncode == 0 else 'failed',
                  'exit_code': proc.returncode, 'report': report_path.name}
    except subprocess.TimeoutExpired:
        if bound:
            bound.close()
        else:
            try: os.killpg(proc.pid, signal.SIGTERM)
            except ProcessLookupError: pass
        try:
            proc.communicate(timeout=3)
        except subprocess.TimeoutExpired:
            if os.name == 'nt': proc.kill()
            else:
                try: os.killpg(proc.pid, signal.SIGKILL)
                except ProcessLookupError: pass
            proc.communicate()
        result = {'module': name, 'status': 'timeout', 'report': report_path.name}
    finally:
        if bound: bound.close()
    # Do not publish arbitrary stderr, command-line parameters, or inspected text.
    if result['status'] == 'completed':
        try:
            with report_path.open(encoding='utf-8') as handle:
                data = json.load(handle)
            if not isinstance(data, dict):
                result['status'] = 'invalid_report'
            elif data.get('status') == 'unsupported':
                result['status'] = 'unsupported'
            else:
                result['coverage_status'] = data.get('coverage_status', 'bounded_scope; inspect reported exclusions')
        except (OSError, ValueError):
            result['status'] = 'invalid_report'
    return result


def make_summary(directory, results):
    lines = ['電腦資安健檢：收集摘要',
             '以下為資料收集結果，不是安全認證或惡意程式判決。請連同 SKILL.md 的判讀流程閱讀。', '']
    for result in results:
        name = result['module']
        lines.append(name + ': collector=' + result['status'] + '; coverage=' + result.get('coverage_status', 'unknown'))
        if result['status'] != 'completed':
            lines.append('  此模組未完成，不能把缺少資料解讀為沒有問題。')
            continue
        data = json.loads((directory / result['report']).read_text(encoding='utf-8'))
        if name == 'skills':
            summary = data.get('summary', {})
            lines.append('  技能包 %s；文字檔 %s；待複核靜態線索 %s。不是已確認漏洞數。' %
                         (summary.get('skill_packages', '?'), summary.get('files_scanned', '?'), summary.get('review_signals', '?')))
            lines.append('  使用頻率、來源與涵蓋期間請見圖形報告；不自動產生刪除名單。')
        elif name == 'browser':
            profiles = data.get('profiles', [])
            discovered = sum(c.get('profile_count', 0) for c in data.get('coverage', []))
            successful = [p for p in profiles if p.get('cookies', {}).get('status') == 'read_only_ok']
            lines.append('  發現profile-like資料夾 %s；回報 %s；Cookie資料庫成功讀取 %s。未讀Cookie內容。' %
                         (discovered, len(profiles), len(successful)))
            lines.append('  僅成功讀取範圍的Cookie總列數 %s；其餘未檢查，不能當成零。' %
                         sum(p['cookies'].get('total', 0) for p in successful))
            if data.get('errors') or discovered != len(profiles):
                lines.append('  偵測到讀取錯誤或未回報profile，覆蓋不完整。')
            lines.append('  擴充安裝條目 %s；可能包含多profile與殘留，啟用狀態須另外核對。' %
                         sum(len(p.get('extensions', [])) for p in profiles))
        elif name == 'system' and 'checks' not in data:
            system = data.get('system', {})
            for key in ['macos', 'filevault', 'firewall', 'gatekeeper', 'sip']:
                obj = system.get(key, {})
                lines.append('  ' + key + ': ' + str(obj.get('result', obj.get('status', 'unknown'))).replace('\n', ' / '))
            tm = system.get('time_machine_destinations', {})
            lines.append('  Time Machine未設定目的地: ' + str(tm.get('no_destinations_configured', 'unknown')))
            lines.append('  啟動plist數: ' + str(len(data.get('startup', {}).get('items', []))))
            lines.append('  歷史異常傳輸／外洩、完整登入失敗紀錄及全磁碟惡意程式掃描未涵蓋。')
        lines.append('  原始證據與略過範圍：' + result['report'])
    lines += ['', '另需人工確認：高權限App、帳號MFA／陌生裝置、OAuth授權、備份還原。',
              '未改動設定、未刪除來源、未建立持續監控。作業系統可能正常更新查詢日誌／快取。',
              '這個報告目錄是私人資料，分享skill時不要包含。']
    return '\n'.join(lines)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output-dir', type=Path, required=True)
    parser.add_argument('--home', type=Path, default=Path.home())
    parser.add_argument('--days', type=int, choices=range(1, 91), default=14, metavar='1..90')
    parser.add_argument('--network-seconds', type=int, choices=range(0, 11), default=3, metavar='0..10')
    parser.add_argument('--check-updates', action='store_true')
    parser.add_argument('--include-plugin-cache', action='store_true')
    parser.add_argument('--skill-root', type=Path, action='append')
    parser.add_argument('--script-root', type=Path, action='append', help='Explicitly authorized standalone script directories')
    parser.add_argument('--modules', help='Subset: system,browser,skills,scripts,connectivity,background,supplemental,recent_apps,exposure (last five Mac only)')
    parser.add_argument('--usage-file', type=Path, help='Explicitly supplied aggregate counts; never raw chats/history')
    args = parser.parse_args()
    host = platform.system()
    if host not in ('Darwin','Windows'):
        parser.error('Only macOS and Windows are supported. No other OS is treated as covered.')
    default = 'system,browser,skills,connectivity,scripts,background,supplemental,recent_apps,exposure' if host=='Darwin' else 'system,browser,skills,scripts'
    selected = (args.modules or default).split(',')
    allowed = ('system','browser','skills','connectivity','scripts','background','supplemental','recent_apps','exposure') if host=='Darwin' else ('system','browser','skills','scripts')
    if not selected or len(set(selected)) != len(selected) or any(x not in allowed for x in selected):
        parser.error('Choose each supported module at most once; Windows connectivity is part of system.')
    try:
        usage = load_usage(args.usage_file)
    except (UsageValidationError, OSError) as error:
        parser.error(str(error) if isinstance(error,UsageValidationError) else 'Usage source could not be read.')
    scripts = Path(__file__).resolve().parent
    # Preserve symlink spelling: individual collectors must be able to reject it.
    home = args.home.expanduser().absolute()
    out = args.output_dir.expanduser().absolute()
    if out.exists() or out.is_symlink():
        parser.error('Choose a new output directory; existing reports are not overwritten.')
    roots = args.skill_root or [home / '.codex/skills', home / '.agents/skills']
    roots = [r.expanduser().absolute() for r in roots]
    if args.include_plugin_cache:
        roots.append(home / '.codex/plugins/cache')
    # Keep the report outside code being inspected and outside this distributed skill.
    script_roots = [r.expanduser().absolute() for r in (args.script_root or [home/'Scripts',home/'.local/bin',home/'Downloads'])]
    for root in roots + script_roots + [scripts.parent]:
        try:
            out.resolve().relative_to(root.resolve())
        except ValueError:
            continue
        parser.error('The report directory must be outside scanned skills and this skill bundle.')
    try:
        storage_security = private_directory(out)
    except (OSError,ValueError):
        parser.error('Cannot create a new private report directory. Use a local path without links/reparse points; Windows needs an ACL-capable fixed disk.')
    jobs = []
    for name in selected:
        report = out / (name + '.json')
        collector = 'windows' if host=='Windows' and name=='system' else name
        argv = [sys.executable, '-B', str(scripts / ('inspect_' + collector + '.py')), '--output', str(report)]
        if name in ('system', 'browser','connectivity','background','supplemental','recent_apps','exposure'):
            argv += ['--home', str(home)]
        if name == 'system':
            argv += ['--days', str(args.days), '--network-seconds', str(args.network_seconds)]
            if args.check_updates:
                argv.append('--check-updates')
        elif name == 'skills':
            for root in roots:
                argv += ['--root', str(root)]
            argv += ['--exclude', str(scripts.parent)]
        elif name == 'scripts':
            for root in script_roots:
                argv += ['--root',str(root)]
        jobs.append((name, argv, report))
    with ThreadPoolExecutor(max_workers=3) as executor:
        results = list(executor.map(execute_module, jobs))
    manifest = {
        'version': '3.0.0', 'platform':host, 'generated_at': dt.datetime.now().astimezone().isoformat(),
        'report_storage': storage_security,
        'modules': results, 'read_only_scope': True,
        'script_sha256': {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(scripts.glob('*.py'))},
        'manual_checks': 'System Settings privacy grants; account security and restore tests need separate authorized review.',
        'limits': 'A completed collector is not a malware-free or no-exfiltration conclusion.'}
    write_new(out / 'manifest.json', manifest)
    write_new(out / '收集摘要.txt', make_summary(out, results), is_json=False)
    modules = {}
    for result in results:
        if result['status']=='completed':
            modules[result['module']] = json.loads((out / result['report']).read_text(encoding='utf-8'))
    report = build_report(modules, manifest, usage=usage)
    write_new(out / 'report.json', report)
    template = (scripts.parent / 'assets/report.html').read_text(encoding='utf-8')
    write_new(out / 'report.html', render_html(report,template), is_json=False)
    print(json.dumps({'report_directory': str(out), 'modules': results}, ensure_ascii=False))
    return 0 if all(r['status'] == 'completed' for r in results) else 1


if __name__ == '__main__':
    sys.exit(main())
