#!/usr/bin/env python3
"""Read-only macOS management, proxy, login and firewall exposure flags.

Never retains raw command output, proxy addresses, PAC URLs or account names.
"""
import argparse
import datetime as dt
import json
import os
from pathlib import Path
import platform
import re
import selectors
import subprocess
import sys
import time

sys.dont_write_bytecode = True
from audit_io import is_redirected, write_new

MAX_OUTPUT = 64 * 1024
TIMEOUT = 8
COMMANDS = {
    'enrollment': ['/usr/bin/profiles', 'status', '-type', 'enrollment'],
    'proxy': ['/usr/sbin/scutil', '--proxy'],
    'guest': ['/usr/bin/defaults', 'read', '/Library/Preferences/com.apple.loginwindow', 'GuestEnabled'],
    'autologin': ['/usr/bin/defaults', 'read', '/Library/Preferences/com.apple.loginwindow', 'autoLoginUser'],
    'stealth': ['/usr/libexec/ApplicationFirewall/socketfilterfw', '--getstealthmode'],
}
PROXY_FLAGS = ('HTTPEnable', 'HTTPSEnable', 'SOCKSEnable', 'FTPEnable',
               'RTSPEnable', 'GopherEnable', 'ProxyAutoConfigEnable',
               'ProxyAutoDiscoveryEnable')


def query(argv, timeout=TIMEOUT, limit=MAX_OUTPUT):
    """Bound even unexpected output; callers only receive ephemeral strings."""
    proc = None
    selector = selectors.DefaultSelector()
    chunks = {'stdout': [], 'stderr': []}
    size = 0
    try:
        proc = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE,
                                env={'PATH': '/usr/bin:/bin:/usr/sbin:/sbin',
                                     'LANG': 'C', 'LC_ALL': 'C'})
        for label, stream in (('stdout', proc.stdout), ('stderr', proc.stderr)):
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, selectors.EVENT_READ, label)
        deadline = time.monotonic() + timeout
        while selector.get_map():
            remain = deadline - time.monotonic()
            if remain <= 0:
                return {'status': 'unavailable', 'reason': 'timeout'}
            for key, _ in selector.select(min(remain, 0.1)):
                block = os.read(key.fd, min(8192, limit + 1 - size))
                if not block:
                    selector.unregister(key.fileobj)
                    continue
                size += len(block)
                if size > limit:
                    return {'status': 'unavailable', 'reason': 'output_limit'}
                chunks[key.data].append(block)
        proc.wait(timeout=max(0.01, deadline - time.monotonic()))
        return {'status': 'ok' if proc.returncode == 0 else 'error',
                'exit_code': proc.returncode,
                'text': b''.join(chunks['stdout']).decode('utf-8', 'replace'),
                'error_text': b''.join(chunks['stderr']).decode('utf-8', 'replace')}
    except subprocess.TimeoutExpired:
        return {'status': 'unavailable', 'reason': 'timeout'}
    except OSError:
        return {'status': 'unavailable', 'reason': 'command_unavailable'}
    finally:
        selector.close()
        if proc is not None:
            if proc.poll() is None:
                proc.kill()
            proc.wait()
            if proc.stdout: proc.stdout.close()
            if proc.stderr: proc.stderr.close()


def enrollment(result):
    out = {'status': 'unknown', 'mdm_enrolled': None, 'automated_enrollment': None}
    if result.get('status') != 'ok': return out
    text = result.get('text', '')
    for field, label in (('mdm_enrolled', 'MDM enrollment'),
                         ('automated_enrollment', 'Enrolled via DEP')):
        rows = re.findall(r'^\s*' + re.escape(label) + r':\s*(Yes|No)(?:\s*\([^\r\n]*\))?\s*$', text, re.M | re.I)
        values = {value.lower() == 'yes' for value in rows}
        if len(values) == 1: out[field] = values.pop()
    if all(out[k] is not None for k in ('mdm_enrolled', 'automated_enrollment')):
        out['status'] = 'observed'
    return out


def proxy_flags(result):
    out = {'status': 'unknown', 'flags': {}, 'enabled_flags': [], 'unreported_flags': list(PROXY_FLAGS)}
    if result.get('status') != 'ok': return out
    text = result.get('text', '')
    if not re.match(r'^\s*<dictionary>\s*\{', text) or not text.rstrip().endswith('}'):
        return out
    for flag in PROXY_FLAGS:
        matches = re.findall(r'^\s*' + re.escape(flag) + r'\s*:\s*([01])\s*$', text, re.M)
        if matches:
            values = sorted(set(int(x) for x in matches))
            out['flags'][flag] = values
            out['unreported_flags'].remove(flag)
            if 1 in values: out['enabled_flags'].append(flag)
    out['status'] = 'observed'
    return out


def preference_state(result, key, presence_only=False):
    """Absent key is distinct from explicit false, denied and malformed values."""
    out = {'status': 'unknown', 'state': 'unavailable'}
    if result.get('status') == 'ok':
        text = result.get('text', '').strip()
        if presence_only:
            # Do not return the value: it can be a local account name.
            if text and '\n' not in text and len(text) <= 256:
                return {'status': 'observed', 'state': 'value_present'}
            return {'status': 'unknown', 'state': 'unrecognized_value'}
        if text in ('0', '1'):
            return {'status': 'observed', 'state': 'enabled' if text == '1' else 'disabled'}
        return {'status': 'unknown', 'state': 'unrecognized_value'}
    error = result.get('error_text', '')
    # Match the requested key and standard missing-pair form; a generic
    # failure/permission error must never be relabelled as an absent setting.
    if result.get('status') == 'error' and re.search(
            r'The domain/default pair of \([^\r\n]*,\s*' + re.escape(key) +
            r'\) does not exist\s*$', error, re.M):
        return {'status': 'observed', 'state': 'not_explicitly_set'}
    return out


def stealth_mode(result):
    if result.get('status') != 'ok': return {'status': 'unknown', 'enabled': None}
    values = re.findall(r'^\s*(?:Firewall\s+)?Stealth mode (?:is\s+)?(enabled|disabled|on|off)\.?\s*$',
                        result.get('text', ''), re.I | re.M)
    values = {x.lower() in ('enabled', 'on') for x in values}
    return {'status': 'observed', 'enabled': values.pop()} if len(values) == 1 else {'status': 'unknown', 'enabled': None}


def check(identifier, category, title, status, summary, state, actions, limitations,
          severity='info', impact='', terms=None):
    return {'id': 'exposure.' + identifier, 'category': category, 'title': title,
            'status': status, 'severity': severity, 'summary': summary,
            'short_summary': summary, 'impact': impact, 'actions': actions,
            'evidence': [{'source': '本機唯讀狀態：' + identifier,
                          'detail': json.dumps(state, ensure_ascii=False)}],
            'limitations': limitations, 'terms': terms or {'enrollment':['mdm'],'proxy':['proxy'],'stealth':['firewall','stealth']}.get(identifier,[])}


def collect(runner=query, host=None):
    host = host or platform.system()
    base = {'schema_version': '3.0', 'module': 'exposure', 'platform': host,
            'observed_at': dt.datetime.now(dt.timezone.utc).isoformat(),
            'source': 'macOS built-in read-only flags; raw output not retained',
            'network_requests': False, 'settings_modified': False}
    if host != 'Darwin':
        base.update(status='unsupported', coverage_status='not_checked', checks=[],
                    limitations=['此補查模組目前只支援 macOS；沒有套用至 Windows 或其他平台。'])
        return base
    results = {name: runner(list(argv)) for name, argv in COMMANDS.items()}
    states = {'enrollment': enrollment(results['enrollment']),
              'proxy': proxy_flags(results['proxy']),
              'guest': preference_state(results['guest'], 'GuestEnabled'),
              'autologin': preference_state(results['autologin'], 'autoLoginUser', True),
              'stealth': stealth_mode(results['stealth'])}
    checks = []
    s = states['enrollment']; known = s['status'] == 'observed'; managed = s['mdm_enrolled'] is True
    summary = '已註冊裝置管理，請確認管理者與用途。' if managed else '未回報 MDM 註冊；其他描述檔尚未列出。' if known else '裝置管理註冊狀態未能完整確認。'
    checks.append(check('enrollment', 'system', '裝置管理', 'review' if known else 'unknown', summary, s,
                        ['若是公司設備，向管理者確認；個人設備若不認得管理來源，再人工核對。'],
                        ['僅查註冊旗標；未讀取管理伺服器、使用者識別或描述檔內容。',
                         '已註冊不代表惡意；未註冊也不能排除本機描述檔或其他管理程式。'],
                        'low' if managed else 'info', '裝置管理可套用設定，來源應符合你的預期。', ['permissions']))
    s = states['proxy']; known = s['status'] == 'observed'; active = bool(s['enabled_flags'])
    summary = '有啟用的系統代理旗標，請確認用途。' if active else '系統快照未回報已啟用的代理旗標。' if known else '系統代理旗標未能讀取。'
    checks.append(check('proxy', 'network', '網路代理', 'review' if known else 'unknown', summary, s,
                        ['若使用 VPN、公司網路或流量工具，核對代理設定是否符合用途。'],
                        ['只保留啟用旗標；未儲存代理位址、PAC URL、例外清單或網路名稱。',
                         '只代表系統當下快照；未回報的旗標不是明確關閉，程式自帶代理與其他網路服務未完整涵蓋。',
                         '代理啟用不是外洩證據；未做連線或封包檢測。'],
                        'low' if active else 'info', '代理可改變連線路徑，需核對是否為預期設定。'))
    s = states['guest']; enabled = s['state'] == 'enabled'; disabled = s['state'] == 'disabled'
    summary = '訪客登入旗標已啟用，請確認是否需要。' if enabled else '訪客登入旗標明確關閉。' if disabled else '未取得明確訪客登入狀態，需看系統設定。'
    checks.append(check('guest', 'system', '訪客登入', 'review' if enabled else 'pass' if disabled else 'unknown', summary, s,
                        ['在使用者與群組確認訪客用途；有需求才保留，不自動修改。'],
                        ['只查 GuestEnabled，沒有登入測試或列出使用者帳號。',
                         '缺少明確偏好值不能當作關閉；管理原則、FileVault 與系統版本可能影響實際行為。'],
                        'low' if enabled else 'info', '訪客功能會影響可登入裝置的方式，需符合實際使用情境。'))
    s = states['autologin']; configured = s['state'] == 'value_present'
    summary = '存在自動登入設定值，需核對是否仍生效。' if configured else '未見明確自動登入設定值；實際狀態待確認。' if s['state'] == 'not_explicitly_set' else '自動登入設定未能確認。'
    checks.append(check('autologin', 'system', '開機自動登入', 'review' if configured else 'unknown', summary, s,
                        ['在使用者與群組核對自動登入；共用或可能遺失的電腦應特別留意。'],
                        ['只保留設定值是否存在，不保留帳號名稱，也未讀取登入憑證。',
                         '偏好值可能過時或受管理原則影響；FileVault 啟用時會禁止自動登入。未見值不保證已關閉。'],
                        'medium' if configured else 'info', '若實際自動登入生效，取得裝置的人可能直接進入使用者環境。'))
    s = states['stealth']; known = s['status'] == 'observed'; enabled = s['enabled'] is True
    summary = '防火牆隱藏模式已啟用。' if enabled else '隱藏模式關閉，可依公共網路需求評估。' if known else '防火牆隱藏模式未能確認。'
    checks.append(check('stealth', 'network', '防火牆隱藏模式', 'pass' if enabled else 'review' if known else 'unknown', summary, s,
                        ['常用公共網路時，可在防火牆選項評估開啟隱藏模式。'],
                        ['只讀選項旗標；未測試外部可達性，也未變更防火牆。',
                         '這只減少回應部分探索請求，不代表隱身、匿名或阻擋所有入侵。'],
                        'low' if known and not enabled else 'info', '隱藏模式可減少對部分探測請求的回應。', ['firewall']))
    unknown = sum(item['status'] == 'unknown' for item in checks)
    base.update(coverage_status='partial' if unknown or states['proxy']['unreported_flags'] else 'bounded',
                checks=checks, summary={'checks': len(checks), 'unknown_checks': unknown},
                coverage=[{'source': name, 'status': state['status'],
                           'command_status': results[name].get('status', 'unavailable'),
                           'error_reason': results[name].get('reason')}
                          for name, state in states.items()],
                limitations=['只查 5 組本機狀態；不等同完整網路、帳號或裝置管理鑑識。',
                             '沒有提權、讀取密碼、測試登入、變更設定或建立監控。'])
    return base


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--home', type=Path, help='Accepted for runner compatibility; never scanned.')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    target = args.output.expanduser().absolute()
    if is_redirected(target) or not target.parent.is_dir():
        parser.error('Use an existing private output directory without redirection.')
    if os.name != 'nt' and target.parent.stat().st_mode & 0o077:
        parser.error('Output directory must be private (0700).')
    if target.exists(): parser.error('Use a new output file.')
    try:
        write_new(target, collect())
    except (OSError, ValueError):
        parser.error('Could not create a new private exposure report.')
    print('Read-only exposure flags collected; no raw identifying output retained.')


if __name__ == '__main__': main()
