#!/usr/bin/env python3
"""Bounded, local, read-only Windows audit. Python 3.9+; no extra packages.

Only whitelisted status properties leave the collection routines. This module
does not elevate, search Wi-Fi profiles, start network discovery, or scan files
with antivirus. Windows edition/permissions may leave checks unavailable.
"""
import argparse
from concurrent.futures import ThreadPoolExecutor
import ctypes as C
import datetime as dt
import json
import os
from pathlib import Path
import platform
import re
import stat
import subprocess
import sys

DWORD = C.c_uint32
WORD = C.c_uint16
BOOL = C.c_int32
BYTE = C.c_uint8
HANDLE = C.c_void_p
MAX_ROWS = 1500

# Fixed code, never assembled from file names, registry contents or user input.
# PowerShell does not load a user profile or change an execution policy.
QUERIES = {
    'wifi': r"""
$profiles=@([Windows.Networking.Connectivity.NetworkInformation,Windows.Networking.Connectivity,ContentType=WindowsRuntime]::GetConnectionProfiles())
$selected=@($profiles | Where-Object {$_.IsWlanConnectionProfile -and ([int]$_.GetNetworkConnectivityLevel() -gt 0)} | Select-Object -First 17)
$index=0
$items=@($selected | Select-Object -First 16 | ForEach-Object {
 $index++
 $security=$_.NetworkSecuritySettings
 [pscustomobject]@{interface=$index;state='connected';status='ok';authentication=[string]$security.NetworkAuthenticationType;cipher=[string]$security.NetworkEncryptionType;connectivity=[string]$_.GetNetworkConnectivityLevel()}
})
[pscustomobject]@{items=$items;limit_reached=($selected.Count -gt 16)}
""",
    'os': r"""
$o=Get-CimInstance -ClassName Win32_OperatingSystem -Property Caption,Version,BuildNumber,OSArchitecture
[pscustomobject]@{caption=$o.Caption;version=$o.Version;build=$o.BuildNumber;architecture=$o.OSArchitecture}
""",
    'defender': r"""
$d=Get-MpComputerStatus
[pscustomobject]@{antivirus=$d.AntivirusEnabled;realtime=$d.RealTimeProtectionEnabled;behavior=$d.BehaviorMonitorEnabled;signature_age_days=$d.AntivirusSignatureAge;quick_scan_age_days=$d.QuickScanAge;running_mode=[string]$d.AMRunningMode}
""",
    'firewall': r"""
@(Get-NetFirewallProfile -PolicyStore ActiveStore | Select-Object -First 3 | ForEach-Object {
 [pscustomobject]@{name=[string]$_.Name;enabled=([string]$_.Enabled);inbound=[string]$_.DefaultInboundAction;outbound=[string]$_.DefaultOutboundAction}
})
""",
    'bitlocker': r"""
# Select status immediately: never serialize the key-protector property.
@(Get-BitLockerVolume | Select-Object -First 32 | ForEach-Object {
 [pscustomobject]@{mount=[string]$_.MountPoint;volume_type=[string]$_.VolumeType;protection=[string]$_.ProtectionStatus;encryption=[string]$_.VolumeStatus;percent=$_.EncryptionPercentage}
})
""",
    'secureboot': 'Confirm-SecureBootUEFI',
    'updates': r"""
@(Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 20 | ForEach-Object {
 [pscustomobject]@{id=$_.HotFixID;installed_on=$(if ($_.InstalledOn) {$_.InstalledOn.ToString('yyyy-MM-dd')} else {$null})}
})
""",
    'startup': r"""
$rows=New-Object System.Collections.Generic.List[object]
$errors=0
$limited=$false
$roots=@('HKCU:\Software\Microsoft\Windows\CurrentVersion\Run','HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce','HKLM:\Software\Microsoft\Windows\CurrentVersion\Run','HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce','HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run')
foreach ($root in $roots) {
 try {
  if (Test-Path -LiteralPath $root) {
   $key=Get-Item -LiteralPath $root
   $names=@($key.GetValueNames() | Select-Object -First 101)
   if ($names.Count -gt 100) {$limited=$true}
   foreach ($n in ($names | Select-Object -First 100)) {
    if ($rows.Count -ge 500) {$limited=$true;break}
    $raw=[string]$key.GetValue($n)
    $exe=$null
    if ($raw -match '^\s*"([^"\r\n]+\.(?:exe|com))"') {$exe=$Matches[1]}
    elseif ($raw -match '^\s*([^\s"\r\n]+\.(?:exe|com))(?:\s|$)') {$exe=$Matches[1]}
    $rows.Add([pscustomobject]@{name=(Clip $n);source=$root;executable=(Clip $exe);arguments_collected=$false})
   }
  }
 } catch {$errors++}
}
[pscustomobject]@{items=@($rows.ToArray());errors=$errors;limit_reached=$limited}
""",
    'tasks': r"""
$tasks=@(Get-ScheduledTask | Where-Object {$_.TaskPath -notlike '\Microsoft\*'} | Select-Object -First 301)
$items=@($tasks | Select-Object -First 300 | ForEach-Object {
 $executables=@($_.Actions | Select-Object -First 5 | ForEach-Object {
  $value=[string]$_.Execute
  if ($value -match '^[^\r\n]+\.(?:exe|com)$') {Clip $value}
 })
 [pscustomobject]@{name=(Clip $_.TaskName);state=[string]$_.State;executables=$executables;source='ScheduledTask';arguments_collected=$false}
})
[pscustomobject]@{items=$items;limit_reached=($tasks.Count -gt 300)}
""",
    'services': r"""
$services=@(Get-CimInstance -ClassName Win32_Service -Property Name,State,StartMode,PathName,ProcessId | Select-Object -First 1001)
$items=@($services | Select-Object -First 1000 | ForEach-Object {
 $raw=[string]$_.PathName
 $exe=$null
 if ($raw -match '^\s*"([^"\r\n]+\.(?:exe|com))"') {$exe=$Matches[1]}
 elseif ($raw -match '^\s*([^\s"\r\n]+\.(?:exe|com))(?:\s|$)') {$exe=$Matches[1]}
 [pscustomobject]@{name=(Clip $_.Name);state=[string]$_.State;start_mode=[string]$_.StartMode;executable=(Clip $exe);pid=$_.ProcessId;source='Win32_Service snapshot';arguments_collected=$false}
})
[pscustomobject]@{items=$items;limit_reached=($services.Count -gt 1000)}
""",
    'connections': r"""
$all=@(Get-NetTCPConnection | Select-Object -First 4001)
$items=@($all | Select-Object -First 4000)
$listening=@($items | Where-Object {$_.State -eq 'Listen'} | Group-Object OwningProcess | ForEach-Object {
 $p=Get-Process -Id ([int]$_.Name) -ErrorAction SilentlyContinue
 $wide=@($_.Group | Where-Object {$_.LocalAddress -eq '0.0.0.0' -or $_.LocalAddress -eq '::'}).Count
 $loop=@($_.Group | Where-Object {$_.LocalAddress -eq '127.0.0.1' -or $_.LocalAddress -eq '::1'}).Count
 [pscustomobject]@{process=$p.ProcessName;pid=[int]$_.Name;all_interfaces=$wide;loopback=$loop;other_local=$_.Count-$wide-$loop;ports=@($_.Group.LocalPort | Sort-Object -Unique | Select-Object -First 100)}
})
[pscustomobject]@{listeners=$listening;established_count=@($items | Where-Object {$_.State -eq 'Established'}).Count;limit_reached=($all.Count -gt 4000)}
""",
    'failed_logins': r"""
try {
 $events=@(Get-WinEvent -FilterHashtable @{LogName='Security';Id=4625;StartTime=(Get-Date).AddDays(-7)} -MaxEvents 1001 -ErrorAction Stop)
 [pscustomobject]@{count=[Math]::Min($events.Count,1000);limit_reached=($events.Count -gt 1000);days=7}
} catch {
 if ($_.FullyQualifiedErrorId -like 'NoMatchingEventsFound*') {
  [pscustomobject]@{count=0;limit_reached=$false;days=7}
 } else {throw}
}
""",
    'installed_apps': r"""
$rows=New-Object System.Collections.Generic.List[object]
$errors=0
$limited=$false
$roots=@('HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall','HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall','HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall')
foreach ($root in $roots) {
 try {
  if (Test-Path -LiteralPath $root) {
   $keys=@(Get-ChildItem -LiteralPath $root | Select-Object -First 1501)
   if ($keys.Count -gt 1500) {$limited=$true}
   foreach ($key in ($keys | Select-Object -First 1500)) {
    if ($rows.Count -ge 1500) {$limited=$true;break}
    $name=$key.GetValue('DisplayName')
    if ($name) {$rows.Add([pscustomobject]@{name=(Clip $name);version=(Clip ($key.GetValue('DisplayVersion')));publisher=(Clip ($key.GetValue('Publisher')));source=$root;state='installed'})}
   }
  }
 } catch {$errors++}
}
[pscustomobject]@{items=@($rows.ToArray());errors=$errors;limit_reached=$limited}
""",
    'running_apps': r"""
$ps=@(Get-Process | Select-Object -First 3001)
$items=@($ps | Select-Object -First 3000 | Group-Object ProcessName | ForEach-Object {
 [pscustomobject]@{name=$_.Name;process_count=$_.Count;source='Get-Process snapshot';state='running'}
})
[pscustomobject]@{items=$items;limit_reached=($ps.Count -gt 3000)}
""",
}


def clean(value, limit=300):
    if value is None:
        return None
    return ''.join(c for c in str(value) if c >= ' ' and c not in '\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069')[:limit]


def rows(value):
    return value if isinstance(value, list) else ([] if value is None else [value])


def ps_executable():
    """Use the OS system directory, not PATH/current-directory command lookup."""
    kernel = C.WinDLL('kernel32', use_last_error=True)
    kernel.GetSystemDirectoryW.argtypes = [C.c_wchar_p, C.c_uint32]
    kernel.GetSystemDirectoryW.restype = C.c_uint32
    buf = C.create_unicode_buffer(32768)
    length = kernel.GetSystemDirectoryW(buf, len(buf))
    if not length or length >= len(buf):
        raise OSError('system_directory_unavailable')
    exe = Path(buf.value) / 'WindowsPowerShell/v1.0/powershell.exe'
    if not exe.is_file():
        raise OSError('powershell_unavailable')
    return str(exe)


def run_query(name, executable=None):
    script = """$ErrorActionPreference='Stop'; $WarningPreference='SilentlyContinue'; $ProgressPreference='SilentlyContinue';
[Console]::OutputEncoding=New-Object System.Text.UTF8Encoding($false)
function Clip($x) { if ($null -eq $x) { return $null }; $s=[string]$x; if ($s.Length -gt 300) { return $s.Substring(0,300) }; return $s }
try { $data=& { SCRIPT }; [pscustomobject]@{ok=$true;data=$data} | ConvertTo-Json -Depth 7 -Compress }
catch { [pscustomobject]@{ok=$false;error_category=[string]$_.CategoryInfo.Category} | ConvertTo-Json -Compress }
""".replace('SCRIPT', QUERIES[name])
    try:
        proc = subprocess.run([executable or ps_executable(), '-NoLogo', '-NoProfile', '-NonInteractive',
                               '-Command', script], capture_output=True, timeout=25,
                              creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0))
    except subprocess.TimeoutExpired:
        return {'ok': False, 'reason': 'timeout'}
    except (OSError, AttributeError):
        return {'ok': False, 'reason': 'powershell_unavailable'}
    # Error streams can contain names, parameters and arbitrary inspected text.
    # Never save them. Only accept bounded JSON produced by the fixed wrapper.
    if proc.returncode != 0 or len(proc.stdout) > 2 * 1024 * 1024:
        return {'ok': False, 'reason': 'command_failed_or_output_limit'}
    try:
        result = json.loads(proc.stdout.decode('utf-8-sig'))
        if not isinstance(result, dict) or not isinstance(result.get('ok'), bool):
            raise ValueError()
        if not result['ok']:
            return {'ok': False, 'reason': clean(result.get('error_category', 'unavailable'), 60)}
        return {'ok': True, 'data': result.get('data')}
    except (ValueError, UnicodeError):
        return {'ok': False, 'reason': 'invalid_output'}


def wifi_from_query(result):
    """Keep only connection security enums, never names/identifiers/profile contents."""
    if not result.get('ok') or not isinstance(result.get('data'), dict):
        return {'ok': False, 'reason': result.get('reason', 'network_security_settings_unavailable')}
    data = result['data']
    items = []
    for item in rows(data.get('items'))[:16]:
        if not isinstance(item, dict):
            continue
        items.append({k: clean(item.get(k), 80) for k in ('state', 'status', 'authentication', 'cipher', 'connectivity')})
        items[-1]['interface'] = len(items)
    return {'ok': True, 'data': items, 'limit_reached': bool(data.get('limit_reached'))}


class SYSTEMTIME(C.Structure):
    _fields_ = [(x, WORD) for x in ('year', 'month', 'weekday', 'day', 'hour', 'minute', 'second', 'millisecond')]


class BTSearch(C.Structure):
    _fields_ = [('size', DWORD), ('authenticated', BOOL), ('remembered', BOOL), ('unknown', BOOL),
                ('connected', BOOL), ('inquiry', BOOL), ('timeout', BYTE), ('radio', HANDLE)]


class BTDevice(C.Structure):
    _fields_ = [('size', DWORD), ('address', C.c_uint64), ('device_class', DWORD),
                ('connected', BOOL), ('remembered', BOOL), ('authenticated', BOOL),
                ('last_seen', SYSTEMTIME), ('last_used', SYSTEMTIME), ('name', WORD * 248)]


class BTRadioParams(C.Structure):
    _fields_ = [('size', DWORD)]


def bluetooth_native():
    """Enumerate cached Classic Bluetooth metadata; inquiry is explicitly OFF."""
    dll = None
    find, radiofind, radio = None, None, HANDLE()
    try:
        dll = C.WinDLL('bthprops.cpl', use_last_error=True)
        dll.BluetoothFindFirstDevice.argtypes = [C.POINTER(BTSearch), C.POINTER(BTDevice)]
        dll.BluetoothFindFirstDevice.restype = HANDLE
        dll.BluetoothFindNextDevice.argtypes = [HANDLE, C.POINTER(BTDevice)]
        dll.BluetoothFindNextDevice.restype = BOOL
        dll.BluetoothFindDeviceClose.argtypes = [HANDLE]
        dll.BluetoothFindFirstRadio.argtypes = [C.POINTER(BTRadioParams), C.POINTER(HANDLE)]
        dll.BluetoothFindFirstRadio.restype = HANDLE
        dll.BluetoothFindRadioClose.argtypes = [HANDLE]
        dll.BluetoothIsDiscoverable.argtypes = [HANDLE]
        dll.BluetoothIsDiscoverable.restype = BOOL
        dll.BluetoothIsConnectable.argtypes = [HANDLE]
        dll.BluetoothIsConnectable.restype = BOOL
        p = BTRadioParams(C.sizeof(BTRadioParams))
        C.set_last_error(0)
        radiofind = dll.BluetoothFindFirstRadio(C.byref(p), C.byref(radio))
        radio_state = {'radio_detected': bool(radiofind)}
        if radiofind:
            radio_state.update(discoverable=bool(dll.BluetoothIsDiscoverable(radio)),
                               connectable=bool(dll.BluetoothIsConnectable(radio)))
        else:
            radio_state['enumeration_error'] = C.get_last_error()
        params = BTSearch(C.sizeof(BTSearch), 1, 1, 0, 1, 0, 0, None)
        device = BTDevice()
        device.size = C.sizeof(BTDevice)
        C.set_last_error(0)
        find = dll.BluetoothFindFirstDevice(C.byref(params), C.byref(device))
        if not find:
            error = C.get_last_error()
            if error != 259:  # ERROR_NO_MORE_ITEMS is a completed empty enumeration.
                return {'ok': False, 'reason': 'bluetooth_device_query_unavailable', 'code': error,
                        'radio': radio_state}
        result = []
        exhausted = not bool(find)
        while find and len(result) < 100:
            rawname = bytes(device.name).decode('utf-16-le', errors='replace').split('\0', 1)[0]
            result.append({'name': clean(rawname) or '未命名裝置', 'type': 'Bluetooth Classic',
                           'state': 'connected' if device.connected else 'remembered',
                           'paired': bool(device.authenticated)})
            device = BTDevice()
            device.size = C.sizeof(BTDevice)
            C.set_last_error(0)
            if not dll.BluetoothFindNextDevice(find, C.byref(device)):
                exhausted = C.get_last_error() == 259
                break
        return {'ok': True, 'data': result, 'radio': radio_state, 'limit_reached': not exhausted,
                'coverage': 'Classic Bluetooth only; BLE not included; first radio status only'}
    except (OSError, AttributeError, ValueError):
        return {'ok': False, 'reason': 'native_bluetooth_unavailable'}
    finally:
        if dll and find:
            dll.BluetoothFindDeviceClose(find)
        if dll and radiofind:
            dll.BluetoothFindRadioClose(radiofind)
        if radio.value:
            kernel = C.WinDLL('kernel32', use_last_error=True)
            kernel.CloseHandle.argtypes = [HANDLE]
            kernel.CloseHandle(radio)


def linked_path(path):
    """Reject any symlink/junction/reparse ancestor before metadata enumeration."""
    try:
        for part in [path] + list(path.parents):
            st = part.lstat()
            if stat.S_ISLNK(st.st_mode) or getattr(st, 'st_file_attributes', 0) & 0x400:
                return True
        return False
    except OSError:
        return True


def downloads_metadata(home, days):
    folder = home / 'Downloads'
    if linked_path(folder):
        return {'ok': False, 'reason': 'missing_inaccessible_or_reparse_path'}
    findings, count, error_count, capped = [], 0, 0, False
    cutoff = dt.datetime.now().timestamp() - days * 86400
    try:
        with os.scandir(folder) as it:
            for entry in it:
                count += 1
                if count > 2000:
                    capped = True
                    break
                try:
                    st = entry.stat(follow_symlinks=False)
                    if not stat.S_ISREG(st.st_mode) or getattr(st, 'st_file_attributes', 0) & 0x400:
                        continue
                    if st.st_mtime < cutoff:
                        continue
                    signals = []
                    suffix = Path(entry.name).suffix.lower()
                    if suffix in ('.exe', '.msi', '.scr', '.com', '.bat', '.cmd', '.ps1', '.vbs', '.js', '.lnk', '.iso'):
                        signals.append('executable_or_installer')
                    if re.search(r'\.(pdf|docx?|xlsx?|jpg|png)\.(exe|scr|com|bat|cmd|vbs|js|lnk)$', entry.name, re.I):
                        signals.append('document_double_extension')
                    if any(x in entry.name for x in '\u202a\u202b\u202d\u202e\u2066\u2067\u2068'):
                        signals.append('direction_control_character')
                    if signals and len(findings) < 200:
                        findings.append({'name': clean(entry.name), 'bytes': st.st_size, 'signals': signals})
                    elif signals:
                        capped = True
                except OSError:
                    error_count += 1
        return {'ok': True, 'items': findings, 'entries_observed': min(count, 2000), 'limit_reached': capped,
                'errors': error_count, 'days': days,
                'scope': 'Only default home/Downloads top level; no contents, archives, signatures or cloud recall'}
    except OSError:
        return {'ok': False, 'reason': 'enumeration_unavailable'}


def check(key, category, title, status, severity, summary, source, evidence, actions=None,
          impact='', limitations=None, terms=None):
    return {'id': 'windows-' + key, 'category': category, 'title': title, 'status': status,
            'severity': severity, 'summary': summary, 'impact': impact,
            'actions': actions or [], 'evidence': [{'source': source, 'detail': evidence}],
            'limitations': limitations or [], 'terms': terms or []}


def build_report(results, wifi, bluetooth, files, observed_at=None):
    """Pure interpretation function, used by fixture tests without Windows access."""
    checks, inventories = [], {'apps': [], 'devices': [], 'startup': [], 'downloads': [], 'background': []}

    def add(key, category, title, status, severity, summary, source, evidence, **kw):
        checks.append(check(key, category, title, status, severity, summary, source, evidence, **kw))

    def unavailable(key, category, title, source):
        result = results.get(key, {})
        add(key, category, title, 'unknown', 'info', '此項未能取得可靠資料，不能當成已啟用或沒有問題。', source,
            '收集狀態：' + str(result.get('reason', 'unavailable')),
            actions=['在 Windows 設定或 Windows 安全性中人工確認；不需為本健檢提升權限。'])

    result = results.get('os', {})
    if result.get('ok') and isinstance(result.get('data'), dict):
        o = result['data']
        detail = ' / '.join(str(clean(o.get(k)) or '未知') for k in ('caption', 'version', 'build', 'architecture'))
        add('os', 'system', 'Windows 版本', 'review', 'info', detail, 'Win32_OperatingSystem selected properties', detail,
            limitations=['版本已讀取；是否仍受支援、是否已安裝最新安全更新，須依官方生命週期與此裝置版本確認。'])
    else:
        unavailable('os', 'system', 'Windows 版本', 'Win32_OperatingSystem')

    result = results.get('defender', {})
    if result.get('ok') and isinstance(result.get('data'), dict):
        d = result['data']
        enabled = d.get('antivirus') is True and d.get('realtime') is True
        disabled = d.get('antivirus') is False or d.get('realtime') is False
        age = d.get('signature_age_days')
        stale = isinstance(age, (int, float)) and 7 < age < 65535
        status = 'review' if disabled else ('attention' if stale else ('pass' if enabled else 'unknown'))
        summary = 'Defender 防毒與即時保護已啟用。' if enabled else '需確認 Defender 狀態，以及是否由其他防毒產品接手。'
        if stale:
            summary += ' 病毒特徵資料超過 7 天未更新。'
        add('defender', 'system', '防毒與即時防護', status, 'medium' if disabled or stale else 'info', summary,
            'Get-MpComputerStatus selected properties', json.dumps(d, ensure_ascii=False),
            actions=['開啟 Windows 安全性 → 病毒與威脅防護，核對保護供應商和更新狀態。'],
            limitations=['未開始掃毒；保護已啟用不代表電腦沒有惡意程式。被動模式可能由其他防毒產品接手。'],
            terms=['defender'])
    else:
        unavailable('defender', 'system', '防毒與即時防護', 'Get-MpComputerStatus')

    result = results.get('firewall', {})
    fws = rows(result.get('data')) if result.get('ok') else []
    if fws and all(isinstance(x, dict) for x in fws):
        disabled = [x for x in fws if str(x.get('enabled')).lower() in ('false', '0')]
        all_on = (len(fws) == 3 and {str(x.get('name')).lower() for x in fws} == {'domain', 'public', 'private'}
                  and all(str(x.get('enabled')).lower() in ('true', '1') for x in fws))
        add('firewall', 'network', 'Windows 防火牆', 'attention' if disabled else ('pass' if all_on else 'unknown'),
            'high' if disabled else 'info', '有網路類型的防火牆未啟用。' if disabled else ('三種網路類型的防火牆均啟用。' if all_on else '未取得三種網路類型的完整啟用狀態。'),
            'Get-NetFirewallProfile -PolicyStore ActiveStore', json.dumps(fws, ensure_ascii=False),
            actions=['在 Windows 安全性 → 防火牆與網路保護確認目前網路；若由公司管理，請交由管理員確認。'],
            limitations=['未驗證每條允許規則或外網是否可連入。'], terms=['firewall'])
    else:
        unavailable('firewall', 'network', 'Windows 防火牆', 'Get-NetFirewallProfile')

    result = results.get('bitlocker', {})
    vols = rows(result.get('data')) if result.get('ok') else []
    systemvols = [v for v in vols if isinstance(v, dict) and str(v.get('volume_type')).lower() in ('operatingsystem', '0')]
    if systemvols:
        on = all(str(v.get('protection')).lower() in ('on', '1') and str(v.get('encryption')).lower() in ('fullyencrypted', '1') for v in systemvols)
        add('bitlocker', 'system', '系統磁碟加密', 'pass' if on else 'attention', 'info' if on else 'high',
            '系統磁碟已完成加密且保護啟用。' if on else '系統磁碟尚未確認為完整加密且保護啟用。',
            'Get-BitLockerVolume selected status only', json.dumps(vols, ensure_ascii=False),
            actions=['在裝置加密或 BitLocker 設定核對狀態；啟用前先自行確認復原方式。'],
            impact='磁碟加密可降低電腦遺失後資料被直接讀取的風險。', limitations=['未讀取、顯示或驗證復原金鑰。'], terms=['bitlocker'])
    else:
        unavailable('bitlocker', 'system', '系統磁碟加密', 'Get-BitLockerVolume selected status only')

    result = results.get('secureboot', {})
    if result.get('ok') and isinstance(result.get('data'), bool):
        on = result['data']
        add('secureboot', 'system', '安全開機', 'pass' if on else 'review', 'info' if on else 'medium',
            '安全開機已啟用。' if on else '安全開機未啟用；請確認硬體與其他系統的相容需求。',
            'Confirm-SecureBootUEFI', str(on), terms=['secureboot'],
            actions=['需要調整時先查裝置廠商說明；本健檢不變更韌體設定。'])
    else:
        unavailable('secureboot', 'system', '安全開機', 'Confirm-SecureBootUEFI')

    result = results.get('updates', {})
    if result.get('ok'):
        updates = [x for x in rows(result.get('data')) if isinstance(x, dict)]
        add('updates', 'system', '系統更新紀錄', 'review', 'info', '已讀取本機更新紀錄；尚未查證最新可用更新。',
            'Get-HotFix (latest 20)', json.dumps(updates, ensure_ascii=False),
            actions=['開啟 設定 → Windows Update，檢查是否有待安裝更新。'],
            limitations=['Get-HotFix 並不涵蓋所有更新來源；沒有紀錄不等於未更新，有紀錄不代表已是最新。'])
    else:
        unavailable('updates', 'system', '系統更新紀錄', 'Get-HotFix')
    add('backup', 'backup', '備份與還原', 'not_checked', 'medium', '尚未確認備份是否完成及能否還原。',
        '未讀取備份目的地或雲端帳號', '未開始備份或還原測試。',
        actions=['在 Windows 備份、檔案歷程記錄或正在使用的備份工具，核對最近成功日期。', '找一份不敏感的檔案，另外安排還原測試。'],
        limitations=['OneDrive 同步、登入 Microsoft 帳號或安裝備份軟體，都不能單獨證明可還原備份存在。'], terms=['backup'])

    for key, title, source in [('startup', '開機自動啟動', 'Run / RunOnce registry'), ('tasks', '第三方排程工作', 'Get-ScheduledTask')]:
        result = results.get(key, {})
        if result.get('ok') and isinstance(result.get('data'), dict):
            d = result['data']
            items = [i for i in rows(d.get('items')) if isinstance(i, dict)]
            inventories['startup'].extend(items)
            incomplete = bool(d.get('errors') or d.get('limit_reached'))
            add(key, 'apps', title, 'review', 'info', '成功讀取的範圍列出 %s 項，請核對是否都是預期用途。%s' %
                (len(items), '有讀取錯誤或數量上限，清單不完整。' if incomplete else ''), source,
                'items=%s; unreadable=%s; limit_reached=%s' % (len(items), d.get('errors', 0), d.get('limit_reached', False)),
                actions=['對不認識的項目先核對發布者和用途，再決定是否停用。'],
                limitations=['未讀取完整啟動參數；不是所有開機持續執行機制。列出不代表惡意。'])
            checks[-1]['evidence'].extend({'source': source, 'detail': json.dumps(item, ensure_ascii=False)} for item in items)
        else:
            unavailable(key, 'apps', title, source)

    result = results.get('services', {})
    if result.get('ok') and isinstance(result.get('data'), dict):
        d = result['data']
        items = [i for i in rows(d.get('items')) if isinstance(i, dict)]
        inventories['background'] = items
        active = sum(str(i.get('state')).lower() == 'running' for i in items)
        incomplete = bool(d.get('errors') or d.get('limit_reached'))
        add('services', 'apps', 'Windows 背景服務', 'review', 'info',
            '成功讀取的範圍列出 %s 個服務，其中 %s 個正在執行。%s' %
            (len(items), active, '有讀取錯誤或數量上限，清單不完整。' if incomplete else ''),
            'Win32_Service selected properties',
            'items=%s; running=%s; errors=%s; limit_reached=%s' % (len(items), active, d.get('errors', 0), d.get('limit_reached', False)),
            actions=['核對不熟悉服務的用途、程式來源與是否由公司管理；不要只因名稱陌生就停止系統服務。'],
            limitations=['不讀取服務帳號、完整執行參數或私人日誌，不啟動、停止或修復服務。服務名稱與執行狀態不代表安全性或使用頻率。含空格且未加引號的執行路徑保留未知。'],
            terms=['service'])
        checks[-1]['evidence'].extend({'source': 'Win32_Service snapshot', 'detail': json.dumps(item, ensure_ascii=False)} for item in items)
    else:
        unavailable('services', 'apps', 'Windows 背景服務', 'Win32_Service selected properties')

    result = results.get('connections', {})
    if result.get('ok') and isinstance(result.get('data'), dict):
        d = result['data']
        listeners = [i for i in rows(d.get('listeners')) if isinstance(i, dict)]
        wide = sum(int(i.get('all_interfaces', 0)) for i in listeners)
        inventories['listeners'] = listeners
        add('connections', 'network', '程式連線與對外服務', 'review', 'medium' if wide else 'info',
            '成功讀取的範圍有 %s 個 TCP 監聽端點綁定所有網路介面。%s' %
            (wide, '達數量上限，清單不完整。' if d.get('limit_reached') else ''), 'Get-NetTCPConnection snapshot',
            'all_interfaces=%s; established=%s; limit_reached=%s' % (wide, d.get('established_count'), d.get('limit_reached')),
            actions=['核對監聽程式是否為自己需要的分享、開發或遠端服務。'],
            limitations=['不記錄遠端 IP 或網域；綁定所有介面不等於外網可達。單次連線狀態無法判斷過去是否異常傳輸。'], terms=['listener'])
        checks[-1]['evidence'].extend({'source': 'Get-NetTCPConnection snapshot', 'detail': json.dumps(item, ensure_ascii=False)} for item in listeners)
    else:
        unavailable('connections', 'network', '程式連線與對外服務', 'Get-NetTCPConnection')

    result = results.get('failed_logins', {})
    if result.get('ok') and isinstance(result.get('data'), dict):
        d = result['data']
        n = d.get('count', 0)
        add('failed-logins', 'system', '近期登入失敗線索', 'review', 'low' if n else 'info',
            '可讀取範圍內近 7 天有 %s%s 筆登入失敗事件。' % ('至少 ' if d.get('limit_reached') else '', n),
            'Security Event 4625; aggregate only', json.dumps(d, ensure_ascii=False),
            actions=['若數量或發生時段不符合使用情況，請在事件檢視器進一步核對。'],
            limitations=['打錯密碼、背景服務或網路驗證也可能產生事件；零事件不代表沒有入侵，取決於記錄政策與保留期間。'])
    else:
        unavailable('failed_logins', 'system', '近期登入失敗線索', 'Security Event 4625')

    for key, title, source in [('installed_apps', '已安裝程式', 'Uninstall registry'), ('running_apps', '目前執行的程式', 'Get-Process snapshot')]:
        result = results.get(key, {})
        if result.get('ok') and isinstance(result.get('data'), dict):
            d = result['data']
            items = [i for i in rows(d.get('items')) if isinstance(i, dict)]
            inventories['apps'].extend(items)
            incomplete = bool(d.get('errors') or d.get('limit_reached'))
            add(key, 'apps', title, 'review', 'info', '成功讀取的範圍盤點 %s 個項目。%s' %
                (len(items), '有讀取錯誤或數量上限，清單不完整。' if incomplete else ''), source,
                'items=%s; errors=%s; limit_reached=%s' % (len(items), d.get('errors', 0), d.get('limit_reached', False)),
                actions=['先核對常用程式的發布者、版本與更新來源，再檢視不需要的權限。'],
                limitations=['目前執行不等於經常使用。安裝清單不保證涵蓋可攜式程式、Store App 或其他使用者。版本新舊未逐一上網查證。'])
        else:
            unavailable(key, 'apps', title, source)
    if wifi.get('ok'):
        items = rows(wifi.get('data'))
        connected = [x for x in items if x.get('state') == 'connected']
        protected = [x for x in connected if x.get('status') == 'ok']
        weak = [x for x in protected if str(x.get('authentication')).lower() in ('none', 'open80211', 'sharedkey80211', 'wpa', 'wpapsk', 'wpanone')
                or str(x.get('cipher')).lower() in ('none', 'wep', 'wep40', 'wep104', 'tkip')]
        known = (not wifi.get('limit_reached') and len(connected) == len(protected)
                 and all(str(x.get('authentication')).lower() in ('rsna', 'rsnapsk', 'wpa3', 'wpa3enterprise192bits', 'wpa3sae', 'owe', 'wpa3enterprise')
                         and str(x.get('cipher')).lower() in ('ccmp', 'gcmp', 'gcmp256') for x in protected))
        status = 'attention' if weak else ('pass' if connected and known else 'unknown')
        detail = json.dumps(items, ensure_ascii=False)
        summary = ('有連線使用開放或較舊的 Wi-Fi 保護。' if weak else
                   ('目前連線顯示較新的 Wi-Fi 加密方式。' if connected and known else
                    ('未取得有連線狀態的 Wi-Fi；沒有可評估的連線。' if not connected else 'Wi-Fi 保護屬性未能完整讀取。')))
        add('wifi', 'network', '目前 Wi-Fi 的安全性', status, 'medium' if weak else 'info', summary,
            'WinRT NetworkSecuritySettings: connected Wi-Fi profiles', detail,
            actions=['不熟悉的公共 Wi-Fi 上，先確認網路提供者與網站 HTTPS；家用路由器優先使用 WPA2-AES 或 WPA3。'],
            limitations=['不記錄網路名稱、MAC 位址或密碼；未驗證路由器韌體、管理員密碼、WPS、VPN、惡意基地台或區域網路其他裝置。OWE 只提供無密碼加密，不驗證熱點身分。'], terms=['wifi', 'wpa'])
    else:
        add('wifi', 'network', '目前 Wi-Fi 的安全性', 'unknown', 'info', 'Wi-Fi 狀態未能讀取；可能是服務、硬體或位置隱私權限制。',
            'WinRT NetworkSecuritySettings', str(wifi.get('reason', 'unavailable')), actions=['在 Windows 設定 → 網路和網際網路 → Wi-Fi，人工查看目前連線的安全性類型。'])

    if bluetooth.get('ok'):
        devices = [x for x in rows(bluetooth.get('data')) if isinstance(x, dict)]
        inventories['devices'] = devices
        radio = bluetooth.get('radio', {})
        discoverable = radio.get('discoverable') is True
        add('bluetooth', 'devices', '藍牙與已知裝置', 'review', 'low' if discoverable else 'info',
            '已列出 %s 個傳統藍牙裝置；%s 個目前連線。%s' %
            (len(devices), sum(d.get('state') == 'connected' for d in devices), '列舉未完整或達數量上限。' if bluetooth.get('limit_reached') else ''),
            'Bluetooth cached enumeration; inquiry=false', json.dumps({'radio': radio, 'limit_reached': bool(bluetooth.get('limit_reached'))}, ensure_ascii=False),
            actions=['核對清單內是否有不認識的裝置；不需要時可自行關閉藍牙或取消舊配對。'],
            limitations=['僅涵蓋傳統藍牙，未涵蓋 BLE；只查第一個藍牙無線電的可探索狀態，不能確認所有硬體的總開關。未掃描附近裝置或傳送配對要求。'], terms=['bluetooth'])
    else:
        add('bluetooth', 'devices', '藍牙與已知裝置', 'unknown', 'info', '未能取得傳統藍牙裝置資料。',
            'Bluetooth cached enumeration', str(bluetooth.get('reason', 'unavailable')),
            actions=['在 設定 → 藍牙與裝置 核對開關、連線裝置和不再使用的配對。'], limitations=['不能據此判定沒有藍牙裝置；BLE 未涵蓋。'])

    if files.get('ok'):
        inventories['downloads'] = files.get('items', [])
        suspicious = sum(any(s != 'executable_or_installer' for s in x.get('signals', [])) for x in files.get('items', []))
        add('downloads', 'files', '近期下載檔案線索', 'review', 'medium' if suspicious else 'info',
            '成功讀取的範圍找到 %s 個值得核對用途的近期檔案，其中 %s 個有偽裝檔名線索。%s' %
            (len(files.get('items', [])), suspicious, '有讀取錯誤或數量上限，清單不完整。' if files.get('errors') or files.get('limit_reached') else ''),
            'Default Downloads metadata only', 'entries=%s; days=%s; capped=%s; errors=%s' %
            (files.get('entries_observed'), files.get('days'), files.get('limit_reached'), files.get('errors')),
            actions=['核對下載來源和用途；不認識的檔案先不要執行。'],
            limitations=['只看預設下載資料夾最上層中繼資料；重新導向的下載位置、完整磁碟、檔案內容與簽章未檢查。可執行副檔名不代表惡意。'])
        checks[-1]['evidence'].extend({'source': 'Downloads metadata only', 'detail': json.dumps(item, ensure_ascii=False)} for item in files.get('items', []))
    else:
        add('downloads', 'files', '近期下載檔案線索', 'unknown', 'info', '預設下載位置未能安全讀取。',
            'Downloads metadata only', str(files.get('reason', 'unavailable')),
            limitations=['可能使用重新導向位置或受到權限限制；未另行遍歷其他磁碟。'])
    return {'schema_version': '2.0', 'platform': 'Windows',
            'observed_at': observed_at or dt.datetime.now().astimezone().isoformat(),
            'coverage_status': 'partial', 'checks': checks, 'inventories': inventories,
            'usage': {'apps': {'status': 'unknown', 'items': [], 'source': 'no_usage_events'}},
            'limitations': ['Windows 資料取得受版本、權限與管理政策影響；未提升權限。',
                            '一次性唯讀快照，不代表正在監控或已完成惡意程式鑑識。',
                            '未讀取密碼、Cookie 值、Wi-Fi 設定檔密鑰、復原金鑰、完整程序參數或私人文件。',
                            '系統查詢可能留下作業系統日誌；本工具不修改來源設定或啟動修復。']}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--home', type=Path, default=Path.home())
    parser.add_argument('--days', type=int, choices=range(1, 91), default=14)
    parser.add_argument('--network-seconds', type=int, default=0, help='Compatibility option: Windows takes one connection snapshot.')
    parser.add_argument('--check-updates', action='store_true', help='Compatibility option: Windows reads installed updates only.')
    args = parser.parse_args()
    if platform.system() != 'Windows':
        result = {'status': 'unsupported', 'platform': platform.system(), 'coverage_status': 'not_checked',
                  'reason': 'Windows collector requires Windows; no Windows commands were run.'}
    else:
        try:
            executable = ps_executable()
        except OSError:
            executable = None
        with ThreadPoolExecutor(max_workers=4) as pool:
            pairs = list(pool.map(lambda key: (key, run_query(key, executable)), QUERIES))
        queries = dict(pairs)
        result = build_report(queries, wifi_from_query(queries.get('wifi', {})), bluetooth_native(), downloads_metadata(args.home.absolute(), args.days))
        result['requested_options'] = {'check_updates': args.check_updates,
                                       'windows_update_mode': 'installed_history_only',
                                       'network_seconds': args.network_seconds, 'network_mode': 'single_snapshot'}
    fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'w', encoding='utf-8') as handle:
        json.dump(result, handle, ensure_ascii=False, indent=2)
        handle.write('\n')
    print(json.dumps({'output': str(args.output), 'coverage_status': result['coverage_status']}, ensure_ascii=False))
    return 0


if __name__ == '__main__':
    sys.exit(main())
