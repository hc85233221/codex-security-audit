#!/usr/bin/env python3
"""User-requested, bounded passive triage; no executable content or remediation."""
import argparse
import collections
import datetime as dt
import ipaddress
import json
import os
from pathlib import Path
import queue
import re
import socket
import ssl
import stat
import sys
import threading
import time
import unicodedata
from urllib.parse import urlsplit
sys.dont_write_bytecode = True
from audit_io import is_redirected, private_directory, write_new
from inspect_skills import SENSITIVE_NAME, SKIP_DIRS
from inspect_scripts import SUFFIXES as SCRIPT_SUFFIXES, script_findings

MAX_ENTRIES = 2000
MAX_DEPTH = 3
MAX_FINDINGS = 300
MAX_SCRIPT_FILES = 100
MAX_SCRIPT_BYTES = 256 * 1024
MAX_TOTAL_SCRIPT_BYTES = 4 * 1024 * 1024
MAX_HEADERS = 32768
MAX_HEADER_FIELDS = 100
NETWORK_SECONDS = 12
BIDI = re.compile('[\u202a-\u202e\u2066-\u2069\u200e\u200f]')
EXECUTABLE_SUFFIXES = {'.exe','.com','.scr','.msi','.msix','.app','.dmg','.pkg','.command','.bat','.cmd','.ps1','.vbs','.js','.sh','.py','.jar','.lnk','.url','.desktop'}
DOCUMENT_SUFFIXES = {'.pdf','.doc','.docx','.xls','.xlsx','.ppt','.pptx','.jpg','.jpeg','.png','.txt','.rtf','.csv'}
HEADERS = {'strict-transport-security','content-security-policy','x-content-type-options','x-frame-options','referrer-policy','permissions-policy'}
CHINESE_RULES = {
    'download_to_interpreter':'下載內容後交給解譯器', 'destructive_operation':'可刪除或重建檔案',
    'permission_widening':'可擴大檔案權限', 'validation_bypass':'可略過驗證',
    'credential_source':'提及敏感憑證來源', 'outbound_data_api':'具有傳送資料能力',
    'instruction_override':'可能要求忽略指示或隱瞞操作', 'obfuscated_execution':'解碼後動態執行線索',
    'possible_embedded_secret':'疑似金鑰格式，未保留內容', 'windows_download_execute':'下載後執行線索',
    'windows_destructive_operation':'可刪除或格式化資料', 'windows_security_change':'可變更安全防護',
    'script_interpreter_delegation':'交由其他解譯器執行', 'batch_destructive_operation':'批次刪除線索',
    'startup_registration':'可建立背景啟動項目', 'broad_trigger':'過廣的觸發描述',
}


def finding(code, title, detail, action, severity='medium', status='review'):
    return {'code':code,'severity':severity,'status':status,'title':title,'detail':detail,'action':action}


def base_report(kind):
    return {'schema_version':'target-1','kind':kind,'observed_at':dt.datetime.now().astimezone().isoformat(),
            'target_display':'未取得有效目標','status':'unknown','summary':'尚未完成檢查。',
            'findings':[],'coverage':{},'limitations':[], 'network_performed':False}


def label(value, limit=180):
    """Display untrusted metadata without directional/control-character spoofing."""
    return ''.join('\\u%04x'%ord(c) if unicodedata.category(c) in ('Cc','Cf','Cs') else c for c in str(value))[:limit]


def parse_url(target):
    if not isinstance(target,str) or not target or len(target)>4096:
        raise ValueError('invalid_url')
    if target!=target.strip() or '\\' in target or any(ord(c)<33 or ord(c)==127 for c in target):
        raise ValueError('ambiguous_url')
    try:
        p=urlsplit(target)
        host=p.hostname
        if p.scheme.lower() not in ('http','https') or not host: raise ValueError('unsupported_url')
        if '%' in host or BIDI.search(host): raise ValueError('ambiguous_hostname')
        port=p.port or (443 if p.scheme.lower()=='https' else 80)
        try:
            address=ipaddress.ip_address(host)
            ascii_host=address.compressed
        except ValueError:
            address=None
            ascii_host=host.rstrip('.').encode('idna').decode('ascii').lower()
            if len(ascii_host)>253 or '.' not in ascii_host: raise ValueError('invalid_hostname')
            if not all(re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?',part) for part in ascii_host.split('.')):
                raise ValueError('invalid_hostname')
        return {'parts':p,'host':host,'ascii_host':ascii_host,'port':port,'address':address,'scheme':p.scheme.lower()}
    except (ValueError,UnicodeError):
        raise ValueError('invalid_url')


def display_url(parsed):
    host=parsed['ascii_host']
    if ':' in host:host='['+host+']'
    port=parsed['port'];standard=443 if parsed['scheme']=='https' else 80
    origin=parsed['scheme']+'://'+host+(':'+str(port) if port!=standard else '')
    parts=parsed['parts']
    depth=sum(bool(x) for x in parts.path.split('/'))
    suffix='；路徑 %d 段（不保存內容）'%depth if depth else ''
    return origin+suffix


def inspect_link(target, kind='link'):
    report=base_report(kind)
    report['coverage']={'mode':'offline_url_structure','status':'bounded','network_requested':False,'reputation_checked':False}
    report['limitations']=['只分析網址結構；沒有連線、查黑名單或執行網站內容。','沒有發現結構線索，也不能證明網站或下載安全。','不保存帳密、查詢參數、片段或路徑內容。']
    try:parsed=parse_url(target)
    except ValueError:
        report['findings']=[finding('invalid_url','網址格式無法安全判讀','只接受完整的 http:// 或 https:// 網址；控制字元、反斜線及模糊主機格式會被拒絕。','先核對原始來源與完整網址，不要開啟不明連結。',status='unknown')]
        report['summary']='網址未能解析，尚未連線。'
        report['coverage']['status']='unavailable'
        return report
    report['target_display']=display_url(parsed)
    p=parsed['parts'];findings=report['findings']
    if parsed['scheme']=='http':
        findings.append(finding('http','連線未使用 HTTPS','HTTP 不提供此連線的 TLS 加密；這不是網站惡意的證據。','不要在未加密連線輸入登入或付款資料。'))
    if p.username is not None or p.password is not None:
        findings.append(finding('userinfo','網址含帳號資訊或混淆前綴','@ 前方不是實際網站主機，帳密內容已略去。','只依實際主機名稱核對來源，勿分享含帳密的網址。'))
    if parsed['address']:
        findings.append(finding('ip_host','網址使用 IP 位址','IP 位址本身不能證明網站身分或可信度。','以原先保存的官方管道核對目標。'))
    if any(ord(c)>127 for c in parsed['host']) or any(x.startswith('xn--') for x in parsed['ascii_host'].split('.')):
        findings.append(finding('idn','網域含國際字元','國際化網域可能是合法名稱，也可能造成外觀混淆；已顯示 ASCII 網域。','逐字核對實際網域，不只看外觀。'))
    scripts={unicodedata.name(c,'').split(' ')[0] for c in parsed['host'] if c.isalpha()}
    if len(scripts&{'LATIN','CYRILLIC','GREEK'})>1:
        findings.append(finding('mixed_script','網域混合相似字系','混合拉丁、希臘或西里爾字元可能造成辨識困難。','從原先儲存的官網入口查證。'))
    if parsed['port'] not in (80,443):
        findings.append(finding('unusual_port','使用非一般網頁連接埠','連接埠不是 80 或 443；可能是合法服務，需核對用途。','確認服務提供者與目的，不因陌生連接埠直接判定惡意。'))
    if BIDI.search(target):
        findings.append(finding('bidi','含文字方向控制字元','顯示順序可能和實際網址不同；原始字元沒有顯示。','請寄件者提供可直接核對的標準網址。'))
    if p.query or p.fragment:
        findings.append(finding('private_components','包含參數或片段','可能有登入、追蹤或分享資訊；本報告未保存其內容。','分享前移除私人參數；網站連線檢查會拒絕此類輸入。','info'))
    report['status']='review'
    report['summary']='發現 %d 項網址結構線索，請核對來源。'%len(findings) if findings else '未見常見網址結構線索；尚未驗證網站內容。'
    return report


def public_ip(value):
    ip=ipaddress.ip_address(value)
    if isinstance(ip,ipaddress.IPv4Address) and any(ip in ipaddress.ip_network(prefix) for prefix in ('192.0.0.0/24','192.88.99.0/24')):return False
    if isinstance(ip,ipaddress.IPv6Address):
        if ip not in ipaddress.ip_network('2000::/3'):return False
        if any(ip in ipaddress.ip_network(prefix) for prefix in ('2001::/23','2001:db8::/32','2002::/16','3fff::/20')):return False
    if isinstance(ip,ipaddress.IPv6Address) and (ip.ipv4_mapped or ip.sixtofour or ip.teredo):return False
    if isinstance(ip,ipaddress.IPv6Address) and any(ip in ipaddress.ip_network(prefix) for prefix in ('64:ff9b::/96','64:ff9b:1::/48')):return False
    # ipaddress behaviour differs across supported Python versions.
    return ip.is_global and not (ip.is_private or ip.is_reserved or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_unspecified)


def resolve_public(host, port, timeout=3):
    """Bound DNS waiting; every returned address must be public before any connect."""
    result=queue.Queue(maxsize=1)
    def resolve():
        try:result.put((True,socket.getaddrinfo(host,port,type=socket.SOCK_STREAM)))
        except (OSError,ValueError):result.put((False,None))
    threading.Thread(target=resolve,daemon=True).start()
    try:ok,records=result.get(timeout=timeout)
    except queue.Empty:raise ValueError('dns_timeout')
    if not ok or not records or len(records)>32:raise ValueError('dns_unavailable')
    choices=[]
    for family,socktype,proto,_,addr in records:
        if family not in (socket.AF_INET,socket.AF_INET6) or not public_ip(addr[0]):raise ValueError('nonpublic_address')
        choice=(family,socktype,proto,addr)
        if choice not in choices:choices.append(choice)
    if not choices:raise ValueError('dns_unavailable')
    return choices


def receive_headers(sock, deadline):
    raw=bytearray()
    while not raw.endswith(b'\r\n\r\n'):
        if len(raw)>=MAX_HEADERS:raise ValueError('header_limit')
        remaining=deadline-time.monotonic()
        if remaining<=0:raise ValueError('header_timeout')
        sock.settimeout(remaining)
        chunk=sock.recv(1)  # Stop exactly after headers; never parse/read a body.
        if not chunk:raise ValueError('incomplete_headers')
        raw.extend(chunk)
    lines=bytes(raw).split(b'\r\n')
    match=re.fullmatch(br'HTTP/1\.[01] ([1-5][0-9]{2})(?: [^\r\n]*)?',lines[0])
    if not match:raise ValueError('invalid_status')
    if len(lines)-3>MAX_HEADER_FIELDS:raise ValueError('header_count_limit')
    retained={};location=None
    for line in lines[1:-2]:
        if not line or line[:1] in b' \t' or b':' not in line:raise ValueError('invalid_header')
        name,value=line.split(b':',1)
        if not re.fullmatch(br'[!#$%&\x27*+.^_`|~0-9A-Za-z-]+',name):raise ValueError('invalid_header')
        key=name.decode('ascii').lower()
        # Cookie values and all unrelated headers are discarded.
        if key in HEADERS:retained[key]=value.strip().decode('latin-1')
        elif key=='location':location=value.strip().decode('latin-1')
    return int(match.group(1)),retained,location


def network_head(parsed):
    deadline=time.monotonic()+NETWORK_SECONDS
    choices=resolve_public(parsed['ascii_host'],parsed['port'],timeout=min(3,NETWORK_SECONDS))
    family,socktype,proto,addr=choices[0]  # No service probing or retries.
    sock=None
    try:
        sock=socket.socket(family,socktype,proto)
        sock.settimeout(max(.1,deadline-time.monotonic()));sock.connect(addr)
        peer=sock.getpeername()[0]
        if ipaddress.ip_address(peer)!=ipaddress.ip_address(addr[0]) or not public_ip(peer):raise ValueError('peer_mismatch')
        tls={}
        if parsed['scheme']=='https':
            context=ssl.create_default_context()
            sock.settimeout(max(.1,deadline-time.monotonic()))
            sock=context.wrap_socket(sock,server_hostname=parsed['ascii_host'])
            certificate=sock.getpeercert()
            tls={'validated':True,'version':sock.version(),'expires_at':certificate.get('notAfter')}
        host=parsed['ascii_host'];host='['+host+']' if ':' in host else host
        request=('HEAD / HTTP/1.1\r\nHost: '+host+'\r\nUser-Agent: Local-Security-Review/3\r\nAccept: */*\r\nConnection: close\r\n\r\n').encode('ascii')
        sock.settimeout(max(.1,deadline-time.monotonic()));sock.sendall(request)
        status,headers,location=receive_headers(sock,deadline)
        result={'http_status':status,'tls':tls,'header_presence':{h:h in headers for h in sorted(HEADERS)},
                'nosniff':headers.get('x-content-type-options','').lower()=='nosniff','redirect_seen':status in (300,301,302,303,305,307,308),
                'redirect_followed':False,'request_path':'/','resolved_address_count':len(choices)}
        if location is not None:
            try:result['redirect_display']=display_url(parse_url(location))
            except ValueError:result['redirect_display']='相對或無法安全解析的目的地（未保存內容）'
        return result
    finally:
        if sock:sock.close()


def inspect_website(target, allow_network=False):
    report=inspect_link(target,'website')
    report['coverage'].update(mode='public_site_headers',network_requested=bool(allow_network),site_content_checked=False)
    report['limitations']=['只對公開網站首頁送一次 HEAD；不跟隨轉址、不讀網頁內容、不執行 JavaScript。','沒有查詢黑名單、漏洞、下載內容或網站背後的商家身分。','安全標頭或有效憑證不能證明網站無惡意；缺少標頭也不是詐騙證據。','主機須全部解析為公開 IP；僅允許 HTTP 80 或 HTTPS 443，固定連線到驗證過的位址。']
    if not allow_network:
        report['status']='unknown';report['summary']='已做離線網址檢查；網站連線尚未授權。'
        report['coverage']['status']='not_checked'
        report['findings'].append(finding('network_not_authorized','尚未連線','需要使用者明確同意後，才查看公開網站的憑證與回應標頭。','確認後使用 --allow-network；此選項不授權其他網站或主動掃描。','info',status='unknown'))
        return report
    try:
        parsed=parse_url(target);p=parsed['parts']
        if p.username is not None or p.password is not None or p.query or p.fragment:raise ValueError('private_url_components')
        if parsed['port']!=(443 if parsed['scheme']=='https' else 80):raise ValueError('port_not_allowed')
        if parsed['address'] and not public_ip(parsed['ascii_host']):raise ValueError('nonpublic_address')
    except ValueError:
        report['status']='unknown';report['summary']='目標未符合公開網站檢查範圍，沒有連線。'
        report['coverage']['status']='unavailable'
        report['findings'].append(finding('network_target_blocked','已停止網站連線','請使用不含帳密、參數或片段的標準公開網站網址；內網與非標準連接埠不在此模式範圍。','提供公開首頁網址，或另行指定內網檢查範圍。',status='unknown'))
        return report
    report['target_display']=display_url(parsed).split('；',1)[0]+'（只查首頁）'
    report['coverage']['input_path_omitted']=p.path not in ('','/')
    report['coverage']['request_path']='/'
    # DNS itself contacts the configured resolver, so mark network attempted here.
    report['network_performed']=True
    try:
        net=network_head(parsed);report['network']=net
    except ssl.SSLCertVerificationError:
        report['status']='attention';report['summary']='網站憑證驗證失敗；未略過驗證。'
        report['coverage']['status']='partial'
        report['findings'].append(finding('tls_not_verified','憑證無法驗證','可能涉及到期、主機名稱、信任鏈或本機信任設定，不能單憑此確定惡意。','先核對網址、日期與網路環境，不輸入敏感資料。','high',status='attention'))
        return report
    except (OSError,ssl.SSLError,ValueError):
        report['status']='unknown';report['summary']='未取得可判讀的網站回應；已停止，沒有重試。'
        report['coverage']['status']='unavailable'
        report['findings'].append(finding('network_unavailable','網站資料未取得','可能為非公開位址、DNS／連線限制、逾時或回應格式不符；未保留原始錯誤。','使用已知官方管道查證；無法連線不代表網站惡意。',status='unknown'))
        return report
    report['status']='review'
    report['coverage']['status']='bounded' if 200<=net['http_status']<300 else 'partial'
    if net['redirect_seen']:
        report['findings'].append(finding('redirect','網站回覆轉址','只記錄已遮蔽的目的地，未跟隨或查詢新的主機。','先核對新主機是否符合預期，再決定是否另行檢查。'))
    if not 200<=net['http_status']<300 and not net['redirect_seen']:
        report['findings'].append(finding('limited_response','回應可能不是一般頁面','HTTP 狀態 %d；登入限制、HEAD 不支援或錯誤頁的標頭可能不同。'%net['http_status'],'不要把這次標頭視為整個網站設定。','info'))
    missing=[h for h,present in net['header_presence'].items() if not present]
    if missing:
        report['findings'].append(finding('headers_not_observed','有安全標頭未出現在此次回應','未觀察到：'+', '.join(missing)+'。這是設定線索，沒有評定網站惡意。','網站管理者可依頁面用途檢視；使用者仍需核對網站身分。','info'))
    report['summary']='已查看一次首頁回應與可取得的連線保護；未檢查網站內容。'
    return report


def cloud_placeholder(info):
    attrs=getattr(info,'st_file_attributes',0)
    flags=getattr(info,'st_flags',0)
    return bool(attrs & (0x400|0x1000|0x40000|0x400000)) or bool(flags & 0x40000000)


def safe_script_bytes(path, root, info, stats, directory_fd=None, entry_name=None):
    """Read only anchored, authorized script text; no path-based fallback."""
    fd=None
    try:
        if directory_fd is None:
            stats['unanchored_script_content_skipped']+=1;return None
        if cloud_placeholder(info) or not stat.S_ISREG(info.st_mode):return None
        if info.st_size>MAX_SCRIPT_BYTES:stats['oversized_scripts']+=1;return None
        fd=os.open(entry_name,os.O_RDONLY|os.O_NOFOLLOW|getattr(os,'O_NONBLOCK',0),dir_fd=directory_fd)
        opened=os.fstat(fd)
        if not stat.S_ISREG(opened.st_mode) or cloud_placeholder(opened) or (opened.st_dev,opened.st_ino)!=(info.st_dev,info.st_ino):
            stats['changed_or_redirected_scripts']+=1;return None
        remaining=MAX_TOTAL_SCRIPT_BYTES-stats['script_bytes_read']
        if opened.st_size>MAX_SCRIPT_BYTES or opened.st_size>=remaining:
            stats['script_limit_skipped']+=1;return None
        with os.fdopen(fd,'rb') as stream:
            fd=None;raw=stream.read(min(MAX_SCRIPT_BYTES+1,remaining));after=os.fstat(stream.fileno())
        stats['script_bytes_read']+=len(raw)
        if (opened.st_size,opened.st_mtime_ns,opened.st_ctime_ns)!=(after.st_size,after.st_mtime_ns,after.st_ctime_ns) or len(raw)>MAX_SCRIPT_BYTES or b'\0' in raw:
            stats['changed_or_binary_scripts']+=1;return None
        text=raw.decode('utf-8');return text
    except (OSError,ValueError,UnicodeError):stats['unreadable_scripts']+=1;return None
    finally:
        if fd is not None:os.close(fd)


def open_child_directory(root_fd, parts):
    """Walk from an already verified root handle; never resolve a symlink."""
    fd=os.dup(root_fd)
    try:
        for component in parts:
            child=os.open(component,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd)
            os.close(fd);fd=child
            info=os.fstat(fd)
            if cloud_placeholder(info) or not stat.S_ISDIR(info.st_mode):raise ValueError('unavailable_directory')
        return fd
    except BaseException:
        os.close(fd);raise


def inspect_folder(target, include_scripts=False):
    report=base_report('folder');stats=collections.Counter();entries=[];findings=[]
    root=Path(target).expanduser().absolute();report['target_display']=label(root.name or '所選資料夾')
    report['coverage']={'mode':'metadata_and_authorized_scripts' if include_scripts else 'metadata_only','max_entries':MAX_ENTRIES,'max_depth':MAX_DEPTH,'max_findings':MAX_FINDINGS,'include_scripts':bool(include_scripts)}
    report['limitations']=['只檢查指定資料夾，最多 2000 個項目、子資料夾深度 3；跳過連結、雲端占位、隱藏與敏感名稱。','檔名、可執行類型或過寬權限是複核線索，不能證明惡意。','不解壓縮、不掛載映像、不執行檔案；未進行防毒或完整簽章鑑識。','Windows 不以 Unix mode 推論 ACL；原生 Windows 尚待實機驗證。']
    if include_scripts:report['limitations'].append('腳本只讀 UTF-8 文字：最多 100 檔、每檔 256 KiB、總計最多 4 MiB／每檔前 10000 行；不保留程式片段或秘密值。')
    else:report['limitations'].append('此次未讀檔案內容；若需要腳本靜態檢查，須另明確指定 --include-scripts。')
    def add(item):
        if len(findings)<MAX_FINDINGS:findings.append(item)
        else:stats['findings_omitted']+=1
    try:
        info=root.lstat()
        if is_redirected(root) or cloud_placeholder(info) or not stat.S_ISDIR(info.st_mode):raise ValueError('invalid_root')
    except (OSError,ValueError):
        report.update(summary='所選資料夾不可讀或為連結／占位項目；沒有追蹤目標。',findings=[],inventory=[])
        report['coverage']['status']='unavailable';return report
    anchored=os.name!='nt' and hasattr(os,'O_NOFOLLOW') and os.open in os.supports_dir_fd and os.scandir in os.supports_fd
    root_fd=None
    if anchored:
        try:
            root_fd=os.open(root,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
            opened=os.fstat(root_fd)
            if (opened.st_dev,opened.st_ino)!=(info.st_dev,info.st_ino) or cloud_placeholder(opened):raise ValueError('root_changed')
        except (OSError,ValueError):
            if root_fd is not None:os.close(root_fd)
            report.update(summary='所選資料夾在開啟時變動，已停止檢查。',inventory=[])
            report['coverage']['status']='unavailable';return report
    else:
        report['limitations'].append('此平台未提供可用的目錄控制代碼介面，僅盤點所選資料夾頂層，不讀腳本內容或遞迴。')
    if os.name!='nt' and info.st_mode&0o002:
        add(finding('root_world_writable','所選資料夾允許其他本機使用者寫入','只根據 POSIX mode，未驗證 ACL 或有效存取。','確認是否有共用需求，再決定是否調整權限。'))
    report['coverage']['traversal_guard']='anchored_directory_handles' if anchored else 'top_level_metadata_only'
    stack=[((),0)]
    try:
      while stack and stats['entries_considered']<MAX_ENTRIES:
        parts,depth=stack.pop();directory=root.joinpath(*parts);directory_fd=None
        try:
            if anchored:
                directory_fd=open_child_directory(root_fd,parts)
                iterator=os.scandir(directory_fd)
            else:
                before=directory.lstat()
                if is_redirected(directory) or cloud_placeholder(before) or (before.st_dev,before.st_ino)!=(info.st_dev,info.st_ino):
                    stats['redirected_or_cloud_skipped']+=1;continue
                iterator=os.scandir(directory)
            with iterator:
                for entry in iterator:
                    if stats['entries_considered']>=MAX_ENTRIES:stats['entry_limit_reached']+=1;break
                    stats['entries_considered']+=1
                    path=directory/entry.name
                    if entry.name.startswith('.') or entry.name.casefold() in SKIP_DIRS or SENSITIVE_NAME.search(entry.name):
                        stats['sensitive_hidden_dependency_skipped']+=1;continue
                    try:
                        entry_info=os.stat(entry.name,dir_fd=directory_fd,follow_symlinks=False) if anchored else entry.stat(follow_symlinks=False)
                        if stat.S_ISLNK(entry_info.st_mode) or cloud_placeholder(entry_info) or (not anchored and is_redirected(path)):
                            stats['redirected_or_cloud_skipped']+=1;continue
                        if not stat.S_ISREG(entry_info.st_mode) and not stat.S_ISDIR(entry_info.st_mode):stats['special_files_skipped']+=1;continue
                        relative=label(path.relative_to(root));suffix=path.suffix.lower()
                        is_dir=stat.S_ISDIR(entry_info.st_mode)
                        row={'name':label(entry.name),'relative_path':relative,'type':'directory' if is_dir else 'file','size':entry_info.st_size if not is_dir else None,'content_read':False}
                        entries.append(row);stats['metadata_entries']+=1
                        if BIDI.search(entry.name):add(finding('filename_direction','檔名含方向控制字元',relative,'核對實際副檔名與來源；不要直接執行。'))
                        suffixes=[s.lower() for s in path.suffixes]
                        if len(suffixes)>1 and suffixes[-1] in EXECUTABLE_SUFFIXES and suffixes[-2] in DOCUMENT_SUFFIXES:
                            add(finding('double_extension','檔名像文件，最後副檔名可執行',relative,'先向已知寄件者確認檔案用途與來源。'))
                        elif suffix in EXECUTABLE_SUFFIXES:
                            add(finding('launchable_file','含可啟動或安裝的項目',relative,'核對官方來源；此類型本身不代表惡意。','info'))
                        if os.name!='nt' and entry_info.st_mode&0o002:
                            add(finding('world_writable','其他本機使用者可寫入',relative+'；只根據 POSIX mode，未驗證 ACL 或有效存取。','確認是否有共用需求，再決定是否調整權限。'))
                        if is_dir:
                            if anchored and depth<MAX_DEPTH:stack.append((parts+(entry.name,),depth+1))
                            else:stats['depth_limited_directories']+=1
                        elif include_scripts and suffix in SCRIPT_SUFFIXES:
                            if stats['scripts_read']>=MAX_SCRIPT_FILES or stats['script_bytes_read']+entry_info.st_size>MAX_TOTAL_SCRIPT_BYTES:
                                stats['script_limit_skipped']+=1;continue
                            content=safe_script_bytes(path,root,entry_info,stats,directory_fd,entry.name)
                            if content is not None:
                                stats['scripts_read']+=1;row['content_read']=True
                                lines=content.splitlines()
                                if len(lines)>10000:stats['script_line_limit']+=1
                                if any(len(line)>4096 for line in lines[:10000]):stats['script_long_line_limit']+=1
                                for signal in script_findings('\n'.join(line[:4096] for line in lines[:10000]),relative):
                                    add(finding('script.'+signal['rule'],CHINESE_RULES.get(signal['rule'],'腳本含需複核的操作'),relative+'：第 '+str(signal['line'])+' 行；內容未保存。','讀上下文確認用途與授權，勿直接執行或按關鍵字判惡意。'))
                    except (OSError,ValueError):stats['metadata_errors']+=1
            if not anchored:
                after=directory.lstat()
                if is_redirected(directory) or (after.st_dev,after.st_ino)!=(before.st_dev,before.st_ino):
                    entries.clear();findings.clear();stats['source_changed_results_discarded']+=1
        except (OSError,ValueError):stats['directory_errors']+=1
        finally:
            if directory_fd is not None:os.close(directory_fd)
    finally:
        if root_fd is not None:os.close(root_fd)
    if stack:stats['unvisited_directories']=len(stack)
    report['findings']=findings;report['inventory']=entries
    unavailable=bool(stats['directory_errors'] or stats['metadata_errors'] or stats['source_changed_results_discarded'])
    bounded=bool(stack or stats['entry_limit_reached'] or stats['depth_limited_directories'] or stats['findings_omitted'] or stats['script_limit_skipped'] or stats['script_line_limit'] or stats['script_long_line_limit'])
    report['coverage'].update(status='partial' if unavailable or bounded else 'bounded',counts=dict(stats),source_text_retained=False)
    report['status']='unknown' if unavailable and not entries else 'review'
    report['summary']='所選資料夾未取得可判讀項目；存在讀取限制，不能視為已完成。' if report['status']=='unknown' else '已取得 %d 筆項目，保留 %d 項複核線索；未判定惡意程式。'%(len(entries),len(findings))
    return report


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--kind',choices=('link','website','folder'),required=True)
    parser.add_argument('--target',required=True)
    parser.add_argument('--output-dir',type=Path,required=True)
    parser.add_argument('--allow-network',action='store_true')
    parser.add_argument('--include-scripts',action='store_true')
    args=parser.parse_args()
    if args.allow_network and args.kind!='website':parser.error('--allow-network is only for website checks.')
    if args.include_scripts and args.kind!='folder':parser.error('--include-scripts is only for explicitly authorized folders.')
    out=args.output_dir.expanduser().absolute()
    try:
        if args.kind=='folder':
            root=Path(args.target).expanduser().absolute()
            try:out.resolve().relative_to(root.resolve())
            except ValueError:pass
            else:raise ValueError('output_inside_target')
        try:out.resolve().relative_to(Path(__file__).resolve().parent.parent)
        except ValueError:pass
        else:raise ValueError('output_inside_skill')
        storage=private_directory(out)
        if args.kind=='folder':report=inspect_folder(args.target,args.include_scripts)
        elif args.kind=='website':report=inspect_website(args.target,args.allow_network)
        else:report=inspect_link(args.target)
        report['storage']=storage
        write_new(out/'target.json',report)
        from render_target import build_target_report
        from report_model import render_html
        model=build_target_report(report,storage_security=storage)
        write_new(out/'report.json',model)
        write_new(out/'report.html',render_html(model,(Path(__file__).resolve().parent.parent/'assets/report.html').read_text(encoding='utf-8')),False)
        summary='指定目標檢查\n'+report['target_display']+'\n'+report['summary']+'\n觀察時間：'+report['observed_at']+'\n\n'+ '\n'.join('- '+x['title']+'：'+x['detail'] for x in report['findings'])+'\n\n限制：\n'+'\n'.join(report['limitations'])
        write_new(out/'摘要.txt',summary,False)
    except (OSError,ValueError):parser.error('Unable to create a new private report or inspect the selected target. No raw input or error details were printed.')
    print(json.dumps({'kind':args.kind,'status':report['status'],'findings':len(report['findings']),'network_performed':report['network_performed'],'report_created':True},ensure_ascii=False))


if __name__=='__main__':main()
