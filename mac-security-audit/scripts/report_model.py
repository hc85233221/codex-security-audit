"""Turn collected facts into a plain-language report, without inventing coverage."""
import datetime as dt
import json
from pathlib import Path
import re
from report_enrichment import enrich_report

GLOSSARY = [
    ('filevault', 'FileVault', 'Mac 的磁碟加密。電腦遺失時，沒有登入憑證的人較難直接讀取磁碟內容；不能阻止已登入帳號中的惡意程式。'),
    ('bitlocker', 'BitLocker／裝置加密', 'Windows 的磁碟加密，用來保護遺失電腦上的資料。本工具不讀復原金鑰。'),
    ('firewall', '防火牆', '控管程式的網路連線規則。開啟不代表所有程式都可信，也不代表所有服務都無法從外部連入。'),
    ('defender', 'Microsoft Defender', 'Windows 的防毒保護。本報告只查看狀態，不主動掃描、隔離或刪檔。'),
    ('gatekeeper', 'Gatekeeper', 'Mac 對下載程式的開啟檢查機制，會檢查開發者身分與相關安全條件。'),
    ('sip', 'SIP／系統完整性保護', '限制程式修改 Mac 的關鍵系統區域。開啟是一項保護，不是整台電腦的安全保證。'),
    ('secure_boot', '安全開機', '在啟動時驗證受信任的系統元件，降低開機流程被竄改的風險。'),
    ('backup', '備份與還原', '備份是另外保存可恢復的資料。雲端同步可能同步誤刪；備份紀錄也不等於已實際測試還原。'),
    ('cookie', 'Cookie', '網站保存在瀏覽器的小筆資料，可能維持登入或偏好。本工具只統計屬性與期限，完全不讀內容。'),
    ('httponly', 'Secure／HttpOnly／SameSite', 'Cookie 的保護屬性，分別限制加密傳送、網頁腳本讀取，以及跨網站傳送情境。缺少屬性需要了解用途，不能直接判定外洩。'),
    ('skill', 'AI skill', '提供 AI 工作流程、指令與程式的技能包。安裝存在、實際啟用與使用次數是不同的事。'),
    ('static_analysis', '靜態檢查', '閱讀程式文字尋找需要複核的操作，並不執行它。命中可能是安全規範或範例，不能直接當成漏洞。'),
    ('prompt_injection', '提示注入', '檔案或網頁內的文字試圖指揮 AI 忽略原本規則。受檢文字是資料，不能當成要照做的指令。'),
    ('signature', '程式簽章', '用來驗證程式完整性及可能的發行者。有效簽章不等於程式絕對安全；自簽章也無法證明公開發行者。'),
    ('permissions', '權限', '程式或帳號可讀寫、控制的範圍，例如螢幕錄製、輸入監控或讀取所有網站。需要對照用途與來源。'),
    ('listener', '監聽連接埠', '程式正在等待其他連線的入口。只供本機連入與接受其他介面連入不同；還要考慮防火牆、路由器及通道設定。'),
    ('wifi', 'Wi-Fi 加密', '保護電腦與無線基地台間的傳輸。WPA2-AES／WPA3 較新；開放網路、WEP、TKIP 需要留意。強加密也無法驗證基地台擁有人可信。'),
    ('wpa', 'WPA2／WPA3', 'Wi-Fi 的驗證與加密標準。WPA3 是較新的標準；仍需確認連到正確基地台、路由器更新及管理設定。'),
    ('bluetooth', '藍牙', '近距離無線連線，可連接鍵盤、耳機等裝置。開啟不等於遭入侵，應確認配對裝置是否認識。'),
    ('usage', '使用頻率', '指定期間內的實際啟動或呼叫次數。本報告只接受有來源與期間的聚合統計，不用修改時間猜測。'),
    ('mfa', 'MFA／多因素驗證', '除了密碼，另用驗證器或安全金鑰等方法確認身分。需在已授權的帳號設定另外確認。'),
    ('https', 'HTTPS', '瀏覽器與網站之間的加密連線。加密不代表網站經營者可信，仍需確認網址。'),
    ('script', '電腦腳本', '用文字編寫、可交給程式執行的自動化指令。本檢查只讀取指定範圍文字，並不執行腳本。'),
    ('background_process', '背景程序／服務', '沒有主視窗也能運作的程式，例如同步、更新與硬體服務。背景存在不是惡意證據。'),
    ('startup', '開機項目與排程', '設定程式在登入、開機或指定時間自動執行。應核對用途與來源，不因自動啟動就停用。'),
    ('acl', 'ACL／存取控制清單', '列出哪些帳號能讀寫檔案的規則。Windows 的 ACL 與 Mac 的 rwx 權限不能直接互換判讀。'),
    ('mdm', '裝置管理', '公司或學校可用管理服務套用設定。出現管理紀錄不代表被入侵；需確認管理者與用途。'),
    ('proxy', '網路代理', '讓連線先經過另一個服務轉送，可能用於公司網路或過濾。只看啟用旗標，無法確認所有實際流量。'),
    ('stealth', '隱藏模式', '讓防火牆減少回應部分探索請求；不是匿名或完整隱身，也不代替其他防護。'),
    ('dns', 'DNS', '將網站名稱查成網路位址。查到位址不代表網站可信，查詢本身也會產生網路請求。'),
    ('tls', 'TLS', '用來加密連線及驗證網站憑證的機制。憑證有效不保證網站內容或經營者可信。'),
    ('head', 'HEAD', '只請求網站回應資訊，不讀取網頁正文。網站仍可能記錄此次請求；本檢查不跟隨轉址。'),
    ('idn', '國際化網域', '可包含不同語言字元的網站名稱。合法名稱也可能看起來很相似，需要核對實際網域。'),
    ('metadata', '中繼資料', '檔名、類型、大小、時間或權限等資料，與文件內文不同；只查這些無法排除檔案中的惡意內容。'),
    ('mcp', 'MCP', '讓 AI 使用外部工具或資料來源的連接方式。設定中有工具不代表已啟用；需要核對其來源與可存取範圍。'),
    ('deserialization', '模型反序列化', '程式將儲存的模型或物件載入記憶體；某些格式可在載入時執行程式。本檢查不載入模型，只以類型提醒核對來源。'),
    ('ai_provenance', '生成來源', '檔案是否由 AI 生成，需有可靠來源紀錄或使用者確認。檔名、資料夾或近期修改時間都不能單獨證明。'),
]

def check(id, category, title, status, summary, impact='', actions=None, evidence=None,
          limitations=None, severity='info', terms=None):
    return dict(id=id, category=category, title=title, status=status, severity=severity,
                summary=summary, impact=impact, actions=actions or [], evidence=evidence or [],
                limitations=limitations or [], terms=terms or [])

def ev(source, detail):
    return {'source': source, 'detail': detail if isinstance(detail, str) else json.dumps(detail, ensure_ascii=False)}

def mac_checks(data, metrics):
    result = []; system = data.get('system', {})
    definitions = [
        ('filevault', '磁碟資料加密', r'FileVault is On\.', r'FileVault is Off\.', 'filevault'),
        ('firewall', '防火牆', r'Firewall is enabled', r'Firewall is disabled', 'firewall'),
        ('gatekeeper', '下載程式開啟保護', r'assessments enabled', r'assessments disabled', 'gatekeeper'),
        ('sip', '系統完整性保護', r'status: enabled', r'status: disabled', 'sip'),
        ('authenticated_root', '系統磁碟完整性驗證', r'status: enabled', r'status: disabled', 'sip'),
    ]
    for key, title, on, off, term in definitions:
        value = system.get(key, {}); text = str(value.get('result', ''))
        status = 'unknown'
        if value.get('status') == 'ok':
            status = 'pass' if re.search(on, text) else 'attention' if re.search(off, text) else 'unknown'
        result.append(check('mac.'+key, 'system', title, status,
                            '已確認啟用。' if status == 'pass' else '已確認未啟用，建議安排處理。' if status == 'attention' else '目前資料不足，無法確認設定。',
                            '這項設定可降低特定風險；不能單獨證明電腦沒有惡意程式。',
                            ['在系統設定確認目前狀態；如需調整，先確認備份與使用需求。'] if status != 'pass' else [],
                            [ev('system.json → system.'+key, value)], severity='high' if status == 'attention' else 'info', terms=[term]))
    schedule = system.get('update_schedule', {})
    available = system.get('available_updates', {})
    update_found = available.get('status')=='ok' and bool(re.search(r'^\* Label:',str(available.get('result','')),re.M))
    result.append(check('mac.updates', 'system', '系統與安全更新', 'attention' if update_found else 'review' if available.get('status') == 'ok' else 'not_checked',
                        '系統回報有可用更新；請安排核對與更新時間。' if update_found else '更新查詢已取得，請核對列出的項目與目前作業系統。' if available.get('status') == 'ok' else '未完成可用更新查詢；不能認定已是最新。',
                        '修補更新可修正已知漏洞，版本與供應情況會改變。',
                        ['開啟系統設定 → 一般 → 軟體更新，核對安全更新；這次健檢不安裝更新。'],
                        [ev('system.json → system.macos', system.get('macos', {})), ev('softwareupdate schedule', schedule), ev('softwareupdate list', available)], severity='high' if update_found else 'medium'))
    backup = system.get('time_machine_destinations', {}); absent = backup.get('no_destinations_configured')
    result.append(check('mac.backup', 'backup', '可還原的備份', 'attention' if absent is True else 'review' if absent is False else 'unknown',
                        '未設定 Time Machine 備份目的地。' if absent is True else '找到 Time Machine 目的地，仍需確認最近成功備份與還原。' if absent is False else '未能確認 Time Machine 目的地。',
                        '電腦故障、誤刪或勒索軟體可能導致資料無法恢復。',
                        ['確認是否另有備份工具與最近成功時間。', '安排小檔案還原測試；新增備份或排程需由使用者決定。'],
                        [ev('tmutil destinationinfo', backup), ev('tmutil listlocalsnapshots', system.get('time_machine_snapshots', {}))],
                        ['只檢查 Time Machine 設定與本機快照；未掃描其他備份工具或外接磁碟。'], 'high' if absent is True else 'medium', ['backup']))
    startup = data.get('startup', {}); items = startup.get('items', [])
    bad = [x for x in items if x.get('world_writable')]
    startup_read = any(x.get('status')=='listed' for x in startup.get('coverage',[]))
    result.append(check('mac.startup', 'apps', '開機與背景啟動項目', 'attention' if bad else 'review' if startup_read else 'unknown',
                        '找到 %d 個啟動設定；用途與必要性仍需確認。' % len(items) if startup_read else '未能完整取得啟動來源，數量及狀態無法確認。',
                        '背景服務可能在登入或開機時執行，也可能提供連線入口。',
                        ['對照名稱、發行者與用途；不認識的項目先查來源，不直接刪除。'],
                        [ev('launchd plist metadata', x) for x in items] + [ev('讀取限制', {k:v for k,v in startup.items() if k!='items'})],
                        [startup.get('limitation', '')], 'medium', ['permissions']))
    listeners = data.get('listeners', {}); opened = listeners.get('items', [])
    all_if = [x for x in opened if x.get('bind') == 'all_interfaces']
    result.append(check('mac.listeners', 'network', '程式連線入口', 'review' if listeners.get('status') == 'ok' else 'unknown',
                        '觀察到 %d 個 TCP 監聽入口，其中 %d 個綁定所有介面。' % (len(opened), len(all_if)) if listeners.get('status')=='ok' else '未能取得監聽入口，無法確認數量與綁定範圍。',
                        '若服務不需要給其他裝置使用，應核對綁定範圍、驗證方式及通道用途。',
                        ['確認對外提供服務的程式用途及登入驗證；未驗證外網是否真的能連入。'],
                        [ev('lsof TCP LISTEN', x) for x in opened], [listeners.get('limitation', '')], 'medium', ['listener', 'firewall']))
    sample = data.get('network_sample', {})
    metrics['traffic'] = {'interval_seconds':sample.get('interval_seconds', 0),
                          'items':[dict(name=x.get('process_pid',''), sent_bytes=x.get('sent_bytes',0), received_bytes=x.get('received_bytes',0)) for x in sample.get('top_active_processes',[])]}
    result.append(check('mac.traffic', 'network', '短時間傳輸觀察', 'review' if sample.get('status') == 'ok' else 'not_checked',
                        '這是短暫流量樣本，無法判斷過去是否有異常傳輸或外洩。',
                        '同步、通訊及 AI 工具都可能產生合法流量，大小本身不是異常判準。',
                        ['有具體可疑程式時，再核對來源、設定及已存在的合適日誌。'],
                        [ev('nettop bounded sample', sample)], [sample.get('limitation','')], terms=['listener']))
    login_read=data.get('login_records',{}).get('status')=='ok'
    result.append(check('mac.logins', 'system', '登入與操作紀錄的覆蓋範圍', 'review' if login_read else 'unknown',
                        '僅取得最近登入類別摘要；沒有完整失敗登入、操作或歷史傳輸資料。' if login_read else '未能取得登入類別摘要，也未檢查完整操作紀錄。',
                        '不能用有限的最近紀錄排除陌生登入。', ['有陌生登入疑慮時，保留時間與情境，再另行授權檢視相關事件。'],
                        [ev('last aggregate', data.get('login_records',{})), ev('共享／代理／管理設定', data.get('remote_and_network',{}))]))
    files = data.get('files', {})
    apps = files.get('application_review_items', [])
    writable = [x for x in apps if x.get('world_writable')]
    result.append(check('mac.app_permissions', 'apps', '程式完整性與可寫入權限', 'attention' if writable else 'review' if apps else 'unknown',
                        '%d 個受檢程式資料夾允許其他本機帳號寫入。' % len(writable) if writable else '已抽查有限範圍程式中繼資料；不是完整應用程式驗證。',
                        '過寬的寫入權限可能增加被其他本機帳號改動的機會。',
                        ['先確認來源與遊戲／更新器需求；需要修復時使用官方方式並保留備份。'],
                        [ev('應用程式中繼資料／簽章', x) for x in apps], [files.get('limitation','')], 'high' if writable else 'low', ['signature','permissions']))
    downloads = files.get('download_review_items', [])
    files_read=isinstance(files.get('download_entries_considered'),int) and (files['download_entries_considered']>0 or not files.get('errors'))
    result.append(check('mac.files', 'files', '近期下載檔案線索', 'review' if files_read else 'unknown',
                        '檢視 %s 筆下載中繼資料，列出 %d 筆需要了解來源的項目。' % (files.get('download_entries_considered','未知'),len(downloads)) if files_read else '未能取得可判讀的下載中繼資料；不是沒有可疑檔案。',
                        '安裝檔、副檔名或隔離標籤只能提示複核，不代表檔案惡意。',
                        ['核對官方來源與用途；不執行未知安裝檔，也不自動上傳掃毒網站。'],
                        [ev('下載中繼資料', x) for x in downloads] + [ev('略過／錯誤', files.get('errors',[]))],
                        [files.get('limitation',''), '未解壓、未執行檔案，也未做全磁碟掃毒。'], 'low', ['signature']))
    secrets = files.get('sensitive_path_permissions_only', [])
    result.append(check('mac.credential_permissions', 'files', '憑證檔案權限', 'attention' if any(x.get('group_or_other_access') for x in secrets) else 'review' if secrets else 'unknown',
                        '只查看指定敏感檔案是否存在及權限；未讀內容。' if secrets else '本次沒有可判讀的敏感檔案權限資料；未讀內容。',
                        '權限過寬可能讓其他本機帳號接觸憑證。', ['確認受檢範圍及 ACL；沒有列出的敏感檔案不在結論範圍。'],
                        [ev('stat only', x) for x in secrets], severity='medium', terms=['permissions','acl']))
    return result


def browser_checks(data, inventory, metrics):
    profiles = data.get('profiles', []); successful = [p for p in profiles if p.get('cookies', {}).get('status') == 'read_only_ok']
    totals = data.get('coverage_totals', {})
    metrics['cookies'] = {'total':sum(p['cookies'].get('total',0) for p in successful),
                          'expired':sum(p['cookies'].get('expired_rows',0) for p in successful),
                          'long_lived':sum(p['cookies'].get('expires_more_than_365_days_from_now',0) for p in successful),
                          'profiles_read':len(successful), 'profiles_discovered':totals.get('discovered_profiles',len(profiles))}
    cookie_ev = []; extension_ev = []; flags = 0
    for p in profiles:
        source = p.get('browser','') + ' / ' + p.get('profile','')
        cookie_ev += [ev(source, {'cookies':p.get('cookies',{}),'preferences_status':p.get('preferences_status'),'security_preferences':p.get('security_preferences',{}), 'coverage_gaps':p.get('coverage_gaps',[])})]
        for x in p.get('extensions',[]):
            inventory['extensions'].append({'name':x.get('name_untrusted',x.get('name','未識別')), 'source':source,
                                             'permissions':x.get('requested_sensitive_permissions',[])+x.get('broad_requested_hosts',[]),
                                             'state':'啟用狀態未確認', 'version':x.get('version','')})
            flags += bool(x.get('review_flags'))
            extension_ev.append(ev(source, x))
    return [check('browser.cookies', 'browser', 'Cookie 安全屬性與期限', 'review' if successful else 'unknown',
                  '成功讀取 %d / %d 個已發現設定檔的 Cookie 中繼資料。' % (len(successful), metrics['cookies']['profiles_discovered']),
                  '到期或長效 Cookie 可作整理參考，數量與屬性不能判定帳號被盜。',
                  ['在瀏覽器設定確認第三方 Cookie 與網站權限；如要清除，先理解可能登出帳號。'],
                  cookie_ev + [ev('覆蓋／錯誤', {'coverage':data.get('coverage',[]),'errors':data.get('errors',[])})],
                  data.get('limitations',[]), terms=['cookie','httponly']),
            check('browser.extensions','browser','瀏覽器擴充功能權限','review' if inventory['extensions'] else 'unknown',
                  '%d 個安裝條目，%d 個條目有較廣權限需核對用途。' % (len(inventory['extensions']),flags),
                  '跨網站讀寫、讀取 Cookie 或控制瀏覽器的權限較大，需確認是否仍需要。',
                  ['核對擴充功能的發行者、用途及啟用狀態；多個設定檔可能重複計數。'], extension_ev,
                  ['磁碟上的 manifest 不證明擴充功能目前已啟用。'], 'medium', ['permissions'])]


def skill_checks(data, inventory):
    summary = data.get('summary', {}); findings = data.get('findings', [])
    for x in data.get('inventory',[]):
        inventory['skills'].append({'name':x.get('name_from_directory','未識別'),
                                     'source':x.get('skill_directory',''), 'signal_count':x.get('review_signals',0),
                                     'usage':'unknown', 'scan_status':x.get('scan_status','unknown')})
    scanned=isinstance(summary.get('files_scanned'),int) and summary['files_scanned']>0
    return [check('skills.static','skills','AI skills 靜態複核','review' if scanned else 'unknown',
                  '%s 個技能包、%s 個文字檔，共 %s 筆待複核線索。' % (summary.get('skill_packages',0),summary.get('files_scanned',0),summary.get('review_signals',0)) if scanned else '沒有可判讀的技能文字檔；請確認範圍、權限及略過原因。',
                  '刪檔、下載執行、讀憑證或外傳等能力需要看上下文；安全規範或範例也會命中。',
                  ['按來源與行號複核；先確認是否為規範、範例或實際執行路徑。', '本機掃描不涵蓋遠端 MCP 的服務端行為與帳號授權。'],
                  [ev('技能掃描範圍', data.get('scope',[]))] + [ev('靜態線索（未讀出程式片段）',x) for x in findings],
                  data.get('limitations',[]), 'medium', ['skill','static_analysis','prompt_injection'])]


def build_report(modules, manifest, usage=None, demo=False):
    now = dt.datetime.now().astimezone().isoformat()
    inventory = {key:[] for key in ('skills','apps','devices','extensions','scripts','background','ai_artifacts')}; checks=[]; metrics={}; scope=[]
    results = {x['module']:x for x in manifest.get('modules',[])}
    for name in ('system','connectivity','browser','skills','scripts','background'):
        if name in ('connectivity','background') and manifest.get('platform')=='Windows':
            continue  # Windows system collector includes wireless and app checks.
        data = modules.get(name); status = results.get(name,{}).get('status','not_selected')
        scope.append({'module':name,'status':status,'detail':results.get(name,{}).get('coverage_status','未取得覆蓋資料')})
        if not data or status != 'completed':
            checks.append(check('module.'+name, {'connectivity':'devices','system':'system','browser':'browser','skills':'skills','scripts':'files','background':'apps'}[name],
                                {'connectivity':'無線連線與程式盤點','system':'系統檢查','browser':'瀏覽器檢查','skills':'AI 技能檢查','scripts':'電腦腳本檢查','background':'背景執行項目'}[name],
                                'not_checked','本次未完成此模組，不能將空白當成正常。',evidence=[ev('manifest.json',results.get(name,{'status':'not_selected'}))]))
            continue
        if 'checks' in data:
            checks.extend(data['checks'])
            for key in inventory: inventory[key].extend(data.get('inventories',{}).get(key,[]))
        elif name == 'system': checks.extend(mac_checks(data,metrics))
        elif name == 'browser': checks.extend(browser_checks(data,inventory,metrics))
        elif name == 'skills': checks.extend(skill_checks(data,inventory))
    usage = usage or {k:{'status':'unknown','source':'未提供經驗證的使用事件統計','items':[]} for k in ('skills','apps')}
    for key,category,label in [('skills','skills','Skills'),('apps','apps','程式')]:
        item=usage.get(key,{}); available=item.get('status')=='available'
        checks.append(check('usage.'+key,category,label+' 使用頻率與保留建議','review' if available else 'unknown',
                            '可依指定期間的實際聚合次數討論保留需求。' if available else '尚無可靠使用事件；無法判定常用或不常用。',
                            '沒有紀錄可能是未收集、工具未支援或期間不完整，不能當成零次。',
                            ['確認統計來源與涵蓋期間，再討論是否保留；不自動停用或刪除。'],
                            [ev('usage metadata',{k:v for k,v in item.items() if k!='items'})],terms=['usage','skill'] if key=='skills' else ['usage']))
    checks += [check('manual.privacy','apps','程式的高權限授權','not_checked','輔助使用、螢幕錄製、輸入監控等需另行核對系統介面。',
                     '高權限程式能看見或控制較多資料，應符合實際需要。', ['在系統隱私權設定查看已授權程式及用途；本工具未擴大讀取權限。'],terms=['permissions']),
               check('manual.accounts','system','帳號、多因素驗證與雲端分享','not_checked','這次本機檢查未登入外部帳號，也未檢視其登入裝置或分享權限。',
                     '本機設定正常，仍可能有帳號外洩或雲端公開分享問題。',['在另外授權的帳號檢查 MFA、陌生裝置、OAuth 與公開分享。'],terms=['mfa'])]
    aliases={'secureboot':'secure_boot','wifi_security':'wifi','app_inventory':'usage','app_permissions':'permissions','code_signature':'signature'}
    for item in checks:
        item['terms']=[aliases.get(term,term) for term in item.get('terms',[])]
        if 'wifi' in item['id'].lower():
            item['category']='devices'  # Matches the UI's Wi-Fi / Bluetooth group.
    requests=[{'id':'privacy','title':'程式的高權限授權','reason':'腳本沒有讀取系統隱私權資料庫，也未要求額外權限。',
               'request':'是否願意在系統隱私權設定查看螢幕錄製、輸入監控等清單，並只回覆不認識的程式名稱？',
               'alternatives':['可先略過，報告保留未檢查。','不需提供畫面內容、密碼或金鑰，也不需為本工具一律開啟完全磁碟存取。']},
              {'id':'backup','title':'確認備份方式與最近成功時間','reason':'本機中繼資料無法涵蓋所有外接、雲端或第三方備份。',
               'request':'是否使用其他備份工具？請提供工具名稱與最近成功日期即可。',
               'alternatives':['在備份程式內手動查看；不用提供備份檔案或登入憑證。','還原測試需另外確認要使用的非敏感測試檔。']},
              {'id':'script-scope','title':'其他腳本資料夾','reason':'只檢查預設／本次指定範圍，沒有遍歷整顆磁碟。',
               'request':'若還有需要檢查的腳本，請指定資料夾及是否同意唯讀掃描。',
               'alternatives':['不擴大範圍也可以完成本次報告。','不要將密碼、金鑰或私人文件資料夾當成腳本範圍。']}]
    if any(usage.get(k,{}).get('status')!='available' for k in ('skills','apps')):
        requests.append({'id':'usage','title':'常用程式與 skills 的使用頻率','reason':'沒有可靠的期間使用統計；目前清單無法用來推論不常用。',
                         'request':'是否有願意提供的聚合使用次數，包含來源與開始／結束時間？',
                         'alternatives':['沒有統計就維持未知，不要求建立追蹤。','可直接告訴助理哪些項目仍需要；人工回憶不會轉成精確事件次數。']})
    blocked=[c for c in checks if c['status'] in ('unknown','not_checked') and not c['id'].startswith(('usage.','manual.'))]
    if blocked:
        requests.append({'id':'blocked','title':'尚未取得的檢查資料','reason':'、'.join(c['title'] for c in blocked),
                         'request':'若要補查，請先選擇項目；助理會說明具體來源與最小必要權限，再詢問是否繼續。',
                         'alternatives':['先在系統設定手動確認並回覆開啟／關閉／不確定。','本工具不自動提升管理員權限、不繞過企業政策；未回覆就保留缺口。']})
    report = {'schema_version':'2.0','meta':{'title':'電腦資安健檢','version':'3.1.0','platform':'macOS' if manifest.get('platform')=='Darwin' else manifest.get('platform','macOS'),
            'observed_at':manifest.get('generated_at',now),'generated_at':now,'demo':demo,
            'scope_note':'一次性唯讀健檢。已收集不等於安全認證；沒有建立持續監控。報告含私人裝置資訊，請勿混入分享包。'},
            'checks':checks,'inventories':inventory,'usage':usage,'metrics':metrics,
            'glossary':[{'id':i,'term':t,'explanation':e} for i,t,e in GLOSSARY], 'scope':scope,
            'limitations':['圖表計算的是本報告檢查項目，不是整台電腦的安全百分比。',
                           'Wi-Fi 加密與藍牙連線狀態不能證明基地台可信或排除竊聽；不掃描附近網路。',
                           '短暫流量樣本不涵蓋歷史外洩；本工具不是防毒軟體或持續監控服務。',
                           '程式與 skill 清單不等於常用排名；使用率只有有來源的事件統計才會顯示。',
                           'Windows 系統命令須在 Windows 執行；發布包附測試紀錄，未通過實機驗證的部分如實標示。'],
            'access_requests':requests,'raw_modules':modules, 'manifest':manifest}
    return enrich_report(report,modules)


def render_html(report, template):
    data = json.dumps(report, ensure_ascii=False, allow_nan=False)
    for char, escaped in [('&','\\u0026'),('<','\\u003c'),('>','\\u003e'),('\u2028','\\u2028'),('\u2029','\\u2029')]:
        data=data.replace(char,escaped)
    if template.count('__REPORT_DATA__') != 1:
        raise ValueError('Expected exactly one report placeholder.')
    return template.replace('__REPORT_DATA__',data)
