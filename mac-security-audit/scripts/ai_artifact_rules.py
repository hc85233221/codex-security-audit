"""Bounded, non-executing AI configuration and generated-code review rules."""
import re

# Patterns return a rule and line number, never matching text or values.
RULES = (
    ('download_execute', '下載後立即執行', 'high',
     r'\b(?:curl|wget)\b[^\n]{0,1000}\|\s*(?:sudo\s+)?(?:bash|sh|zsh|python[\d.]*)\b|(?:Invoke-WebRequest|Invoke-RestMethod|DownloadString|\biwr\b|\birm\b)[^\n]{0,500}(?:Invoke-Expression|\biex\b)'),
    ('destructive_operation', '大量刪除或磁碟操作', 'medium',
     r'\brm\s+(?:-[A-Za-z]+\s+)*-[A-Za-z]*[rf][A-Za-z]*\b|\bshutil\.rmtree\s*\(|\b(?:diskutil\s+erase|mkfs|Format-Volume|Clear-Disk)\b|\bRemove-Item\b[^\n]{0,200}-(?:Recurse|Force)\b'),
    ('validation_bypass', '略過連線或來源驗證', 'medium',
     r'\bverify\s*=\s*False\b|\b(?:curl|wget)\b[^\n]{0,120}(?:--insecure|--no-check-certificate)|\bxattr\b[^\n]{0,160}-[a-z]*d[a-z]*\s+com\.apple\.quarantine'),
    ('dynamic_execution', '動態執行或混淆內容', 'medium',
     r'\b(?:eval|exec)\s*\([^\n]{0,400}(?:atob|b64decode|fromhex)|(?:atob|b64decode|fromhex)[^\n]{0,400}\b(?:eval|exec)\s*\(|\bsubprocess\.[a-z_]+\([^\n]{0,400}shell\s*=\s*True'),
    ('credential_access', '可能存取憑證來源', 'medium',
     r'\.aws[/\\]credentials|\.ssh[/\\]id_(?:rsa|ed25519|ecdsa)|\bsecurity\s+find-(?:generic|internet)-password|[\x22\x27/]\.env(?:[\x22\x27/\s.]|$)|\bauth\.json\b'),
    ('data_submission', '含資料傳送能力', 'low',
     r'\b(?:requests|httpx|session|client)\.(?:post|put|patch)\s*\(|\bcurl\b[^\n]{0,300}(?:--data|--upload-file|\s-F\s)|\b(?:navigator\.sendBeacon|XMLHttpRequest)\b|\bmethod\s*:\s*[\x22\x27](?:POST|PUT|PATCH)[\x22\x27]'),
    ('instruction_override', '含指令覆寫或隱瞞操作文字', 'medium',
     r'\b(?:ignore|disregard|override)\s+(?:(?:all|any|the)\s+)?(?:previous|prior|system|developer)\s+(?:instructions?|prompts?|rules?)|\b(?:do not|don\x27t|never)\s+(?:tell|inform|notify)\s+(?:the\s+)?user|\b(?:bypass|skip)\s+(?:all\s+)?(?:approval|confirmation|permission)\b|忽略(?:所有|之前|先前|系統|開發者).{0,12}(?:指令|規則)|(?:不要|不得)告訴使用者'),
    ('possible_embedded_secret', '疑似內嵌敏感憑證', 'high',
     r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----|\bAKIA[0-9A-Z]{16}\b|\bgh[pousr]_[A-Za-z0-9]{30,}\b|\bsk-(?:proj-)?[A-Za-z0-9_-]{32,}\b|\b(?:api[_-]?key|access[_-]?token|client[_-]?secret|password)\s*[\x22\x27]?\s*[:=]\s*[\x22\x27][A-Za-z0-9_+/=-]{20,}[\x22\x27]'),
    ('browser_active_content', '網頁或向量圖含主動執行內容', 'low',
     r'<script\b|\bon(?:load|error|click)\s*=|javascript\s*:|<foreignObject\b|<iframe\b'),
    ('unsafe_deserialization', '載入可包含程式的序列化資料', 'medium',
     r'\b(?:pickle|dill|joblib)\.loads?\s*\(|\btorch\.load\s*\(|\byaml\.load\s*\('),
    ('security_widening', '放寬系統防護或檔案寫入權限', 'medium',
     r'\bchmod\b[^\n]{0,160}(?:\b0?777\b|\b[ao]\+w\b)|\b(?:spctl\s+--(?:master|global)-disable|csrutil\s+disable)|\bSet-MpPreference\b[^\n]{0,150}-Disable'),
)
CONFIG_RULES = (
    ('broad_approval', '設定可能略過逐次確認', 'medium',
     r'[\x22\x27]?(?:approval_policy|approvalMode|defaultMode)[\x22\x27]?\s*[:=]\s*[\x22\x27](?:never|bypassPermissions|dontAsk)[\x22\x27]|\b(?:dangerouslySkipPermissions|skipDangerousModePermissionPrompt)\b[\x22\x27]?\s*[:=]\s*true'),
    ('broad_sandbox', '設定可能允許廣泛本機存取', 'medium',
     r'[\x22\x27]?(?:sandbox_mode|sandboxMode)[\x22\x27]?\s*[:=]\s*[\x22\x27](?:danger-full-access|unrestricted)[\x22\x27]|[\x22\x27](?:allowedTools|allow)[\x22\x27]\s*:\s*\[[^\n]{0,200}[\x22\x27]\*[\x22\x27]'),
    ('plain_http_endpoint', '設定含未加密 HTTP 端點', 'medium', r'\bhttp://[^\s\x22\x27<>]+'),
    ('all_interface_listener', '設定含接受其他網路介面的線索', 'medium', r'\b0\.0\.0\.0\b|\[::\]|[\x22\x27]::[\x22\x27]|[\x22\x27]--listen[\x22\x27]'),
    ('mcp_shell_command', 'AI 工具設定可啟動命令或下載套件', 'low',
     r'[\x22\x27]?command[\x22\x27]?\s*[:=]\s*[\x22\x27](?:[^\x22\x27\n]{0,200}[/\\])?(?:bash|sh|zsh|cmd(?:\.exe)?|powershell(?:\.exe)?|pwsh(?:\.exe)?|npx|uvx)[\x22\x27]'),
)
COMPILED = [(rule, title, severity, re.compile(pattern, re.I)) for rule, title, severity, pattern in RULES]
CONFIG_COMPILED = [(rule, title, severity, re.compile(pattern, re.I)) for rule, title, severity, pattern in CONFIG_RULES]
NEGATION = re.compile(r'\b(?:never|avoid|forbid|prohibit|do not|must not|should not)\b|不得|不要|禁止|不可|不能|不應|勿|避免', re.I)
EXAMPLE = re.compile(r'\b(?:example|sample|test|fixture)\b|例如|範例|示例|測試', re.I)


def scan_lines(text, is_config=False, max_lines=10000, max_line_length=4096, max_findings=120):
    """Return bounded indicators. Do not return snippets, URLs, tokens or commands."""
    lines = text.splitlines()
    truncated = len(lines) > max_lines or any(len(x) > max_line_length for x in lines[:max_lines])
    result = []
    rules = COMPILED + (CONFIG_COMPILED if is_config else [])
    for number, original in enumerate(lines[:max_lines], 1):
        line = original[:max_line_length]
        for rule, title, severity, pattern in rules:
            if pattern.search(line):
                tags = []
                if line.lstrip().startswith(('#', '//', '<!--')): tags.append('comment_context')
                if NEGATION.search(line): tags.append('negation_context')
                if EXAMPLE.search(line): tags.append('example_context')
                result.append({'rule': rule, 'title': title, 'line': number, 'severity': severity,
                               'status': 'review_signal', 'context_tags': tags, 'source_excerpt': 'omitted'})
                if len(result) >= max_findings:
                    return result, True
    if any(x['rule'] == 'credential_access' for x in result) and any(x['rule'] == 'data_submission' for x in result):
        if len(result) < max_findings:
            result.append({'rule': 'credential_and_transfer', 'title': '同檔案同時出現憑證存取與傳送能力',
                           'line': None, 'severity': 'high', 'status': 'review_signal',
                           'context_tags': ['file_level_cooccurrence_only'], 'source_excerpt': 'omitted'})
    return result, truncated
