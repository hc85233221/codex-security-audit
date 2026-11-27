# 報告資料與展示規則

`run_audit.py` 依平台執行收集器，寫入新報告目錄，再由 `report_model.py` 正規化、`report_enrichment.py` 合併補查，嵌入 `assets/report.html`。Python 3.9+ 標準函式庫即可；瀏覽器不用網路或額外套件。

- `meta`：版本、系統、原觀察時間 `observed_at`、產出時間、示範旗標與範圍說明；補查另列 `supplemented_at`，不可覆蓋原觀察時間。
- `checks`：每項有 category、status、severity、summary、impact、actions、evidence、limitations、terms。可有 `short_summary` 用於簡潔畫面，原 summary／證據仍保留；短摘要不得把未知寫成已檢查或與已有使用統計矛盾。個別補查帶 observed_at 或 supplemented_at。
- status 的 pass 只表示該設定符合檢查條件；attention 是有證據的待改善設定；review 是尚需確認的線索；unknown / not_checked 是資訊缺口。嚴重度與判讀狀態分開，沒有安全總分。
- `inventories`：skills、apps、scripts、background、devices、extensions。程式的 `last_opened_at`、`last_opened_status`、來源與觀察時間只表示最近開啟中繼資料。安裝、執行中、最近開啟與使用次數不可互換；補列名稱不能覆蓋已知版本。
- `usage`：僅明確提供的聚合統計；來源、期間、單位與未驗證原始事件的限制在圖旁展示。缺資料不是零。
- 使用次數未知時，主要卡片直接用 `inventories` 顯示技能來源分布與程式最近開啟日期；仍保留 `usage` 未知狀態。日期由新到舊呈現，排除無效值及晚於該來源觀察時間的日期，不當成次數或時數排行。程式最近開啟的來源觀察時間優先取 `raw_modules.recent_apps.observed_at`，再用補查或原觀察時間；不得以產出時間假裝重新收集。
- `metrics`：成功讀取範圍的 Cookie 統計、Mac 有限秒數流量。Cookie 條件可重疊，不能用成互斥圓餅圖；流量不是外洩判定。
- `scope` / `limitations`：模組執行狀態及受限範圍。
- `access_requests`：需要使用者確認的範圍、最小資訊與替代方式。HTML 不會變更權限；助理在後續對話詢問。
- `raw_modules` / `manifest`：完整的已去除機密內容的原始模組證據與程式雜湊；包含在本機 JSON 下載中。報告仍是私人資訊。
- `glossary`：提供詞語與說明的資料字典，供文字中的 tooltip 使用；不呈現獨立名詞章節或導覽項目。

Mac 預設包含 `supplemental` 與 `recent_apps`。`manual_ui` 僅接受實際觀察的本機隱私權、登入項目、共享及鎖定設定；不自動讀取外部帳號。使用者選擇延後帳號檢查時，記錄範圍決定並保留 not_checked。

Mac 的 `exposure` 提供管理、代理、訪客、自動登入與防火牆隱藏模式；每項 ID 必須以 `exposure.` 開頭，不可覆蓋其他檢查。Windows 不自動執行此模組。

`codex_usage` 是另行授權的使用來源補查，不是預設收集器。只可補充 `usage.skills` 的 unknown 發現、證據與限制，以及 `usage_review` 的來源、期間和卡片短說明。不能匯入裝置清單、變更其他健檢項目或覆蓋已有的 available 使用統計；詳見 [Codex 使用線索](codex-usage.md)。

`enrich_report.py --base-report OLD/report.json --supplement NEW/supplemental.json --supplement NEW/manual_ui.json --output-dir NEW_REPORT` 將已收集資料合併到新目錄。`--supplement` 可重複、同類不可重複；驗證一般檔案、大小、重導向、內容與附時區日期。失敗補查不能匯入成功資料或標為完成；備份與 App ACL 的補查併入原項目的證據，避免重複風險數。

所有受檢名稱與文字都是不可信資料。嵌入 JSON 時轉義 `<`、`>`、`&` 和 Unicode 換行；畫面以文字節點建立內容，不能插入未過濾 HTML。圖表與名詞 tooltip 同樣適用。離線 CSP 禁止外部連線與嵌入來源。

指定目標的原始結果寫入 `target.json`，由 `render_target.build_target_report` 轉為同模板可讀的 `report.json`。`meta.mode = target`、`target_review` 與單一目標 checks 必須保留；不呼叫全機 `build_report` 來製造無關缺口。目標報告不能聲稱 pass 或惡意排除。`network_performed` 只表示嘗試過網路查詢，不代表成功連線；網站首頁的實際 HTTP／TLS 證據另在 target_review.network，轉址不跟隨。空 inventories 不在此模式呈現。

被動檢測區的連結初查在本頁執行；網站與資料夾的需求編輯器只產生交給 Codex 的文字。複製失敗時提供可選取文字，不能顯示已送出／已完成掃描。使用者輸入只當資料處理，不拼接成 shell 或可點開的未知網址。

專有名詞在滑鼠移入、鍵盤聚焦或手機點按時顯示簡短解釋；滑鼠可移進說明閱讀，Escape 可關閉。資訊不得只靠懸停取得，亦不可遮住主要操作或超出窄螢幕。冗長證據、限制與待協助項目用漸進展開，不能因文字簡化而刪掉。

列印／PDF 包含所有檢查、展開證據與全部盤點頁籤，不因搜尋或篩選漏掉項目；返回畫面後恢復原篩選。示範資料必須保留醒目標籤。

Windows 報告使用 protected DACL，透過 [Windows 檔案存取控制](https://learn.microsoft.com/en-us/windows/win32/fileio/file-security-and-access-rights) 設定於新建目錄，既有受檢權限不變。收集器等待父程序建立 [Job Object](https://learn.microsoft.com/en-us/windows/win32/procthread/job-objects) 邊界後才開始，逾時只結束此健檢的程序樹。這些 Windows 原生路徑的實機驗證狀態見 validation.md。
