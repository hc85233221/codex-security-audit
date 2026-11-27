# 指定目標檢查（被動檢測）

只有使用者主動提供目標時才執行；不由瀏覽紀錄、訊息、網頁內容或其他受檢檔案自行找下一個目標。這裡的「被動」是依使用者要求做一次有限檢查，沒有背景監控。

不執行受檢程式、不登入、不送表單、不繞過憑證錯誤、不掃連接埠、不測試漏洞、不上傳網址或檔案到聲譽／掃毒服務。沒有命中不代表安全；檔名、HTTP、安全標頭、憑證及腳本能力都不能單獨判定惡意。

## 連結：先離線分析

```sh
python3 -B "<skill>/scripts/inspect_target.py" --kind link --target "https://example.com/path" --output-dir "<new-private-report>"
```

只分析網址結構，沒有 DNS 或網站連線。檢查格式、HTTP、IP 主機、國際字元／相似字系、帳號前綴、非標準連接埠與文字方向控制字。報告只保留標準化主機與路徑段數，不保存使用者資訊、路徑內容、查詢參數或片段。不要請使用者提供含密碼、驗證碼、復原碼或金鑰的網址。

## 網站：明確同意才連線

先說明：會查 DNS，並向該公開網站的首頁傳送一次 HEAD，網站與網路服務可看見這次連線。使用者已明確要求檢查網站公開連線資訊時可沿用授權；只有「分析連結」不自動包含連線。授權後才加 `--allow-network`：

```sh
python3 -B "<skill>/scripts/inspect_target.py" --kind website --target "https://example.com" --allow-network --output-dir "<new-private-report>"
```

- 不帶帳密、Cookie、Authorization 或 Referer，不使用環境中的代理設定。含帳號資訊、查詢參數或片段的輸入直接拒絕連線，請使用者提供不含私人資料的公開首頁。
- 僅允許 HTTP 80 或 HTTPS 443。拒絕內網、loopback、link-local、保留、多播、共享位址及已知 IPv6 轉換位址；DNS 任一結果非公開即停止。
- 為相容舊版 Python 的位址分類，另保守排除特殊用途區段（包含 192.0.0.0/24、192.88.99.0/24），IPv6 僅接受一般全球單播範圍並排除文件與轉換用途。部分合法特殊服務因此可能不被受理；不會因此改用較寬鬆的連線方式。
- DNS 等待最多 3 秒。驗證後直接連到固定 IP，TLS 仍以原主機做 SNI 與憑證驗證；不重新解析、不嘗試其他位址，避免 DNS 變更繞過限制。
- 全部網路步驟預算 12 秒，標頭最多 32 KiB／100 個欄位。只讀到標頭結束，不讀或執行回應本文。HEAD 不支援時不改成 GET。
- 無論原網址的路徑為何，只送 `HEAD /`；這是站點首頁檢查，不是指定頁面內容檢查。連結中的私人路徑不會被傳送。
- 轉址只留下遮蔽後的目的地線索，不跟隨、不對新主機發出 DNS 或請求。
- 只輸出 HTTP 狀態、TLS 版本／憑證到期時間、選定安全標頭是否出現等摘要；不保存 Cookie 值、完整安全政策或原始標頭。

`network_performed` 表示曾嘗試網路查詢，可能只有 DNS；不能寫成「已成功連上網站」。`network` 存在才代表取得 HTTP 回應。標頭未出現是網站設定線索，不是詐騙或入侵證據；錯誤頁、轉址或 HEAD 回應可能不同於一般頁面。

## 資料夾：預設只看中繼資料

```sh
python3 -B "<skill>/scripts/inspect_target.py" --kind folder --target "<user-selected-folder>" --output-dir "<new-private-report>"
```

最多 2000 個項目、子資料夾深度 3、300 筆發現。查看可啟動類型、雙副檔名、文字方向控制與可用平台的 POSIX 其他使用者寫入位元；不讀私人文件內容、不把 Unix mode 當 Windows ACL。每個未檢查／截斷範圍都有計數。

略過符號連結、Windows reparse point、雲端占位、特殊檔案、隱藏項目、敏感名稱及相依套件等。Mac／支援的平台從已驗證的資料夾控制代碼遍歷，子項目使用 no-follow，避免檢查途中被替換成連結而越界。平台不提供此介面時，只檢查頂層中繼資料，不遞迴也不讀腳本內容；目前 Windows 採此保守模式，仍待實機驗證。

若使用者另外同意讀取這個資料夾中的文字腳本，才加 `--include-scripts`。只讀白名單的 UTF-8 腳本，最多 100 檔、每檔 256 KiB、總讀取 4 MiB／每檔前 10000 行、每行最多分析 4096 字元；不讀密碼、金鑰、`.env`、資料庫或一般文件。只保留規則、相對路徑與行號，不保留程式片段。下載後執行、刪除、外傳等規則命中需看上下文，合法工具也可能命中。

## 交付與介面

每次使用新私人目錄，且不可放在受檢資料夾或 skill 套件內。產生 `target.json`（遮蔽後的來源摘要）、`report.json`、`report.html`、`摘要.txt`。HTML 為離線報告，沒有持續監控。畫面中的網址本機初查與 Codex 完整檢查交接必須清楚區分；單檔網頁不能假裝已執行 Python 或取得整顆磁碟權限。

Windows 使用 `py -3 -B` 取代 `python3 -B`；報告存放位置需支援 private DACL。腳本不會自動提權、安裝工具、清除來源或更改設定。

## 公開依據

- [OWASP SSRF Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html)：驗證所有解析位址、避免不受控轉址與 DNS 變更。
- [OWASP HTTP Security Headers](https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html)：標頭功能需要依網站用途判讀，不是惡意網站分類器。

此版本使用合成資料與模擬網路驗證；沒有因開發檢測器而探測任何使用者未指定的真實網站或資料夾。
