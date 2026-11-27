# 無線裝置、程式與使用統計

## 顯示什麼，如何判讀

- **Wi-Fi**：Mac 直接讀 CoreWLAN 的目前介面電源、安全類型和無線協定；不呼叫搜尋網路方法、不讀 Wi-Fi 名稱、基地台位址或密碼。Windows 的相應限制見 `windows.md`。WPA2／WPA3 是裝置與基地台之間的連線保護，不代表基地台可信、路由器最新或網站安全。若未取得有效連線指標，不能將安全類型 0 誤判成正在使用開放網路。
- **藍牙**：保留電源、可被探索狀態、已連線裝置名稱與未連線的已記錄條目數。裝置位址、序號、原始系統資訊不寫入報告。名稱不能證明身分；由使用者核對是否認得。唯讀查詢不會搜尋附近裝置、發起配對或解除配對。
- **程式清單**：Mac 最多盤點 300 個頂層 App 的名稱／版本，並以 NSWorkspace 取得目前有介面執行的程式。目錄、跳過與錯誤均記錄。背景服務、未列目錄、完整程式權限和軟體漏洞比對不在此盤點內；另由系統模組及人工補查處理。
- **常用程式、常用 skill**：本機快照無法推算使用頻率。存在、已安裝、啟用、目前執行、最近開啟日期、檔案修改時間與使用次數是不同的事。沒有可靠次數時，上方卡片改為「AI Skills 盤點」及「最近開啟的程式」，沒有開啟日期則顯示程式盤點；簡短註明使用次數未取得，不讓已有資料呈現為空白。技能來源分布只代表磁碟位置，不代表啟用狀態或可信程度；技能包與程式條目可能含同名不同來源或快取版本。

## 可選：匯入聚合使用統計

只有使用者已明確提供／授權的彙總 JSON 可作為使用次數來源；不要為填圖表讀取聊天紀錄、shell history、瀏覽紀錄、Screen Time 資料庫或其他私人活動歷史，也不要建立背景追蹤。此技能未發現或保證任何 AI 產品有通用的 skill 呼叫次數介面。

`usage_metrics.load_usage(path)` 驗證本機檔案後產出 dashboard 的 usage 區段；整合入口使用 `--usage-file` 指定。未提供檔案或未提供某類別時維持未知。

以下為**格式範例，並非任何人的實測結果**：

```json
{
  "schema_version": 1,
  "source": "使用者授權的事件彙總匯出",
  "period_start": "2026-10-01T00:00:00+08:00",
  "period_end": "2026-10-08T00:00:00+08:00",
  "skills": [
    {"name": "文件整理", "count": 12},
    {"name": "資安健檢", "count": 2}
  ],
  "apps": [
    {"name": "文書程式", "count": 18}
  ]
}
```

可由使用者自行從可信任工具匯出，或由已授權且有事件介面的工具只彙總名稱與次數；記錄實際來源與期間。手動填寫須在 source 清楚註明「使用者手動估計」，不能稱為已驗證事件。來源未核驗時報告會保留此限制。

資料規則：

- UTF-8 JSON，不超過 1 MiB；每類最多 1000 個不同名稱。
- 每筆只可有 `name`、`count`；次數必須為 0 至 1,000,000,000 的整數。skills 單位是呼叫次數，apps 單位是啟動次數，兩者都不是使用時數。
- source 和 name 只放簡短可辨識名稱，不放路徑、網址、電子郵件、憑證、逐筆事件、指令或私人內容。自動驗證不能辨識所有秘密，產生來源端也必須先做資料最小化。
- 期間需含時區、起點早於終點，終點不可在未來（容許 5 分鐘時鐘誤差）。資料是歷史期間就顯示原始期間，不能當作目前的即時狀態。
- 缺席的名稱不是使用零次。只有明列 `count: 0` 才顯示該名稱在提供期間內的零次；空清單表示來源提供空集合，不能證明所有程式都沒使用。
- 不依少用或零次自動刪除 skill／程式；清理需使用者另行指定，並確認相依性。

## 查詢來源

- Apple Core WLAN：<https://developer.apple.com/documentation/corewlan>
- Apple `CWSecurity` 列舉：<https://developer.apple.com/documentation/corewlan/cwsecurity>
- Apple `CWInterface.security()`：<https://developer.apple.com/documentation/corewlan/cwinterface/security()>
- Apple `NSWorkspace.runningApplications`：<https://developer.apple.com/documentation/appkit/nsworkspace/runningapplications>
- Apple 路由器與基地台建議：<https://support.apple.com/en-us/102766>
- Apple 系統資訊：<https://support.apple.com/guide/system-information/welcome/mac>

以上只提供公開查證連結；報告不載入外部資源、不自行上傳資料。
