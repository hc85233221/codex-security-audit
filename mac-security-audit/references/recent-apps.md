# 程式最近開啟線索

Mac 收集器 `inspect_recent_apps.py` 僅查 `/Applications` 與 `~/Applications` 的頂層 App，最多 300 個。它只向 `mdls` 指定 `kMDItemLastUsedDate`，不讀文件、聊天、瀏覽紀錄、原始活動流、`kMDItemUsedDates` 或 `kMDItemUseCount`。

Apple 的定義是：由 LaunchServices 開啟檔案時更新的時間。因此這是「系統記錄的最近開啟」，不能代表前景使用時數、持續活躍或期間使用頻率；未提供值也不能說沒用過。

畫面可顯示最近開啟欄位與觀察時間，但 `usage.apps.status` 仍須保持 unknown，除非另有已授權、具來源及開始／結束時間的聚合統計。不能從開啟時間或清單缺席推論應刪除。

未遞迴；符號連結／reparse point 略過。每個查詢最多 1.5 秒、四個並行，總查詢預算 45 秒；受限項目保留 unknown。Windows 不套用 Spotlight 指令。

來源：[Apple Spotlight Metadata Attributes — kMDItemLastUsedDate](https://developer.apple.com/library/archive/documentation/CoreServices/Reference/MetadataAttributesRef/Reference/CommonAttrs.html)。本機資料與報告不會送往此網站。
