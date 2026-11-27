# 本機補查

`inspect_supplemental.py` 僅適用 Mac，可單獨執行 `--home PATH --output NEW_FILE`。輸出目錄應先由主入口建立私人權限；不覆蓋已有報告。

- **備份狀態**：只用 `tmutil status` 與 `destinationinfo`，保留是否執行、目的地種類／數量，不保存名稱、URL、路徑或識別碼。沒有執行中的備份不表示沒有備份。
- **最近成功時間**：不要為補資料自動執行 `tmutil latestbackup`。即使沒有 `-m`，實測系統仍可能嘗試掛載目的地。改在 Time Machine 或使用者指定的備份程式介面查看；不掛載、不開始備份、不改排程。
- **其他備份工具**：只查看標準程式目錄中的常見備份、同步工具名稱。安裝了工具不證明成功備份，未找到也不能排除其他工具或手動備份。
- **App ACL**：對標準程式目錄中頂層 world-writable 項目，最多 20 個，用 `ls -lde` 補查 ACL；不做實際寫入測試，不保留 ACL 中的帳號名稱。頂層權限不能外推到每個套件內檔案。
- **程式清單缺口**：最多每個標準目錄 300 筆，針對缺少、非標準或不可安全讀取的 Info.plist，僅以資料夾名稱補列程式。版本、啟用與來源未確認；不追蹤連結或執行啟動器。

資料來源可能受版本或權限限制。需要額外資訊時，先告知原因與最小必要範圍，再詢問使用者；不能把保留未知改成通過。

Apple 說明：[Time Machine 備份](https://support.apple.com/en-ie/104984)、[還原單一項目](https://support.apple.com/guide/mac-help/restore-files-mh11422/mac)。成功紀錄與還原驗證是不同證據。
