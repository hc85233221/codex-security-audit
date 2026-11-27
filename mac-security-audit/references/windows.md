# Windows 收集與判讀

適用本機 Windows 10／11，需既有 Python 3.9 以上與 Windows PowerShell 5.1。此版在 macOS 上完成解析邏輯、原生 API 結構、模擬權限不足、隱私與檔案測試；**尚未完成 Windows 實機驗證**。不要把示範報告當成任何人的實際 Windows 健檢結果。

由 `run_audit.py` 選擇 `inspect_windows.py`。預設以一般使用者執行；權限不足或不支援的項目保留「無法確認」。需要補查時先說明該項資料來源與所需權限，依 `SKILL.md` 的流程詢問授權；不得自行提升權限、變更 PowerShell 執行原則或防毒設定。

| 範圍 | 資料來源 | 判讀限制 |
|---|---|---|
| OS | `Win32_OperatingSystem` 的版本、組建、架構 | 不查使用者、序號或裝置 ID；版本可讀不代表仍受支援 |
| 防毒 | `Get-MpComputerStatus` 選定保護狀態、特徵資料年齡 | Defender 被動模式可能由第三方接手；不開始掃毒 |
| 防火牆 | `Get-NetFirewallProfile -PolicyStore ActiveStore` | 分別讀 Domain／Private／Public；未測外網可達性 |
| 磁碟加密 | `Get-BitLockerVolume` 僅輸出狀態、加密比例及磁碟代號 | 不存取或序列化 KeyProtector／RecoveryPassword；加密完成但保護暫停不能算通過 |
| 安全開機 | `Confirm-SecureBootUEFI` | 非管理員可能讀不到；讀不到不等於關閉 |
| 更新 | `Get-HotFix` 最近 20 筆選定欄位 | 非完整更新清單。Windows 下 `--check-updates` 仍只讀本機安裝紀錄，不執行更新搜尋或安裝 |
| 備份 | 人工待確認 | 不以 OneDrive 同步或安裝備份程式當成還原證明 |
| 自動啟動 | Run／RunOnce 指定登錄位置、非 Microsoft 排程 | 只輸出名稱與可辨認的執行檔，不輸出完整參數；未涵蓋所有持續執行技術 |
| 背景服務 | `Win32_Service` 名稱、狀態、啟動模式、程序 ID、可辨認的執行檔 | 最多 1,000 個；不讀服務帳號，不輸出完整參數，不啟動、停止或修復服務；模糊路徑保留未知 |
| 連線 | `Get-NetTCPConnection` 單次快照 | 只存綁定範圍、監聽埠與程序名稱，不存遠端位址；不測流量、不能回推歷史外洩 |
| 登入失敗 | Security 4625，近 7 天最多 1,001 筆取計數 | 不讀／輸出訊息本文。記錄政策、清除與保留期均影響覆蓋；失敗次數不等於攻擊次數 |
| 程式 | Uninstall 登錄清單、`Get-Process` 名稱快照 | 不使用會觸發 MSI 檢查／修復的 `Win32_Product`；安裝、執行、常用是不同概念 |
| Wi-Fi | WinRT `NetworkSecuritySettings`，只保留目前有連線狀態的 Wi-Fi | 只選取驗證／加密／連線類型；不讀設定檔內容或密碼、不記錄 SSID／BSSID／MAC、不呼叫可能跳出位置權限要求的 BSSID API |
| 藍牙 | Native Bluetooth API 的快取裝置清單 | `fIssueInquiry=false`，不搜尋附近裝置、不配對；僅傳統藍牙，不涵蓋 BLE，僅第一個無線電狀態 |
| 近期下載 | 預設 Downloads 最上層，最多 2,000 筆中繼資料、200 個線索 | 不追蹤 symlink／junction／reparse point，不讀檔、不解壓、不執行、不下載雲端內容；重導向下載位置未檢查 |

所有 PowerShell 查詢來自程式內固定片段、帶 `-NoProfile -NonInteractive`，每段 25 秒上限。原始錯誤訊息可能包含私人資料，因此只記錄錯誤類別。Windows 模組固定標記部分覆蓋，因備份、完整權限、BLE、歷史活動與真實常用排行仍需補查。

報告檔案需要放在僅使用者可讀的新目錄，應由主入口建立 Windows ACL。POSIX 的 `0600` 數字在 Windows 不足以證明存取控制；不要直接把模組輸出放在共用資料夾。Windows 帳號或公司政策可能限制建立私人目錄，失敗時應停止輸出私人報告，而不是聲稱已保護。

## Wi-Fi 與藍牙的白話說明

- **WPA2／WPA3**：電腦與 Wi-Fi 基地台之間的保護方式。WEP、TKIP 與舊 WPA 值得更新；現代加密不保證基地台本身可信。
- **OWE**：不輸入密碼也能加密連線，但無法憑此確認熱點身分。不要等同已驗證的私人網路。
- **可被探索**：附近裝置較容易找到這台電腦；不等於已被連入，也不代表有人成功配對。
- **已配對／已連線**：已配對表示留有信任關係，已連線表示現在使用；曾經配對不代表目前仍在傳輸。
- **背景服務**：沒有視窗也能運作的程式，例如更新、列印與備份。正在執行不代表使用者經常使用，也不等於惡意活動。
- **BLE**：低功耗藍牙，許多周邊會使用。這版的傳統藍牙清單無法代表全部 BLE 裝置。

## 官方依據

以下連結只供人工查閱，收集器與離線面板不會自動開啟或上傳資料：

- [Defender 狀態查詢](https://learn.microsoft.com/en-us/powershell/module/defender/get-mpcomputerstatus)
- [生效中的防火牆設定](https://learn.microsoft.com/en-us/powershell/module/netsecurity/get-netfirewallprofile)
- [BitLocker 磁碟狀態](https://learn.microsoft.com/en-us/powershell/module/bitlocker/get-bitlockervolume?view=windowsserver2025-ps)
- [安全開機與管理員權限限制](https://learn.microsoft.com/en-us/powershell/module/secureboot/confirm-securebootuefi)
- [Get-HotFix 的資料範圍](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/get-hotfix)
- [事件讀取與 FilterHashtable](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.diagnostics/get-winevent)
- [安裝程式盤點與 Win32_Product 的副作用](https://learn.microsoft.com/en-us/powershell/scripting/samples/working-with-software-installations)
- [Windows 服務狀態欄位](https://learn.microsoft.com/en-us/windows/win32/cimwin32prov/win32-service)
- [NetworkSecuritySettings 連線驗證與加密屬性](https://learn.microsoft.com/en-us/uwp/api/windows.networking.connectivity.networksecuritysettings)
- [目前可用連線清單與連線狀態篩選](https://learn.microsoft.com/en-us/uwp/api/windows.networking.connectivity.networkinformation.getconnectionprofiles)
- [Wi-Fi 驗證類型列舉](https://learn.microsoft.com/en-us/uwp/api/windows.networking.connectivity.networkauthenticationtype)
- [不使用會觸發位置權限要求的 BSSID API](https://learn.microsoft.com/en-us/windows/win32/nativewifi/wi-fi-access-location-changes)
- [藍牙快取查詢與 BLE 限制](https://learn.microsoft.com/en-us/windows/win32/api/bluetoothapis/nf-bluetoothapis-bluetoothfindfirstdevice)
- [禁止主動 inquiry 的查詢欄位](https://learn.microsoft.com/en-us/windows/win32/api/bluetoothapis/ns-bluetoothapis-bluetooth_device_search_params)
