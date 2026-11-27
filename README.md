# 電腦資安健檢 · Codex Skill

**一個連結，交給 Codex 安裝。** Mac／Windows 唯讀檢查，附繁體中文互動報告。

## 安裝給 Codex

複製以下整段，貼到有本機檔案操作能力的 **Codex**：

```text
請使用 skill-installer 安裝這個 Skill：
https://github.com/hc85233221/codex-security-audit/tree/v3.1.0/mac-security-audit
只安裝，先不要開始健檢；若同名 Skill 已存在，先確認版本及自行修改的內容，不要直接覆蓋。
```

[開啟 v3.1.0 安裝來源](https://github.com/hc85233221/codex-security-audit/tree/v3.1.0/mac-security-audit) · [下載分享 ZIP](https://github.com/hc85233221/codex-security-audit/releases/download/v3.1.0/mac-security-audit-v3.1.0.zip)

連結由 Codex 下載並安裝；只在瀏覽器點開連結不會自動安裝。安裝完成後，在下一則訊息輸入：

```text
請使用 $mac-security-audit 唯讀健檢我的電腦，產生圖表報告。
不要修改設定或讀取密碼；需要額外權限或資料時，先說明原因並詢問我。
```

需要具備本機操作能力的 Codex，以及 **Python 3.9 以上**。Windows 另使用內建 PowerShell 5.1；缺少工具時會先說明，不會自行安裝或提權。

## 已安裝的人怎麼更新？

**不會自動更新。** 每次安裝是本機副本，固定版本連結會保留原版本。

請在 Codex 說：

```text
請從 https://github.com/hc85233221/codex-security-audit 檢查並更新我的 mac-security-audit Skill。
先核對目前版本與本機修改，保留舊版備份；有自行修改的內容時先詢問，不要直接覆蓋。
```

v3.1.0 起也可以說「使用 $mac-security-audit 檢查是否有新版」。只查版本不替換檔案；明確要求更新後才準備、核對與安裝。沒有背景自動更新或監控。

v3.0.0 使用者也可使用上面的完整指令，由 Codex 讀取 [更新流程](mac-security-audit/references/updating.md)，不需要先手動刪除舊版。

Windows 可查詢公開新版；自動準備與本機檔案比對尚未支援，更新會改走官方安裝工具下載至新資料夾，保留原版後再處理。

## 能看見什麼

- **優先處理事項**：備份、更新、加密、防火牆與登入設定，附來源、時間、改善方式。
- **電腦與 AI**：程式、背景服務、開機項目、排程、腳本、AI Skills、Wi-Fi 與藍牙摘要。
- **AI 設定與近期檔案**：查看限定設定、程式及工作流的風險線索，不執行內容。近期檔案不是 AI 來源證明；圖片、模型、壓縮檔及其他未讀內容另標示限制。
- **瀏覽器線索**：Cookie 中繼資料與擴充套件；不讀 Cookie 值、密碼或瀏覽歷史。
- **科技感報告**：深色介面、圖表、搜尋與篩選；專業名詞滑鼠移入／鍵盤聚焦／手機點按即可解釋。

報告為本機 `report.html`，雙擊即可離線開啟，支援列印／另存 PDF。安裝量、執行狀態、最近開啟與真正使用次數分開呈現；沒有可靠統計就標示未知。

## 被動檢測：你指定，才檢查

| 目標 | 實際執行範圍 |
| --- | --- |
| 連結 | 離線檢查網址結構，不開啟網站。 |
| 公開網站 | 明確授權後，只查首頁的 DNS、TLS 與單次 HEAD；不登入、不執行網頁程式、不跟隨轉址。 |
| 資料夾 | 預設檢查檔名與中繼資料；腳本文字需要另外明確授權。 |

面板的網站／資料夾功能會產生可複製給 Codex 的檢查需求。**貼回 Codex 並實際執行後才有結果**；不表示面板正在監控。

例如：

```text
請使用 $mac-security-audit，離線檢查這個連結：<網址>
```

```text
請使用 $mac-security-audit，唯讀檢查這個資料夾的檔名與權限：<資料夾路徑>
不要執行、刪除或上傳檔案。
```

## 檢查近期 AI 檔案

```text
請使用 $mac-security-audit 檢查近 14 天下載與 AI 生成檔案的資安線索。
先確認輸出資料夾；不執行、不上傳、不刪除檔案，不讀聊天、憑證或私人文件。
```

預設僅查看近期下載與明列 AI 設定；其他輸出資料夾由使用者指定。結果分開呈現設定、程式與工作流、只看中繼資料的檔案及未檢查內容，不把「未發現線索」當成安全保證。Windows 此新增模組採保守的中繼資料檢查。

## 隱私與限制

- 受檢設定與檔案保持唯讀，只建立新的本機報告。
- 不讀密碼、金鑰、復原碼、聊天內容或 Cookie 值；不自動刪除、停用、修復或設定監控。
- 不將檔案或網址送第三方掃毒服務。明確要求網站連線檢查時，網站可能記錄該次連線。
- 報告可能包含程式名稱與本機路徑；請保存在私人本機資料夾，不要上傳到公開儲存庫。讓 AI 分析摘要時，該 AI 服務仍會依其環境處理內容。
- 本工具整理風險線索，不是防毒認證、完整鑑識或安全保證；缺資料會標示待確認／未檢查。
- **Mac 已實機驗證；Windows 尚未實機驗證。** Windows 需支援 ACL 的本機固定磁碟來保護報告，覆蓋範圍與 Mac 不同。

本儲存庫與分享 ZIP 只包含通用 Skill 程式、介面及文件，不含建立者的私人健檢報告。

## 手動安裝與完整說明

下載 ZIP 後，將其中的 `mac-security-audit` 資料夾複製到 Codex 的 skills 目錄（預設 Mac 為 `~/.codex/skills/`，Windows 為 `%USERPROFILE%\.codex\skills\`）。若自訂 `CODEX_HOME`，使用該目錄下的 `skills`。已有同名 Skill 時先確認內容與備份，不直接覆蓋。

- [完整中文使用說明](mac-security-audit/使用說明.txt)
- [Skill 指令與範圍](mac-security-audit/SKILL.md)
- [驗證範圍](mac-security-audit/references/validation.md)
- [AI 檔案檢查範圍](mac-security-audit/references/ai-artifacts.md)
- [版本更新流程](mac-security-audit/references/updating.md)
- [Windows 平台差異](mac-security-audit/references/windows.md)
- [指定目標檢查](mac-security-audit/references/targeted-checks.md)
- [原始碼 SHA-256 清單](SHA256SUMS.txt)

本工具可供下載、安裝及個人電腦健檢使用。需要回報問題時，請先移除報告中的個人資料、路徑與裝置資訊；不要在公開 Issue 貼密碼、金鑰或完整私人報告。
