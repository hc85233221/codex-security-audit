# 檢查與更新 Skill

GitHub 的發布與每個人的本機安裝是分開的。固定標籤（例如 `v3.0.0`）不會跟著 `main` 改變；即使從 `main` 安裝，之後也不會自動同步。本 Skill 沒有背景更新服務，健檢本身不會偷偷連線更新。

使用者可以對 Codex 說：

> 請檢查資安健檢 Skill 有沒有新版。

> 請更新資安健檢 Skill，保留舊版備份；如果我有自行修改，先告訴我差異。

第一句只查詢，第二句授權準備及完成一般更新；不要再為相同且未變動的授權重複詢問。本機自行修改、來源不符或權限不足時，先說明具體問題，保留現況，請使用者決定。

## 只檢查

先告知會連到這個工具的 GitHub 公開版本資料，不傳送本機檔案、帳號憑證或健檢報告：

```sh
python3 -B "<installed-skill>/scripts/check_update.py" --check
```

Windows 改成 `py -3 -B`。輸出本機版本、最新正式版、固定標籤及解析後的 commit。`local_newer` 代表本機較新，不能自動降版；`local_version_unknown` 代表沒有可靠本機版號，不假設為最新版或舊版。

固定來源為 `hc85233221/codex-security-audit`，不接受使用者或網頁提供的任意更新主機。網路失敗／API 限流就是無法確認，不當成沒有更新，也不要求登入、提供 token 或擴大權限。

## 使用者要求更新時

```sh
python3 -B "<installed-skill>/scripts/check_update.py" --prepare --output-dir "<new-private-staging-directory>"
```

此命令只準備候選檔案，**尚未更新安裝版**。輸出必須是已存在本機父資料夾中的新資料夾；不自動建立一整串未確認的父路徑。它將正式標籤解析到 commit 後下載，檢查壓縮檔路徑、重複項目、大小／數量上限、特殊檔案、Skill 入口與全部原始碼 SHA-256。候選程式不會被匯入或執行。結果存於 `prepared-update.json`；候選資料夾是 `candidate/mac-security-audit`。

檢查 `local_modifications`：

- `matches_published_version`：已與本機所稱版本的公開原始檔逐一比對，沒有修改／缺少／額外檔案。
- `local_changes`：列出修改、缺少或額外檔名，不讀額外檔案的內容。不要覆蓋，先問要保留／合併哪些修改。
- `unverified`：來源基準、讀取權限或安全檔案比對能力不足，不能推論「未修改」。保留舊版，說明原因與人工替代。

只有 `replacement_eligible=true`、使用者已明確要求更新、且候選差異仍符合此 Skill 的原用途時，Codex 才繼續：

1. 檢視候選與舊版的程式差異，確認沒有新增非預期服務、憑證要求、監控或外傳。下載來源相同與 checksum 相符只證明一致性，不保證程式安全。
2. 把目前 Skill 完整備份到 **skills 目錄之外**的私人本機資料夾。不要備份／覆蓋使用者健檢報告，也不要自行清除舊備份。
3. 替換前重新比對舊版與 `baseline_commit`，確認檢查期間沒有人修改檔案；重新核對候選與 `candidate_sha256`。任何差異就停止，不使用 `--force`。
4. 用安全的檔案操作在安裝目錄的同一個檔案系統準備候選，拒絕 symlink／junction／reparse point；將舊資料夾重新命名留存，再將候選資料夾重新命名到原安裝路徑。兩次重新命名不是完整交易；若第二步失敗，恢復原資料夾，不留下半套混合版本。不要逐檔覆寫正在使用的 Skill。
5. 確認安裝路徑的所有檔案、版本與候選校驗碼一致，並確認原備份仍在。成功後告知新版本與備份位置；新指令可在下一則訊息使用。更新不會重跑健檢、修改系統防護或重寫舊報告。

不要從候選內執行「自行安裝／更新」腳本來繞過上述確認；本 helper 刻意沒有自動覆蓋或自動執行新程式的功能。

Windows 可查詢公開最新版，但目前 helper 缺少同等安全目錄控制代碼能力，本機版號保持未知，`--prepare` 會拒絕寫入。不要把未知當作未修改；保留原資料夾，改用 Codex 既有官方 skill-installer 下載到使用者指定的新資料夾，或提供分享 ZIP 讓使用者在已備份後手動安裝。不得聲稱 helper 已完成 Windows 檔案比對、候選準備或替換；Windows 原生更新流程尚未實機驗證。

## 從 v3.0.0 第一次升級

v3.0.0 沒有更新 helper。朋友可把下面的穩定入口貼給 Codex：

> 請從 https://github.com/hc85233221/codex-security-audit/releases/latest 找最新正式版，更新我的 mac-security-audit；先下載到新資料夾、確認來源並備份舊版。有自行修改時先詢問，不直接覆蓋。

Codex 應使用既有 `$skill-installer`，以該次已核對的標籤 URL 和 `--dest <new-staging-directory>` 安裝到暫存處；不要直接安裝到已存在的正式位置。讀取候選的更新流程後，使用 **已審閱**的 helper 加上 `--installed-skill <old-skill>`、`--baseline-version 3.0.0` 進行準備；這個版號只是待驗證的基準，不會略過完整比對。若使用者不確定舊版，保持未知並先確認。

不要把原本固定版本的 `v3.0.0` 標籤移動到新版。保留舊連結讓朋友能重現同一版本；最新正式版的發現入口使用 Releases/latest。

## 驗證範圍

更新 helper 的測試使用模擬 GitHub 回覆與合成 ZIP，涵蓋不同版本、同版／降版阻擋、固定來源、標籤解析、檔案雜湊、symlink／特殊檔案、重複路徑、壓縮／數量上限、本機改動與候選寫入。實際 Mac 發布版安裝可另行試驗；模擬測試不是 Windows 實機驗證，也不是供應鏈安全認證。
