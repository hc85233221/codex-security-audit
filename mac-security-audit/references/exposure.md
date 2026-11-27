# 裝置管理、代理與登入補查

`inspect_exposure.py` 目前只支援 Mac，補充 5 組有助核對用途的本機旗標。Windows 會回報 unsupported，不把 Mac 的設定或解讀套用過去。

| 項目 | 唯讀來源 | 如何判讀 |
| --- | --- | --- |
| 裝置管理 | `profiles status -type enrollment` | 只記錄 MDM 與自動註冊的 Yes／No；已註冊可能是合法公司管理，未註冊也不表示沒有其他描述檔。 |
| 系統代理 | `scutil --proxy` | 只保留明確 0／1 的啟用旗標；可能含多個 scope。未回報不是明確關閉。 |
| 訪客登入 | `defaults read /Library/Preferences/com.apple.loginwindow GuestEnabled` | 只接受明確 0／1；找不到該鍵、無權限及格式不符分開記錄。 |
| 自動登入 | 同一偏好網域的 `autoLoginUser` | 只保留值是否存在，捨棄帳號名稱。存在不保證仍生效，FileVault 與管理原則可能改變實際行為。 |
| 防火牆隱藏模式 | `socketfilterfw --getstealthmode` | 可減少回應部分探索請求，不等於網路匿名、外部不可達或完整入侵防護。 |

每個程序最多 8 秒，stdout＋stderr 合計最多 64 KiB；超出即停止該次自建程序，保留未知。固定命令不經 shell，不讀環境中的代理設定或完整系統偏好。收集結果不保留原始輸出、使用者帳號、MDM 伺服器、代理位址、PAC URL 或例外網域。

執行前建立新的私人報告目錄，再指定新檔案：

```sh
python3 -B "<skill>/scripts/inspect_exposure.py" --output "<private-report-directory>/exposure.json"
```

這些項目只是觀察到的設定與核對線索。代理或 MDM 啟用本身不是惡意證據；未註冊管理亦不是安全保證。不存在偏好鍵時，使用者可在「使用者與群組」手動確認，不以猜測補成 pass。沒有登入測試、連線測試、提權、改設定或新增監控。

## 已驗證範圍

合成測試涵蓋敏感輸出不留存、欄位白名單、scope 代理衝突、缺省與權限失敗區別、自動登入名稱移除、狀態解析、unsupported 不執行指令，以及程序時間／輸出上限。Mac 本機結果另外以實際觀察時間保存；不代表 Windows 實機驗證。

## 官方依據

- [Apple：裝置管理設定](https://support.apple.com/guide/mac-help/mh35474/mac)
- [Apple：網路代理設定](https://support.apple.com/guide/mac-help/mchlp2591/mac)
- [Apple：使用者與群組設定](https://support.apple.com/guide/mac-help/mtusr001/mac)
- [Apple：自動登入條件及 FileVault 限制](https://support.apple.com/102316)
- [Apple：防火牆隱藏模式](https://support.apple.com/guide/mac-help/mh17133/mac)

以上文件於 2026-11-16 核對；版本或介面位置可能變更。執行中只查本機，不把本機資料送往這些網站。
