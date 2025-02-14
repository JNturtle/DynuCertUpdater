# DynuCertUpdater

此專案使用 **Dynu v2 API** 以及 **Python ACME 函式庫** 進行動態 DNS 更新與 Let's Encrypt 憑證簽發。  
簽發成功後會輸出三份檔案：  
- `<Host>.key` (私鑰)  
- `<Host>.crt` (公鑰，含完整鏈)  
- `<Host>.pfx` (PKCS#12，使用者指定密碼加密)

## 功能特色

1. 介面化設定
   - 輸入 IP、Host、Base Domain (例如 `myhost.ddnsfree.com`)、Dynu API Key、Email 與 PFX 密碼。
2. 連動 Dynu v2 API
   - 若找不到指定 Domain，會自動建立並等待 5 秒再查詢一次。
   - 更新 Domain 的 `ipv4Address`。
3. ACME DNS-01 驗證
   - 於 Dynu 新增 `_acme-challenge.<domain>` 的 TXT 紀錄。
   - 提交 Challenge，完成後自動刪除 TXT。
4. 輸出三份憑證檔
   - `<Host>.key`：私鑰
   - `<Host>.crt`：公鑰（含完整鏈）
   - `<Host>.pfx`：PKCS#12 格式，內含私鑰與完整鏈，並以使用者輸入的密碼加密

## 安裝與執行

1. **下載或 clone 本專案**  
   ```bash
   git clone https://github.com/YourName/DynuCertUpdater.git
   cd DynuCertUpdater
