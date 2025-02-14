# DynuCertUpdater
此專案使用 **Dynu v2 API** 以及 **Python ACME 函式庫** 進行動態 DNS 更新與 Let's Encrypt 憑證簽發。  
簽發成功後會輸出三份檔案：  
- `<Host>.key` (私鑰)  
- `<Host>.crt` (公鑰，含完整鏈)  
- `<Host>.pfx` (PKCS#12，使用者指定密碼加密)

簡單操作產生公共機構簽署的憑證與DDNS，方便練習以HTTPS網站部署與網路驗證。
dynu免費註冊並使用DDNS，個人體驗相比DuckDNS穩定性更高！
請先在https://www.dynu.com註冊帳號，並在API Credentials複製API Key。

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
   ```
	或是直接下載 fetch.py 與 main.py 即可 
3. 安裝相依套件
	-	若你使用 vendor 方式（vendor/ 資料夾已附帶套件），則可直接執行，不需安裝。
	-	否則請在系統安裝 Python 3.7+，並執行：
	-	或使用 fetch.py 下載並解壓縮至 vendor/（請參考 fetch.py 說明）。
4. 執行程式
	-	第一次執行 main.py 後會產生 config.json，在介面中輸入：
		-	IP：要更新到 Dynu 的 IPv4
		-	Host + Base Domain（例如 myhost + ddnsfree.com -> myhost.ddnsfree.com）
		-	Dynu API Key（於 Dynu 後台取得）
		-	Email（預設 example@yourdomain.com）
		-	PFX 密碼（可留空，則產生無密碼的 .pfx）
	-	按下「更新並簽發憑證」後程式會：
   	1.	連動 Dynu v2 API 查詢或建立 Domain，並更新其 IPv4。
   	2.	進行 ACME DNS-01 驗證，於 Dynu 新增 _acme-challenge.<domain> TXT。
   	3.	驗證成功後，輸出 <Host>.key, <Host>.crt, <Host>.pfx 三份檔案。
   	4.	刪除 TXT 紀錄。
