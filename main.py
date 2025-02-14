#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
DynuLEUpdater.py (API v2) - 無 username/password，改以 API Key 驗證

這是一個以 Python + Tkinter 建立的範例程式，示範如何使用 Dynu 的 REST API（v2）更新動態 DNS。
與舊的 `https://api.dynu.com/nic/update?` 方式不同，這裡改用 API v2 的方式：
  1. 取得/建立指定的 domain (host + base_domain)。
  2. 更新該 domain 的 ipv4Address。
  3. 呼叫 certbot 以 DNS 驗證自動產生憑證，產出檔案命名為 Host.pem。

特點：
  - 移除舊版 username/password 輸入，改為輸入 Dynu API Key。
  - 設定檔 config.json 中只會儲存 IP、Host、Base Domain、以及 api_key。
  - 產生憑證時，預設使用一個固定的 certbot email（可自行改寫）。
  - 若該 domain 在 Dynu 尚未建立，程式會自動呼叫 POST /v2/dns 建立之。
  - 僅示範更新整個 domain 的 A 紀錄，若要更新子域名可使用 /v2/dns/record/...。
  - DNS-01 驗證需準備 dynu_auth_hook.sh / dynu_cleanup_hook.sh（可參考官方文件自行撰寫）。

請先在 Dynu 後台 (Control Panel -> API Credentials) 建立 API Key，然後在程式介面輸入。
"""
"""
Dynu + ACME Python Example
--------------------------
1. 使用 Dynu v2 API 透過 API Key 來建立/查詢 domain 並更新其 IPv4。
2. 若找不到 domain，嘗試建立並等待10秒後再次查詢，若仍找不到則跳出錯誤。
3. 使用 Python ACME 函式庫進行 DNS-01 驗證，自動在 Dynu 上新增/刪除 _acme-challenge.<domain> 的 TXT 記錄。
4. 憑證簽發成功後，會將檔案存為 <Host>.pem。
5. 移除舊版 username/password 輸入，改用 Dynu API Key。
6. 僅示範一次性簽發，不含續期邏輯。
"""
"""
main.py
-------
1. 以 Dynu v2 API + API Key 查詢/建立 Domain，並更新其 IPv4。
2. 使用 Python ACME 函式庫 (acme) 進行 DNS-01 驗證並簽發憑證。
3. 若找不到 domain，先建立後等待 10 秒再查詢，若仍失敗則中止。
4. 簽發成功後，將憑證寫入 <Host>.pem。
"""
"""
main.py
-------
1. 在程式開頭將 vendor/ 資料夾加到 sys.path。
2. 使用 Dynu v2 API (API Key) 查詢/建立 Domain 並更新其 IPv4。
3. 若找不到 domain，先建立後等待10秒再查詢，若仍找不到則中止。
4. 使用 Python ACME 函式庫進行 DNS-01 驗證並簽發憑證，將私鑰+fullchain 寫入 <Host>.pem。
5. 刪除 TXT 記錄時，若 404 表示該記錄已不存在，則忽略。
"""
"""
main.py
-------
1. 在程式開頭將 vendor/ 資料夾加到 sys.path。
2. 使用 Dynu v2 API (API Key) 查詢/建立 Domain 並更新其 IPv4。
3. 若找不到 domain，先建立後等待10秒再查詢，若仍找不到則中止。
4. 使用 Python ACME 函式庫進行 DNS-01 驗證並簽發憑證。
5. 輸出三個檔案：
   - <Host>.key (私鑰)
   - <Host>.crt (公鑰，含完整鏈)
   - <Host>.pfx (PKCS#12，包含私鑰與完整鏈，需使用者輸入的密碼加密)
6. 刪除 TXT 紀錄時，若 404 表示該記錄已不存在，則忽略。

注意：
- 本程式為示範，不含自動續期與完整錯誤處理。
- 若想免安裝套件，可考慮 vendor 或 PyInstaller 打包。
"""
"""
main.py
-------
1. 在程式開頭將 vendor/ 資料夾加到 sys.path（若有使用 vendor 方式）。
2. 使用 Dynu v2 API (API Key) 查詢/建立 Domain 並更新其 IPv4。
3. 若找不到 domain，先建立後等待 5 秒再查詢，若仍找不到就中止。
4. 介面新增 Email 輸入框（預設 example@yourdomain.com）。
5. 使用 Python ACME 函式庫進行 DNS-01 驗證並簽發憑證，輸出三份檔案：
   - <Host>.key (私鑰)
   - <Host>.crt (公鑰，含完整鏈)
   - <Host>.pfx (PKCS#12，需密碼)
6. 刪除 TXT 記錄時，若 404 表示已不存在則忽略。
"""

import sys
import os

# 若有 vendor/ 資料夾放相依套件，則加到 sys.path
script_dir = os.path.dirname(os.path.abspath(__file__))
vendor_dir = os.path.join(script_dir, 'vendor')
if os.path.isdir(vendor_dir):
    sys.path.insert(0, vendor_dir)

import json
import time
import threading
import tkinter as tk
from tkinter import ttk

import requests
import josepy
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import pkcs12, BestAvailableEncryption, NoEncryption
from cryptography import x509

from acme import client, messages, challenges, crypto_util

# Let's Encrypt 正式環境 (若要使用 Staging，可改 URL)
ACME_DIRECTORY_URL = "https://acme-v02.api.letsencrypt.org/directory"

CONFIG_FILE = "config.json"

BASE_DOMAINS = [
    "accesscam.org",
    "camdvr.org",
    "casacam.net",
    "ddnsfree.com",
    "ddnsgeek.com",
    "freeddns.org",
    "giize.com",
    "gleeze.com",
    "kozow.com",
    "loseyourip.com",
    "mywire.org",
    "ooguy.com",
    "theworkpc.com",
    "webredirect.org"
]

class DynuAcmeApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Dynu + ACME (Python) - Key/CRT/PFX")
        self.geometry("600x500")
        self.create_widgets()
        self.load_config()

    def create_widgets(self):
        frame = ttk.Frame(self)
        frame.pack(padx=10, pady=10, fill="x", expand=True)

        # IP
        ttk.Label(frame, text="IP 位址:").grid(row=0, column=0, sticky="w")
        self.ip_entry = ttk.Entry(frame)
        self.ip_entry.grid(row=0, column=1, sticky="ew")

        # Base Domain
        ttk.Label(frame, text="Base Domain:").grid(row=1, column=0, sticky="w")
        self.base_domain_var = tk.StringVar()
        self.base_domain_cb = ttk.Combobox(
            frame,
            textvariable=self.base_domain_var,
            values=BASE_DOMAINS,
            state="readonly"
        )
        self.base_domain_cb.grid(row=1, column=1, sticky="ew")
        self.base_domain_cb.current(0)

        # Host
        ttk.Label(frame, text="Host:").grid(row=2, column=0, sticky="w")
        self.host_entry = ttk.Entry(frame)
        self.host_entry.grid(row=2, column=1, sticky="ew")

        # Domain 預覽
        self.domain_label = ttk.Label(frame, text="完整域名: ")
        self.domain_label.grid(row=3, column=0, columnspan=2, sticky="w", pady=(5,5))
        self.host_entry.bind("<KeyRelease>", self.update_domain_preview)
        self.base_domain_cb.bind("<<ComboboxSelected>>", self.update_domain_preview)

        # Dynu API Key
        ttk.Label(frame, text="Dynu API Key:").grid(row=4, column=0, sticky="w")
        self.api_key_entry = ttk.Entry(frame, show="*")
        self.api_key_entry.grid(row=4, column=1, sticky="ew")

        # Email
        ttk.Label(frame, text="申請憑證 Email:").grid(row=5, column=0, sticky="w")
        self.email_entry = ttk.Entry(frame)
        self.email_entry.grid(row=5, column=1, sticky="ew")

        # PFX Password
        ttk.Label(frame, text="PFX 密碼:").grid(row=6, column=0, sticky="w")
        self.pfx_pass_entry = ttk.Entry(frame, show="*")
        self.pfx_pass_entry.grid(row=6, column=1, sticky="ew")

        # 按鈕
        self.start_button = ttk.Button(frame, text="更新並簽發憑證", command=self.on_start)
        self.start_button.grid(row=7, column=0, columnspan=2, pady=10)

        # 進度顯示
        self.log_text = tk.Text(self, height=16)
        self.log_text.pack(padx=10, pady=10, fill="both", expand=True)

        frame.columnconfigure(1, weight=1)

    def update_domain_preview(self, event=None):
        host = self.host_entry.get().strip()
        base = self.base_domain_var.get().strip()
        domain = f"{host}.{base}" if host and base else ""
        self.domain_label.config(text=f"完整域名: {domain}")

    def load_config(self):
        if os.path.exists(CONFIG_FILE):
            try:
                with open(CONFIG_FILE, "r", encoding="utf-8") as f:
                    cfg = json.load(f)
                self.ip_entry.insert(0, cfg.get("ip", ""))
                self.host_entry.insert(0, cfg.get("host", ""))
                bd = cfg.get("base_domain", BASE_DOMAINS[0])
                if bd in BASE_DOMAINS:
                    self.base_domain_var.set(bd)
                self.api_key_entry.insert(0, cfg.get("api_key", ""))
                # 預設 Email
                default_email = cfg.get("email", "example@yourdomain.com")
                self.email_entry.insert(0, default_email)

                self.log("設定檔已載入。")
            except Exception as e:
                self.log(f"讀取設定檔失敗: {e}")
        else:
            self.log("尚未發現設定檔。")

        # 載入後刷新完整域名
        self.update_domain_preview()

    def save_config(self):
        cfg = {
            "ip": self.ip_entry.get().strip(),
            "host": self.host_entry.get().strip(),
            "base_domain": self.base_domain_var.get().strip(),
            "api_key": self.api_key_entry.get().strip(),
            "email": self.email_entry.get().strip() or "example@yourdomain.com"
        }
        try:
            with open(CONFIG_FILE, "w", encoding="utf-8") as f:
                json.dump(cfg, f, ensure_ascii=False, indent=2)
            self.log("設定檔已儲存。")
        except Exception as e:
            self.log(f"儲存設定檔失敗: {e}")

    def log(self, msg):
        self.log_text.insert(tk.END, msg + "\n")
        self.log_text.see(tk.END)

    def on_start(self):
        self.start_button.config(state="disabled")
        self.save_config()
        threading.Thread(target=self.run_process, daemon=True).start()

    def run_process(self):
        try:
            ip = self.ip_entry.get().strip()
            host = self.host_entry.get().strip()
            base = self.base_domain_var.get().strip()
            api_key = self.api_key_entry.get().strip()
            email = self.email_entry.get().strip() or "example@yourdomain.com"

            if not (ip and host and base and api_key):
                self.log("請確定 IP、Host、BaseDomain 與 API Key 都已填寫。")
                return

            domain = f"{host}.{base}"

            # Step 1: 透過 Dynu API 查詢/新增 domain
            self.log(f"【步驟 1】嘗試查詢或建立 {domain} ...")
            domain_id = self.get_or_create_domain(domain, ip, api_key)
            if domain_id is None:
                self.log("無法取得或建立該 domain，請檢查輸入。")
                return

            self.log(f"已取得或建立 domainId={domain_id}，開始更新 IP={ip} ...")
            if not self.update_domain_ip(domain_id, ip, api_key):
                self.log("更新 IP 時發生錯誤，結束。")
                return
            self.log("Dynu DDNS 更新成功 (API v2)。")

            # Step 2: 進行 ACME DNS-01 驗證並簽發憑證
            self.log("【步驟 2】開始進行 ACME DNS-01 驗證並簽發憑證 ...")
            pfx_password = self.pfx_pass_entry.get().strip()
            if not pfx_password:
                self.log("未輸入 PFX 密碼，將使用空密碼產生 .pfx。")

            try:
                self.issue_certificate_via_acme(domain, api_key, email, pfx_password)
                self.log("憑證簽發流程結束。")
            except Exception as e:
                self.log(f"憑證簽發失敗：{e}")

        except Exception as e:
            self.log(f"發生錯誤：{e}")
        finally:
            self.start_button.config(state="normal")

    def get_or_create_domain(self, domain, ip, api_key):
        """
        先嘗試在 Dynu v2 API 查詢 domain，
        若找不到則嘗試建立後等待 5 秒再查詢一次；
        若仍找不到就回傳 None。
        """
        did = self.find_domain_id(domain, api_key)
        if did is not None:
            return did

        self.log(f"找不到 {domain}，嘗試建立 ...")
        if not self.create_domain(domain, ip, api_key):
            return None

        self.log("等待 5 秒後再次查詢 ...")
        time.sleep(5)
        did2 = self.find_domain_id(domain, api_key)
        return did2

    def find_domain_id(self, domain, api_key):
        list_url = "https://api.dynu.com/v2/dns"
        headers = {
            "accept": "application/json",
            "API-Key": api_key
        }
        r = requests.get(list_url, headers=headers, timeout=10)
        if r.status_code != 200:
            self.log(f"取得 domain 列表失敗：{r.status_code}, {r.text}")
            return None

        data = r.json()
        if isinstance(data, dict) and "domains" in data:
            domain_list = data["domains"]
        elif isinstance(data, list):
            domain_list = data
        else:
            domain_list = []

        for d in domain_list:
            if d.get("name", "").lower() == domain.lower():
                return d.get("id")
        return None

    def create_domain(self, domain, ip, api_key):
        create_url = "https://api.dynu.com/v2/dns"
        headers = {
            "accept": "application/json",
            "API-Key": api_key,
            "Content-Type": "application/json"
        }
        new_domain_obj = {
            "name": domain,
            "ipv4Address": ip,
            "ttl": 90,
            "ipv4": True,
            "ipv6": False
        }
        resp = requests.post(create_url, headers=headers, json=new_domain_obj, timeout=10)
        if resp.status_code == 200:
            self.log("建立 Domain 成功。")
            return True
        else:
            self.log(f"建立 Domain 失敗：{resp.status_code}, {resp.text}")
            return False

    def update_domain_ip(self, domain_id, ip, api_key):
        get_url = f"https://api.dynu.com/v2/dns/{domain_id}"
        headers = {
            "accept": "application/json",
            "API-Key": api_key
        }
        r = requests.get(get_url, headers=headers, timeout=10)
        if r.status_code != 200:
            self.log(f"取得 domain 物件失敗：{r.status_code}, {r.text}")
            return False

        domain_obj = r.json()
        domain_obj["ipv4Address"] = ip

        post_url = f"https://api.dynu.com/v2/dns/{domain_id}"
        headers["Content-Type"] = "application/json"
        resp = requests.post(post_url, headers=headers, json=domain_obj, timeout=10)
        if resp.status_code == 200:
            return True
        else:
            self.log(f"更新 domain IP 失敗：{resp.status_code}, {resp.text}")
            return False

    def issue_certificate_via_acme(self, domain, api_key, email, pfx_password):
        """
        1. 建立 ephemeral account key 並註冊
        2. new_order
        3. 找出 DNS-01 challenge
        4. Dynu 上新增 _acme-challenge.<domain> 的 TXT
        5. answer_challenge & poll
        6. finalize & 輸出三份檔案:
           - <Host>.key (私鑰)
           - <Host>.crt (公鑰，含完整鏈)
           - <Host>.pfx (PKCS#12，需密碼)
        7. 刪除 TXT
        """
        self.log("建立 ACME 帳戶金鑰並註冊 ...")
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        acc_key = josepy.JWKRSA(key=private_key)
        net = client.ClientNetwork(acc_key, user_agent="DynuAcmePython")
        directory = messages.Directory.from_json(net.get(ACME_DIRECTORY_URL).json())
        acme_client = client.ClientV2(directory, net=net)

        new_reg = messages.NewRegistration.from_data(email=email, terms_of_service_agreed=True)
        acme_client.new_account(new_reg)

        # domain private key
        self.log("產生 domain 私鑰 ...")
        domain_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        domain_key_pem = domain_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )

        # CSR
        csr_pem = crypto_util.make_csr(domain_key_pem, [domain])
        orderr = acme_client.new_order(csr_pem)

        # 找出 DNS-01
        challenge = None
        for authz in orderr.authorizations:
            for ch in authz.body.challenges:
                if isinstance(ch.chall, challenges.DNS01):
                    challenge = ch
                    break
            if challenge:
                break
        if not challenge:
            raise ValueError("找不到 DNS-01 驗證方式，無法進行。")

        # TXT
        response, validation = challenge.response_and_validation(acme_client.net.key)
        txt_name = challenge.chall.validation_domain_name(domain)
        txt_value = challenge.chall.validation(acme_client.net.key)
        self.log(f"DNS-01 驗證: {txt_name} = {txt_value}")

        # 新增或更新 TXT
        self.add_or_update_txt_record(domain, txt_name, txt_value, api_key)

        # 提交 challenge
        self.log("提交 challenge ...")
        acme_client.answer_challenge(challenge, response)

        # 等待 & finalize
        self.log("等待 Let's Encrypt 驗證 ...")
        finalized = acme_client.poll_and_finalize(orderr)
        fullchain_pem = finalized.fullchain_pem

        # 分析 fullchain
        all_certs = []
        lines = fullchain_pem.strip().split("-----BEGIN CERTIFICATE-----")
        for chunk in lines:
            c = chunk.strip()
            if c:
                c = "-----BEGIN CERTIFICATE-----" + c
                cert_obj = x509.load_pem_x509_certificate(c.encode("utf-8"), default_backend())
                all_certs.append(cert_obj)
        if not all_certs:
            raise ValueError("fullchain_pem 中沒有找到任何憑證")

        leaf_cert = all_certs[0]
        intermediate_certs = all_certs[1:] if len(all_certs) > 1 else []

        # 輸出三份檔案
        host = domain.split(".")[0]

        # 1) 私鑰 <host>.key
        key_file = f"{host}.key"
        with open(key_file, "wb") as f:
            f.write(domain_key_pem)
        self.log(f"已寫出私鑰: {key_file}")

        # 2) 公鑰(含完整鏈) <host>.crt
        crt_file = f"{host}.crt"
        with open(crt_file, "w", encoding="utf-8") as f:
            f.write(fullchain_pem)
        self.log(f"已寫出公鑰(含鏈): {crt_file}")

        # 3) PFX <host>.pfx
        pfx_file = f"{host}.pfx"
        pfx_pass = pfx_password.encode("utf-8") if pfx_password else None

        # 產生 PKCS12
        # cas=intermediate_certs (舊版 cryptography)
        pfx_data = pkcs12.serialize_key_and_certificates(
            name=domain.encode("utf-8"),
            key=domain_key,
            cert=leaf_cert,
            cas=intermediate_certs if intermediate_certs else None,
            encryption_algorithm=(
                BestAvailableEncryption(pfx_pass)
                if pfx_pass
                else NoEncryption()
            )
        )
        with open(pfx_file, "wb") as f:
            f.write(pfx_data)
        self.log(f"已寫出 PFX: {pfx_file} (密碼：{'<空>' if not pfx_pass else '***'})")

        # 刪除 TXT
        self.log("刪除 TXT 紀錄 ...")
        self.delete_txt_record(domain, txt_name, api_key)
        self.log("DNS-01 驗證 TXT 紀錄已清除。")

    def add_or_update_txt_record(self, domain, txt_name, txt_value, api_key):
        if not txt_name.endswith(domain):
            raise ValueError("TXT 名稱不在該 domain 下")

        node_name = txt_name.replace(f".{domain}", "")
        domain_id = self.find_domain_id(domain, api_key)
        if not domain_id:
            raise ValueError("找不到 domainId，無法新增 TXT")

        list_url = f"https://api.dynu.com/v2/dns/{domain_id}/record"
        headers = {
            "accept": "application/json",
            "API-Key": api_key
        }
        r = requests.get(list_url, headers=headers, timeout=10)
        if r.status_code != 200:
            raise ValueError(f"列出 DNS Record 失敗: {r.status_code}, {r.text}")

        records = r.json().get("dnsRecords", [])
        existing_txt = None
        for rec in records:
            if rec.get("recordType") == "TXT" and rec.get("nodeName") == node_name:
                existing_txt = rec
                break

        headers["Content-Type"] = "application/json"
        if existing_txt:
            # 更新
            self.log(f"發現既有 TXT 記錄 (id={existing_txt['id']})，更新中 ...")
            existing_txt["textData"] = txt_value
            existing_txt["state"] = True
            update_url = f"https://api.dynu.com/v2/dns/{domain_id}/record/{existing_txt['id']}"
            resp = requests.post(update_url, headers=headers, json=existing_txt, timeout=10)
            if resp.status_code != 200:
                raise ValueError(f"更新 TXT 記錄失敗: {resp.status_code}, {resp.text}")
        else:
            # 新增
            self.log("無既有 TXT 記錄，新增 ...")
            new_txt_obj = {
                "domainId": domain_id,
                "nodeName": node_name,
                "recordType": "TXT",
                "textData": txt_value,
                "ttl": 120,
                "state": True
            }
            post_url = f"https://api.dynu.com/v2/dns/{domain_id}/record"
            resp = requests.post(post_url, headers=headers, json=new_txt_obj, timeout=10)
            if resp.status_code != 200:
                raise ValueError(f"新增 TXT 記錄失敗: {resp.status_code}, {resp.text}")

        self.log("TXT 記錄已建立/更新，等待 30 秒讓 DNS 生效 ...")
        time.sleep(30)

    def delete_txt_record(self, domain, txt_name, api_key):
        if not txt_name.endswith(domain):
            return

        node_name = txt_name.replace(f".{domain}", "")
        domain_id = self.find_domain_id(domain, api_key)
        if not domain_id:
            return

        list_url = f"https://api.dynu.com/v2/dns/{domain_id}/record"
        headers = {
            "accept": "application/json",
            "API-Key": api_key
        }
        r = requests.get(list_url, headers=headers, timeout=10)
        if r.status_code != 200:
            self.log(f"列出 DNS Record 失敗(刪除TXT時): {r.status_code}, {r.text}")
            return

        records = r.json().get("dnsRecords", [])
        target = None
        for rec in records:
            if rec.get("recordType") == "TXT" and rec.get("nodeName") == node_name:
                target = rec
                break
        if not target:
            self.log("未找到 TXT 記錄可刪除。")
            return

        del_url = f"https://api.dynu.com/v2/dns/{domain_id}/record/delete/{target['id']}"
        resp = requests.get(del_url, headers=headers, timeout=10)
        if resp.status_code == 200:
            self.log("TXT 記錄刪除成功。")
        elif resp.status_code == 404:
            self.log("TXT 記錄已不存在，忽略。")
        else:
            self.log(f"刪除 TXT 記錄失敗: {resp.status_code}, {resp.text}")


if __name__ == "__main__":
    app = DynuAcmeApp()
    app.mainloop()