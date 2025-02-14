#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
fetch_deps.py
-------------
1. 使用 pip 下載指定 Python 套件的 Wheel 檔至 vendor_temp/。
2. 將所有 .whl 解壓縮至 vendor/。
3. 使用者只需執行此腳本一次，即可在 main.py 中動態載入這些套件，而無需安裝到系統。

需求：
- 系統已安裝 pip。
- Python 3.6+。
"""

import os
import sys
import subprocess
import zipfile
import glob
import shutil

# 你想要打包的套件清單
DEPENDENCIES = [
    "acme",
    "cryptography",
    "josepy",
    "pyOpenSSL",
    "requests"
]

def main():
    script_dir = os.path.dirname(os.path.abspath(__file__))
    vendor_temp = os.path.join(script_dir, "vendor_temp")
    vendor_dir = os.path.join(script_dir, "vendor")

    # 1. 建立暫存資料夾 vendor_temp
    if not os.path.exists(vendor_temp):
        os.makedirs(vendor_temp)
    # 2. 建立 vendor 資料夾
    if not os.path.exists(vendor_dir):
        os.makedirs(vendor_dir)

    # 3. pip download
    print("==> 下載套件中 ...")
    pkgs_str = " ".join(DEPENDENCIES)
    cmd = [
        sys.executable, "-m", "pip", "download",
        #"--no-deps",
        "-d", vendor_temp
    ] + DEPENDENCIES
    print("執行：", " ".join(cmd))
    subprocess.run(cmd, check=True)

    # 4. 解壓 .whl 到 vendor/
    print("==> 解壓縮 Wheel 檔 ...")
    whl_files = glob.glob(os.path.join(vendor_temp, "*.whl"))
    for whl_path in whl_files:
        print(f"解壓縮 {os.path.basename(whl_path)} -> vendor/")
        with zipfile.ZipFile(whl_path, "r") as zf:
            zf.extractall(vendor_dir)

    print("==> 清理暫存資料夾 vendor_temp/ ...")
    shutil.rmtree(vendor_temp, ignore_errors=True)

    print("完成！請在 main.py 中加上對 vendor/ 的載入。")

if __name__ == "__main__":
    main()