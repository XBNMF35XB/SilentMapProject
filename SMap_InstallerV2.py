#!/usr/bin/env python3

import os
import platform
import subprocess
import sys
import shutil
import hashlib
import urllib.request
import time

# ---------------- CONFIG ---------------- #

REPO_URL = "https://github.com/XBNMF35XB/SilentMapProject"
RAW_BASE = "https://raw.githubusercontent.com/XBNMF35XB/SilentMapProject/main"
REPO_DIR = "SMap"
VENV_DIR = "venv"
OFFICIAL_FILES = ["SMap.py", "ReadMe.txt", "Apache Licence", "ContactMe.txt"]

# ---------------- UTILS ---------------- #

def run(cmd):
    print(f"[+] Running: {cmd}")
    subprocess.run(cmd, shell=True, check=True)

def command_exists(cmd):
    return shutil.which(cmd) is not None

def hash_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            h.update(chunk)
    return h.hexdigest()

def hash_from_url(url):
    h = hashlib.sha256()
    with urllib.request.urlopen(url) as r:
        while True:
            chunk = r.read(4096)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()

# ---------------- OS DETECTOR ---------------- #

def detect_linux():
    try:
        data = {}
        with open("/etc/os-release") as f:
            for line in f:
                if "=" in line:
                    k, v = line.strip().split("=", 1)
                    data[k] = v.strip('"')
        if "PRETTY_NAME" in data:
            return data["PRETTY_NAME"]
        if "NAME" in data:
            return data["NAME"]
        did = data.get("ID", "").lower()
        known = {
            "arch": "Arch Linux", "manjaro": "Manjaro", "endeavouros": "EndeavourOS",
            "debian": "Debian", "ubuntu": "Ubuntu", "kali": "Kali Linux",
            "fedora": "Fedora", "centos": "CentOS", "alpine": "Alpine Linux"
        }
        return known.get(did, f"Linux ({did or 'Unknown'})")
    except Exception:
        return "Linux (Unknown)"

def local_os():
    s = platform.system()
    if s == "Linux": return detect_linux()
    if s == "Windows": return "Windows"
    if s == "Darwin": return "macOS"
    return s

# ---------------- VENV ---------------- #

def create_venv():
    if not os.path.exists(VENV_DIR):
        run(f"python3 -m venv {VENV_DIR}")

def install_python_packages():
    pip_path = os.path.join(VENV_DIR, "bin", "pip")
    if not os.path.exists(pip_path):
        pip_path = os.path.join(VENV_DIR, "Scripts", "pip.exe")
    packages = [
        "scapy", "requests", "urllib3", "colorama", "tqdm", "pyyaml", 
        "netifaces", "psutils", "ipython", "pandas", "tabulate", "rich",
        "cryptography", "python-dotenv", "platformdirs", "pywifi"
    ]
    print(f"[+] Installazione pacchetti Python: {', '.join(packages)}")
    run(f"{pip_path} install --upgrade pip")
    run(f"{pip_path} install {' '.join(packages)}")
    print("[+] Every package installet!")

# ---------------- REPO SYNC ---------------- #

def sync_repository():
    if not os.path.exists(REPO_DIR):
        os.makedirs(REPO_DIR)

    for f in os.listdir(REPO_DIR):
        if f not in OFFICIAL_FILES:
            path = os.path.join(REPO_DIR, f)
            if os.path.isfile(path):
                os.remove(path)
            else:
                shutil.rmtree(path)

    for f in OFFICIAL_FILES:
        local_path = os.path.join(REPO_DIR, f)
        remote_url = f"{RAW_BASE}/{f}"
        try:
            if os.path.exists(local_path):
                if hash_file(local_path) != hash_from_url(remote_url):
                    print(f"[!] Different {f} file, downloading...")
                    urllib.request.urlretrieve(remote_url, local_path)
            else:
                print(f"[+] Installing missing file: {f}")
                urllib.request.urlretrieve(remote_url, local_path)
        except Exception as e:
            print(f"[!] Syncronization Error {f}: {e}")
            sys.exit(1)

# ---------------- AUTO-REMOVE ---------------- #

def remove_self():
    try:
        script_path = os.path.abspath(sys.argv[0])
        if platform.system() == "Windows":
            bat_file = os.path.join(REPO_DIR, "del_self.bat")
            with open(bat_file, "w") as f:
                f.write(f"""
@echo off
timeout /t 2 /nobreak >nul
del "{script_path}"
del "%~f0"
""")
            subprocess.Popen([bat_file], shell=True)
        else:
            os.remove(script_path)
        print("[+] Installer delited automaticly!")
    except Exception:
        print("[!] Impossible to auto-delite the installer!.")

# ---------------- INSTALLERS ---------------- #

def install_linux():
    osname = detect_linux()
    print(f"[+] Linux distro rilevata: {osname}")
    if any(x in osname for x in ["Arch", "Manjaro", "Garuda", "Endeavour"]):
        run("sudo pacman -S --needed git python nmap wireshark-cli")
    elif any(x in osname for x in ["Ubuntu", "Debian", "Mint", "Kali"]):
        run("sudo apt update && sudo apt install -y git python3 python3-venv nmap tshark")
    else:
        print("[!] Linux Distro not supported.")
        sys.exit(1)

def install_macos():
    if not command_exists("brew"):
        print("[!] Install Homebrew")
        sys.exit(1)
    run("brew install git python nmap wireshark")

def install_windows():
    if not command_exists("git") or not command_exists("python"):
        print("[!] Git o Python mancante")
        sys.exit(1)

# ---------------- MAIN ---------------- #

def main():
    if not os.path.exists(REPO_DIR):
        os.makedirs(REPO_DIR)
    os.chdir(REPO_DIR)

    os_type = platform.system()
    print(f"[+] OS Rilevato: {os_type}")

    try:
        if os_type == "Linux":
            install_linux()
        elif os_type == "Darwin":
            install_macos()
        elif os_type == "Windows":
            install_windows()
        else:
            print("[!] Oprating System not supported. read ContactMe.txt in the repo")
            sys.exit(1)

        create_venv()
        install_python_packages()
        sync_repository()

        python_exec = os.path.join(VENV_DIR, "bin", "python")
        if not os.path.exists(python_exec):
            python_exec = os.path.join(VENV_DIR, "Scripts", "python.exe")

        run(f"{python_exec} {os.path.join(os.getcwd(), 'SilentMap.py')}")
        remove_self()

    except subprocess.CalledProcessError:
        print("[!] Installation Failed.")
        sys.exit(1)

if __name__ == "__main__":
    main()
