#!/usr/bin/env python3

import os
import platform
import subprocess
import sys
import shutil
import hashlib
import urllib.request

REPO_URL = "https://github.com/XBNMF35XB/SilentMapProject"
RAW_URL = "https://raw.githubusercontent.com/XBNMF35XB/SilentMap.py/main/SilentMapProject"
REPO_DIR = "SilentMap.py"
VENV_DIR = "venv"

def run(cmd):
    print(f"[+] {cmd}")
    subprocess.run(cmd, shell=True, check=True)

def command_exists(cmd):
    return shutil.which(cmd) is not None

def detect_linux_distro():
    if not os.path.exists("/etc/os-release"):
        return "unknown"
    with open("/etc/os-release") as f:
        data = f.read().lower()
    if "arch" in data:
        return "arch"
    if any(x in data for x in ["debian", "ubuntu", "kali", "mint"]):
        return "debian"
    return "unknown"

# ---------------- VENV ---------------- #

def create_venv():
    if not os.path.exists(VENV_DIR):
        run(f"python3 -m venv {VENV_DIR}")

def install_python_packages():
    pip_path = os.path.join(VENV_DIR, "bin", "pip")
    if not os.path.exists(pip_path):
        pip_path = os.path.join(VENV_DIR, "Scripts", "pip.exe")
    run(f"{pip_path} install --upgrade pip scapy")

# ---------------- REPO ---------------- #

def clone_repo():
    if not os.path.exists(REPO_DIR):
        run(f"git clone {REPO_URL}")
    else:
        print(f"[+] {REPO_DIR} already exists, skipping git clone.")

def hash_file(path):
    sha256 = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            sha256.update(chunk)
    return sha256.hexdigest()

def hash_from_url(url):
    sha256 = hashlib.sha256()
    with urllib.request.urlopen(url) as response:
        while True:
            chunk = response.read(4096)
            if not chunk:
                break
            sha256.update(chunk)
    return sha256.hexdigest()

def verify_silentmap():
    local_path = os.path.join(REPO_DIR, "SilentMap.py")
    if not os.path.exists(local_path):
        print("[!] Local SilentMap.py missing")
        sys.exit(1)

    print("[+] Downloading remote SilentMap.py for integrity check...")
    remote_hash = hash_from_url(RAW_URL)
    local_hash = hash_file(local_path)

    if local_hash != remote_hash:
        print("[!] Hash mismatch! Local SilentMap.py may be corrupted or modified.")
        sys.exit(1)
    print("[+] SilentMap.py verified successfully.")

def verify_minimal_files():
    required = ["README.md", "LICENSE"]
    for f in required:
        path = os.path.join(REPO_DIR, f)
        if not os.path.exists(path):
            print(f"[!] Missing required file: {f}")
            sys.exit(1)
    print("[+] Minimal file check passed.")

def remove_self():
    script_path = os.path.abspath(sys.argv[0])
    try:
        os.remove(script_path)
        print("[+] Installer removed itself.")
    except Exception:
        pass

# ---------------- OS-SPECIFIC ---------------- #

def install_arch():
    run("sudo pacman -S --needed git python nmap wireshark-cli")
    create_venv()
    install_python_packages()
    clone_repo()
    verify_silentmap()
    verify_minimal_files()
    run(f"{VENV_DIR}/bin/python SilentMap.py")
    remove_self()

def install_debian():
    run("sudo apt update")
    run("sudo apt install -y git python3 python3-venv nmap tshark")
    create_venv()
    install_python_packages()
    clone_repo()
    verify_silentmap()
    verify_minimal_files()
    run(f"{VENV_DIR}/bin/python3 SilentMap.py")
    remove_self()

def install_macos():
    if not command_exists("brew"):
        print("[!] Install Homebrew from https://brew.sh")
        sys.exit(1)
    run("brew install git python nmap wireshark")
    create_venv()
    install_python_packages()
    clone_repo()
    verify_silentmap()
    verify_minimal_files()
    run(f"{VENV_DIR}/bin/python3 SilentMap.py")
    remove_self()

def check_npcap():
    possible_paths = [r"C:\Windows\System32\Npcap", r"C:\Program Files\Npcap"]
    return any(os.path.exists(p) for p in possible_paths)

def install_windows():
    if not check_npcap():
        print("[!] Npcap not detected. Install it: https://npcap.com/#download")
        sys.exit(1)
    if not command_exists("git") or not command_exists("python"):
        print("[!] Git or Python not found in PATH.")
        sys.exit(1)

    run(f"python -m venv {VENV_DIR}")
    pip_path = os.path.join(VENV_DIR, "Scripts", "pip.exe")
    run(f"{pip_path} install --upgrade pip scapy")

    clone_repo()
    verify_silentmap()
    verify_minimal_files()
    python_path = os.path.join(VENV_DIR, "Scripts", "python.exe")
    run(f"{python_path} SilentMap.py")
    remove_self()

# ---------------- MAIN ---------------- #

def main():
    os_type = platform.system()
    print(f"[+] Detected OS: {os_type}")

    try:
        if os_type == "Linux":
            distro = detect_linux_distro()
            print(f"[+] Detected Linux distro: {distro}")
            if distro == "arch":
                install_arch()
            elif distro == "debian":
                install_debian()
            else:
                print("[!] Unsupported Linux distro.")
                sys.exit(1)
        elif os_type == "Darwin":
            install_macos()
        elif os_type == "Windows":
            install_windows()
        else:
            print("[!] Unsupported OS.")
            sys.exit(1)
    except subprocess.CalledProcessError:
        print("[!] Installation failed.")
        sys.exit(1)

if __name__ == "__main__":
    main()
