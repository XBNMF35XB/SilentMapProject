#!/usr/bin/python3

#=====================================================
#   IMPORTS
#=====================================================

import os
import sys
import time
import random
import platform
import subprocess
import socket

# Optional Scapy for ARP Scan (needs sudo)
try:
    from scapy.all import ARP, Ether, srp, conf
except ImportError:
    conf = None

#=====================================================
#   COLORS
#=====================================================

ICE     = "\033[97m"
GREEN   = "\033[92m"
YELLOW  = "\033[93m"
BLUE    = "\033[94m"
ORANGE  = "\033[33m"
RESET   = "\033[0m"
BOLD    = "\033[1m"

#=====================================================
#   GLOBAL SETTINGS
#=====================================================

SILENT_MODE = False  # Attivato da utente all'inizio

#=====================================================
#   VISUAL UTILITIES
#=====================================================

def wt(text, d=0.02, color=ICE, bp=False):
    global SILENT_MODE
    delay = d if SILENT_MODE else 0.002
    for c in text:
        sys.stdout.write(color + c + RESET)
        sys.stdout.flush()
        if bp:
            sys.stdout.write("\a")
        time.sleep(delay)
    print()

def step_loading(label, size=26, speed=0.02):
    global SILENT_MODE
    speed = speed * 3 if SILENT_MODE else speed  # rallenta se silent
    label = label.strip()
    for i in range(size + 1):
        filled = "#" * i
        empty = "-" * (size - i)
        pct = int((i / size) * 100)

        if pct == 100:
            sys.stdout.write(
                f"\r{YELLOW}[LOADING]{RESET} {label:<32} "
                f"{YELLOW}[{filled}{empty}] {pct:3d}% {GREEN}[OK]{RESET}"
            )
        else:
            sys.stdout.write(
                f"\r{YELLOW}[LOADING]{RESET} {label:<32} "
                f"{YELLOW}[{filled}{empty}] {pct:3d}%{RESET}"
            )

        sys.stdout.flush()
        time.sleep(speed)
    print()

#=====================================================
#   INTRO
#=====================================================

def intro():
    wt("BOOTING MODULE...", bp=True)
    time.sleep(0.4)

    steps = [
        "Loading scanners",
        "Syncing entropy grid",
        "Initializing device map",
        "Deploying detection cores",
        "Activating network engines"
    ]

    for s in steps:
        step_loading(s)

    wt(f"\n{BOLD}SYSTEM CORE ONLINE{RESET}\n")

    # Chiedi Silent Mode
    global SILENT_MODE
    choice = input("Activate Silent Mode? (y/n): ").strip().lower()
    SILENT_MODE = True if choice == "y" else False
    if SILENT_MODE:
        print("\nSilent Mode activated. Operations will be slower to avoid detection.\n")
    else:
        print("\nSilent Mode not activated. Running normally.\n")

#=====================================================
#   LOCAL OS DETECTION
#=====================================================

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
            # Arch
            "arch": "Arch Linux",
            "manjaro": "Manjaro",
            "endeavouros": "EndeavourOS",
            "artix": "Artix Linux",
            "garuda": "Garuda Linux",
            # Debian / Ubuntu
            "debian": "Debian",
            "ubuntu": "Ubuntu",
            "linuxmint": "Linux Mint",
            "pop": "Pop!_OS",
            "kali": "Kali Linux",
            "parrot": "Parrot OS",
            "elementary": "elementary OS",
            "zorin": "Zorin OS",
            "mx": "MX Linux",
            # Red Hat
            "fedora": "Fedora",
            "rhel": "Red Hat Enterprise Linux",
            "centos": "CentOS",
            "rocky": "Rocky Linux",
            "almalinux": "AlmaLinux",
            # SUSE
            "opensuse": "openSUSE",
            "sles": "SUSE Linux Enterprise",
            # Alpine / lightweight
            "alpine": "Alpine Linux",
            "void": "Void Linux",
            "gentoo": "Gentoo",
            "nixos": "NixOS",
            "slackware": "Slackware",
            # Embedded / special
            "raspbian": "Raspberry Pi OS",
            "postmarketos": "postmarketOS",
            "steam": "SteamOS",
            "clear-linux-os": "Clear Linux"
        }

        if did in known:
            return known[did]
        return f"Linux ({did or 'Unknown'})"
    except Exception:
        return "Linux (Unknown)"

def detect_device_type():
    m = platform.machine().lower()
    if "arm" in m: return "ARM Device"
    if "x86" in m: return "PC / Laptop"
    return "Unknown"

def local_os():
    s = platform.system()
    if s == "Linux": return detect_linux()
    if s == "Windows": return "Windows"
    if s == "Darwin": return "macOS"
    return s

def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "Unknown"

def get_mac_address():
    try:
        import uuid
        mac = uuid.getnode()
        if (mac >> 40) % 2:
            return "Unknown"
        return ":".join(f"{(mac >> ele) & 0xff:02x}" for ele in range(40, -1, -8))
    except Exception:
        return "Unknown"

def build_details(osname):
    return {
        "OS": osname,
        "Kernel": platform.release(),
        "Machine": platform.machine(),
        "Platform": platform.platform(),
        "User": os.getenv("USER") or os.getenv("USERNAME") or "Unknown",
        "Device Type": detect_device_type(),
        "Local IP": get_local_ip(),
        "MAC Address": get_mac_address(),
    }

def reveal(osname, details):
    wt("\nLOCKING TARGET...", bp=True)
    step_loading("Analyzing system", size=40)

    wt(f"\n{BOLD}DETECTED OS: {osname}{RESET}")
    wt("\n-- DETAILS --\n")

    for k, v in details.items():
        wt(f"{k}: {v}")
        time.sleep(0.04)
    print()

#=====================================================
#   NETWORK MODULE
#=====================================================

def arp_scan(subnet="192.168.1.0/24", retries=3, timeout=2):
    if conf is None:
        print("Scapy not installed.")
        return []

    conf.verb = 0
    pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=subnet)

    answered = []
    for _ in range(retries):
        ans, _ = srp(pkt, timeout=timeout, retry=0)
        answered.extend(ans)

    hosts = {}
    for _, r in answered:
        ip = r.psrc
        mac = r.hwsrc
        hosts[ip] = mac  # evita duplicati

    results = []
    for ip, mac in hosts.items():
        # Hostname
        try:
            hostname = socket.gethostbyaddr(ip)[0]
        except Exception:
            hostname = "Unknown"

        # Vendor MAC
        oui = mac[:8].upper()
        vendors = {
            "00:1A:2B": "Cisco",
            "3C:52:82": "Intel",
            "FC:FB:FB": "Apple",
            "B8:27:EB": "Raspberry Pi",
        }
        vendor = vendors.get(oui, "Unknown")

        # Ping alive check
        alive = False
        try:
            subprocess.run(
                ["ping", "-c", "1", "-W", "1", ip],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
            alive = True
        except Exception:
            pass

        results.append({
            "ip": ip,
            "mac": mac,
            "hostname": hostname,
            "vendor": vendor,
            "alive": alive
        })

    return results

def guess_os_ttl(ip):
    try:
        cmd = ["ping", "-c", "1", "-W", "1", ip]
        p = subprocess.run(cmd, stdout=subprocess.PIPE, text=True)
        o = p.stdout.lower()

        if "ttl=" not in o:
            return "Unknown"

        ttl = int(o.split("ttl=")[1].split()[0])
        if ttl == 64: return "Linux"
        if ttl == 128: return "Windows"
        if ttl == 255: return "Network Device"
        return f"Unknown (TTL={ttl})"
    except:
        return "Unknown"

def vpn_breacher(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except:
        return "Unable to resolve"

def network_scan(subnet):
    print("\nENGAGING NETWORK MODULE...")
    hosts = arp_scan(subnet)

    if not hosts:
        print("No active hosts.\n")
        return

    print(f"\nFOUND {len(hosts)} HOSTS\n")

    global SILENT_MODE
    for h in hosts:
        ip = h["ip"]
        mac = h["mac"]

        print(f"\nTARGET    : {ip}")
        print(f"MAC       : {mac}")
        print(f"Vendor    : {h['vendor']}")
        print(f"Hostname  : {h['hostname']}")
        print(f"Alive     : {'Yes' if h['alive'] else 'No'}")
        print(f"OS Guess  : {guess_os_ttl(ip)}")
        time.sleep(0.1 * (3 if SILENT_MODE else 1))

    print("\nNetwork scan complete.\n")

#=====================================================
#   IP / MAC INFO UTILITIES
#=====================================================

def is_valid_ip(ip):
    try:
        socket.inet_aton(ip)
        return True
    except OSError:
        return False

def is_valid_mac(mac):
    mac = mac.lower().replace("-", ":")
    parts = mac.split(":")
    if len(parts) != 6:
        return False
    return all(len(p) == 2 and all(c in "0123456789abcdef" for c in p) for p in parts)

def ip_info(ip):
    print("\n[ IP INFO ]")
    print("IP:", ip)

    if ip.startswith("127."):
        print("Type: Loopback")
    elif ip.startswith(("10.", "192.168.", "172.")):
        print("Type: Private / Local")
    else:
        print("Type: Public")

    try:
        host = socket.gethostbyaddr(ip)[0]
        print("Hostname:", host)
    except Exception:
        print("Hostname: Not resolvable")

def mac_info(mac):
    mac = mac.lower().replace("-", ":")
    print("\n[ MAC INFO ]")
    print("MAC:", mac)

    oui = mac[:8].upper()
    vendors = {
        "00:1A:2B": "Cisco",
        "3C:52:82": "Intel",
        "FC:FB:FB": "Apple",
        "B8:27:EB": "Raspberry Pi",
    }

    print("Vendor:", vendors.get(oui, "Unknown Vendor"))

def ip_mac_info_module():
    wt("Run IP / MAC Info module? (y/n): ", d=0.01, color=ORANGE)
    if input().strip().lower() != "y":
        return

    print("\nAnalyze:")
    print("[1] IP Address")
    print("[2] MAC Address")

    choice = input("Select option: ").strip()

    if choice == "1":
        ip = input("Enter IP address: ").strip()
        if is_valid_ip(ip):
            ip_info(ip)
        else:
            print("Invalid IP address.")

    elif choice == "2":
        mac = input("Enter MAC address: ").strip()
        if is_valid_mac(mac):
            mac_info(mac)
        else:
            print("Invalid MAC address.")

    else:
        print("Invalid option.")

#=====================================================
#   MAIN
#=====================================================

def main():
    intro()
    osname = local_os()
    details = build_details(osname)
    reveal(osname, details)

    wt("Run network scan module? (y/n): ", d=0.01, color=ORANGE)
    if input().strip().lower() != "y":
        wt("\nShutting down...", color=BLUE)
        return
    network_scan("192.168.1.0/24")

    ip_mac_info_module()
    wt("\nShutting down...", color=BLUE)

if __name__ == "__main__":
    random.seed(int(time.time()))
    main()
