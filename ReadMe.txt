SilentMap (SMap)
SilentMap, also known as SMap, is a lightweight Python-based system and network analysis tool.
When executed, SilentMap collects and displays detailed information about the local system, including:
Operating System and kernel
Device type and architecture
Local IP address
MAC address
User and platform details
Optionally, SilentMap can perform a local network scan to identify other devices connected to the same subnet, providing information such as IP address, MAC address, hostname, vendor (limited database), and a basic OS guess.
If a detected device is reported as “Linux” without a specific distribution, it is likely a kernel-based or embedded device, such as routers, cameras, smart TVs, IoT devices, or other unknown systems.
Features
Local system information detection
Cross-platform OS detection (Linux, Windows, macOS)
Optional Silent Mode (reduced speed for stealthier operation)
ARP-based network scanning (requires Scapy and elevated privileges)
IP and MAC address analysis utilities
Simple, single-file design
Requirements
Python 3.8 or newer
Git
Optional: scapy (required for network scanning)
Administrator / root privileges for ARP scanning
To install Scapy: pip install scapy
Installation

Arch Linux 
sudo pacman -S git 
git clone https://github.com/XBNMF35XB/SilentMap.py.git cd SilentMap.py sudo python3 SilentMap.py

Debian-based Distributions (Debian, Ubuntu, Kali Linux, Linux Mint) 
sudo apt update sudo apt install git python3 git clone https://github.com/XBNMF35XB/SilentMap.py.git 
cd SilentMap.py 
sudo python3 SilentMap.py


macOS Requires Homebrew. 
brew install git python 
git clone https://github.com/XBNMF35XB/SilentMap.py.git 
cd SilentMap.py python3 SilentMap.py


Windows Install Git: https://git-scm.com/download/win 
Install Python (enable Add Python to PATH): https://www.python.org/downloads/windows/
Open PowerShell as Administrator and run: 
git clone https://github.com/XBNMF35XB/SilentMap.py.git
cd SilentMap.py python SilentMap.py



Usage Notes
Network scanning works best on local networks (e.g. 192.168.x.0/24) Vendor identification is based on a limited OUI database Some features may require elevated privileges Results may vary depending on operating system and network configuration
Disclaimer
This tool is provided for educational and informational purposes only. Use SilentMap only on systems and networks you own or have explicit permission to analyze. The author is not responsible for misuse or illegal activities.
Author
XBNMF35XB Alias: Nexus

