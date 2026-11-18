# NetScanner - Hybrid Network Scanner & Auditing Tool

A lightweight, professional-grade network auditing tool built with Python and Scapy. NetScanner is designed for fast, stealthy, and reliable network reconnaissance, combining active scanning techniques with passive sniffing to build a comprehensive map of network devices and their open services.

##  Features

*   **Hybrid Network Mapping:** 
    *   **Active ARP Sweep:** Rapidly discovers hosts within a specified CIDR range.
    *   **Passive Sniffing:** Silently captures background ARP, DHCP, and mDNS traffic to identify devices without generating active noise.
*   **TCP SYN Stealth Scanning:** Performs asynchronous port scanning (`-sS`) to detect open, closed, and filtered ports while minimizing the footprint left in target logs.
*   **Vendor Identification (MAC OUI):** Automatically translates MAC addresses into hardware manufacturers (e.g., Apple, Cisco, Samsung) using a built-in OUI database.
*   **Hostname Resolution:** Utilizes both passive DNS/DHCP inspection and active reverse DNS lookups to resolve device names.
*   **JSON Reporting:** Exports detailed, structured network maps and scan results to a JSON file for further analysis or archiving.

##  Prerequisites

To run this tool, you need Python 3.x and the `scapy` library installed on your system.

1. Install the required Python packages:
   ```bash
   pip install scapy
   ```
2. **Note for Windows Users:** Scapy requires a packet capture driver. Ensure you have [Npcap](https://npcap.com/) (recommended) or WinPcap installed on your machine.
3. **Privileges:** Network sniffing and crafting raw packets (like TCP SYN) require administrative or root privileges. Run your terminal as Administrator (Windows) or use `sudo` (Linux/macOS).

##  Usage

```text
usage: main.py [-h] [-m CIDR] [-s IP] [-p PORTS] [--passive] [-o FILE] [--version]
```

### Command-Line Arguments:
*   `-m, --map <CIDR>` : Map network devices in the specified IP range (e.g., 192.168.1.0/24).
*   `-s, --scan <IP>`  : Perform a TCP SYN port scan on a specific IP address.
*   `-p, --ports <PORTS>`: Specify ports to scan (e.g., `22,80,443` or `1-1000`). Default: `22,80,443,445,8080`.
*   `--passive`        : Run entirely in passive mode, only listening to network traffic without sending any packets.
*   `-o, --output <FILE>`: Export the discovered devices and scan results to a JSON file.
*   `--version`        : Show the program's version number and exit.

##  Examples

**1. Map a local network and save results to a file:**
```bash
python main.py -m 192.168.0.0/24 -o network_map.json
```
*This will perform an active ARP sweep, followed by passive sniffing. Press `Ctrl+C` to stop sniffing and save the report.*

**2. Perform a stealth TCP SYN scan on specific ports:**
```bash
python main.py -s 192.168.0.10 -p 21,22,80,443,3306 -o scan_results.json
```

**3. Scan a full range of ports on a target:**
```bash
python main.py -s 192.168.0.1 -p 1-8080
```

**4. Run in completely silent (passive) mode:**
```bash
python main.py --passive -o passive_capture.json
```

##  Disclaimer

This tool is created for educational purposes and authorized network auditing only. Do not use NetScanner on networks or devices you do not own or have explicit permission to test. The author is not responsible for any misuse of this software.