from scapy.all import sniff, ARP, Ether, UDP, DHCP, DNS, DNSRR, get_if_hwaddr, conf, AsyncSniffer, srp, sr , IP, TCP
from datetime import datetime
import sys
import time
import argparse
import socket 


#Creating "database" for devices in the memory
#Format : {"MAC": {"ip": "IP_ADDRESS", "last_seen": "TIMESTAMP"}}
network_devices = {}
#OUI database for MAC address vendor lookup
OUI_DATABASE = {
    "10:27:f5": "Cisco Systems",
    "60:83:e7": "Apple Inc",
    "ac:f1:08": "Samsung Electronics",
    "f0:72:ea": "Google Inc",
    "54:13:79": "Brother Industries",
    "48:0b:b2": "Xiaomi Communications"
}


# We download MAC adress of the default interface to avoid capturing our own ARP packets
MY_MAC_ADDRESS = get_if_hwaddr(conf.iface)

def packet_handler(packet):
    # Ignore packets sent by our own device
    if packet.haslayer("Ether") and packet[Ether].src == MY_MAC_ADDRESS:
        return
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    # FIRST MODULE: Check if the packet has ARP layer
    if packet.haslayer("ARP"):
        # Get MAC and IP addresses from the ARP packet
        mac_address = packet[ARP].hwsrc
        ip_address = packet[ARP].psrc
        
        # Ignore packets "0.0.0.0"
        if ip_address == "0.0.0.0":
            return
        # Ignor empty MAC addresses
        if mac_address == "00:00:00:00:00:00":
            return
        
        # Check if the device is NOT in the database
        if mac_address not in network_devices:
            network_devices[mac_address] = {"ip": ip_address, "hostname": "Unknown", "last_seen": timestamp}
            print(f"[{timestamp}] New host: {mac_address} | {ip_address}")
        else:
            # Update the last seen timestamp for existing devices
            if network_devices[mac_address]["ip"] != ip_address:
                network_devices[mac_address]["ip"] = ip_address
            network_devices[mac_address]["last_seen"] = timestamp
            # print(f"[{timestamp}] Device updated: MAC={mac_address}, IP={ip_address}")
    
    # SECOND MODULE: Check if the packet has DHCP layer
    if packet.haslayer("DHCP"):
        # Get MAC and IP addresses from the DHCP packet
        mac_address = packet[Ether].src
        for option in packet[DHCP].options:
            if isinstance(option, tuple) and option[0] == 'hostname':
                hostname = option[1].decode('utf-8', errors='ignore')
                # Update the hostname in the database if the device is already known
                if mac_address in network_devices and network_devices[mac_address]["hostname"] != hostname:
                    network_devices[mac_address]["hostname"] = hostname
                    print(f"[{timestamp}] Hostname updated: MAC={mac_address}, Hostname={hostname}")
    # THIRD MODULE: Check mDNS packets (Apple, Print, IoT devices)        
    if packet.haslayer(DNS) and packet.haslayer(UDP) and packet[UDP].sport == 5353:
        mac_address = packet[Ether].src
        # Search anwser in section DNS (DNSRR)
        if packet.haslayer("DNSRR"):
            try:
                # We decode its name
                rrname = packet[DNSRR].rrname.decode('utf-8', errors='ignore').rstrip('.')
                # We check if the name contains ".local" to identify mDNS packets
                if ".local" in rrname:
                    cleaned_name = rrname.split(".local")[0].replace("_", "")
                    
                    if mac_address in network_devices:
                        current_hostname = network_devices[mac_address]["hostname"]
                        if current_hostname == "Unknown" and "-" not in cleaned_name:
                            network_devices[mac_address]["hostname"] = cleaned_name
                            print(f"[{timestamp}] mDNS hostname updated: MAC={mac_address}, Hostname={cleaned_name}")
            
            except Exception as e:
                print(f"[{timestamp}] Error processing mDNS packet: {e}")
                    
def active_arp_sweep(ip_range):
    # ACTIVE MODULE: Perform an active ARP sweep to discover devices on the network
    print(f"Performing active ARP sweep on {ip_range}...")
    
    packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip_range)
    srp(packet, timeout=2, verbose=False)
    #srp : this function sends and receives packets at layer 2 (Ethernet) and returns a couple of lists: answered and unanswered packets. The timeout parameter specifies how long to wait for responses.
    #timeout : given in seconds, the time to wait for a response before considering the packet unanswered.
    #verbose : if set to True, it will print information about the packets being sent and received. If set to False, it will suppress this output.
    print("[*] Active ARP sweep completed. [*]")

def tcp_syn_scan(target_ip, target_ports):
    # Shorting the list of ports to scan to avoid sending too many packets at once
    if len(target_ports) > 10:
        ports_display = f"{target_ports[0]}-{target_ports[-1]} (all {len(target_ports)} ports)"
    else:
        ports_display = str(target_ports)

    # ACTIVE MODULE: Perform a TCP SYN scan to check if the port is open
    print(f"Performing TCP SYN scan on {target_ip} for ports: {ports_display}...")
    
    # Building input: single IP, but Scapy allows to send multiple packets in a single call, so we can scan multiple ports at once.
    packet = IP(dst=target_ip) / TCP(dport=target_ports, flags="S")
    # sr() sends packets at layer 3 (IP) and returns a couple of lists: answered and unanswered packets. The timeout parameter specifies how long to wait for responses.
    answered, unanswered = sr(packet, timeout=2, verbose=False)
    # Categorizing the results of the scan into open, closed, and filtered ports   
    open_ports = []
    closed_ports = []
    filtered_ports = []
    
    # Analyzing the answered packets to determine the state of the ports
    for sent_pkt, recv_pkt in answered:
        if recv_pkt.haslayer(TCP):
            # Extract the destination port and TCP flags from the received packet
            port = sent_pkt[TCP].dport
            # TCP flags can indicate the state of the port:
            # "SA" (SYN-ACK) indicates the port is open.
            flags = recv_pkt[TCP].flags
            # "R" (RST) or "RA" (RST-ACK) indicates the port is closed.
            if flags == "SA":
                open_ports.append(port)
            elif flags == "R" or flags == "RA":
                closed_ports.append(port)
                
    # 2. Analyzing ports that did not respond (dropped by firewall)
    for sent_pkt in unanswered:
        if sent_pkt.haslayer(TCP):
            filtered_ports.append(sent_pkt[TCP].dport)
            
    # 3. Formatting and displaying results
    print(f"[*] TCP SYN scan completed for {target_ip}.")
    
    if open_ports:
        print("[+] Open ports:")
        for port in open_ports:
            print(f"    - Port {port} is OPEN")
    else:
        print("[-] No open ports found.")
        
    if closed_ports:
        # Shortening the list of closed ports for display
        print(f"[-] Closed ports: {len(closed_ports)} (not responding with SYN-ACK)")
        
    if filtered_ports:
        print(f"[!] Filtered ports (dropped by firewall): {len(filtered_ports)}")
        
    return open_ports, closed_ports, filtered_ports
        
def get_vendor_from_mac(mac_address):
    # We are using the OUI database to look up the vendor based on the MAC address prefix
    if not mac_address or ":" not in mac_address:
        return "Unknown Vendor"
    
    mac_prefix = mac_address[:8].lower()  # Get the first 3 bytes (OUI) of the MAC address
    return OUI_DATABASE.get(mac_prefix, "Unknown Vendor")


# MAIN FUNCTION
def main():
    # Define parsers for command-line arguments
    parser = argparse.ArgumentParser(description="Simple Scanner for Network Devices and Services",
                                     formatter_class=argparse.RawTextHelpFormatter) 
    parser.add_argument("-m", "--map", metavar="CIDR", help="Map network devices in the specified IP range (e.g., 192.168.1.0/24)")
    parser.add_argument("-s", "--scan", metavar="IP", help="Scan for open ports on the specified IP address (e.g., 192.168.1.1)")
    parser.add_argument("-p", "--ports", metavar="PORTS", help="Specify ports to scan (e.g., 22,80,443 or 1-1000). Default is 22,80,443,445,8080.", default="22,80,443,445,8080")
    parser.add_argument("--passive", action="store_true", help="Run in passive mode only (no active scanning).")
    parser.add_argument("-o", "--output", metavar="FILE", help="Output results to a file (e.g., results.json).")
    parser.add_argument("--version", action="version", version="Simple Scanner v1.0")
    
    
    
    args = parser.parse_args()
    
    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(0)
        
    # Logic to handle the command-line arguments
    if args.scan:
        port_list = []
        for p in args.ports.split(','):
            p = p.strip()
            if '-' in p: # Handle port ranges
                start, end = map(int, p.split('-'))
                port_list.extend(range(int(start), int(end) + 1))
            elif p.isdigit():
                port_list.append(int(p))
        # Results of the TCP SYN scan are stored in the network_devices dictionary     
        open_ports, closed_ports, filtered_ports = tcp_syn_scan(args.scan, port_list)
        # If the scanned IP is already in the database, we update its information; otherwise, we create a new entry with the scanned IP and unknown MAC address.
        target_mac = None
        for mac, data in network_devices.items():
            if data["ip"] == args.scan:
                target_mac = mac
                break
            # If the scanned IP is not found in the database, we create a new entry with the scanned IP and unknown MAC address.
        if not target_mac:
            target_mac = f"Directly scanned IP {args.scan} (MAC unknown)"
            network_devices[target_mac] = {
                "ip": args.scan, 
                "hostname": "Unknown",
                "last_seen": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }
        network_devices[target_mac]["open_ports"] = open_ports
        if filtered_ports:
            network_devices[target_mac]["filtered_ports"] = len(filtered_ports)
        network_devices[target_mac]["closed_ports"] = closed_ports
        
        
    # Logic to handle passive sniffing and active ARP sweep    
    if args.map or args.passive:
        print("[*] Starting passive sniffing for ARP, DHCP, and mDNS packets...[*]")
        try:
            # Start background sniffing for ARP, DHCP, and mDNS packets
            background_sniffer = AsyncSniffer(filter="arp or (udp and(port 67 or port 5353))", prn=packet_handler, store=False)
            background_sniffer.start()
            
            if args.map:
                active_arp_sweep(args.map)
            
            print("[*] Sniffing in background... Press Ctrl+C to stop packet capture and display results.[*]")
            
            # Block the main thread until Ctrl+C is pressed
            while True:
                time.sleep(1)
        
        except KeyboardInterrupt:
            print("\nPacket capture stopped.")
            background_sniffer.stop()
            # Resolving hostnames that are still unknown using reverse DNS lookup
            print("[*] Resolving hostnames for devices with unknown hostnames...[*]")
            socket.setdefaulttimeout(0.2)  # Set a timeout for socket operations
            for mac, data in network_devices.items():
                if data["hostname"] == "Unknown":
                    try:
                        data["hostname"] = socket.gethostbyaddr(data["ip"])[0]
                    except Exception:
                        pass
            # Displaying the discovered devices in a formatted table
            print(f"\n--- Discovered devices ---")
            for mac, data in network_devices.items():
                Vendor = get_vendor_from_mac(mac)
                print(f"{mac:<17} | {data['ip']:<15} | Vendor: {Vendor:<25} | Hostname: {data['hostname']:<25} | Last Seen: {data['last_seen']}")
    # Logic to handle output to a file
    if args.output:
        import json
        
        # Adding vendor information to each device in the network_devices dictionary before saving to the output file
        for mac in list(network_devices.keys()):
            network_devices[mac]["vendor"] = get_vendor_from_mac(mac)
            
        with open(args.output, 'w') as f:
            json.dump(network_devices, f, indent=4)
        print(f"\n[*] Results saved to {args.output} [*]")
if __name__ == "__main__":
    main()