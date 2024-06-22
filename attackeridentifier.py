#! /usr/bin/env python3
from scapy.all import ARP, sniff
import datetime

# Dictionary to store IP to MAC mappings
ip_mac_mapping = {}

# Define gateway IP and MAC address
gateway_ip = "192.168.1.1"  # Replace with your gateway IP address
gateway_mac = "00:11:22:33:44:55"  # Replace with your gateway MAC address

# File to store attacker details
log_file = "arp_spoofing_log.txt"

def log_attacker(source_ip, source_mac):
    """Log the attacker's information to a file."""
    with open(log_file, "a") as file:
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        file.write(f"Timestamp: {timestamp}\n")
        file.write(f"Gateway IP: {gateway_ip}\n")
        file.write(f"Expected Gateway MAC: {gateway_mac}\n")
        file.write(f"Attacker IP: {source_ip}\n")
        file.write(f"Attacker MAC: {source_mac}\n")
        file.write("-" * 40 + "\n")

def arp_display(pkt):
    if ARP in pkt and pkt[ARP].op == 2:  # is-at (response)
        source_ip = pkt[ARP].psrc
        source_mac = pkt[ARP].hwsrc
        destination_mac = pkt[ARP].hwdst
        protocol = 'ARP'
        length = len(pkt)
        info = f"{source_ip} is at {source_mac}"

        # Label as broadcast if destination MAC is 00:00:00:00:00:00
        if destination_mac == '00:00:00:00:00:00':
            destination_mac = 'Broadcast'

        # Signature-based detection for ARP spoofing
        if source_ip == gateway_ip and source_mac != gateway_mac:
            print(f"WARNING: Gateway ARP spoofing detected!")
            print(f"Gateway IP address {source_ip} is being claimed by MAC address {source_mac}, expected MAC address is {gateway_mac}")
            log_attacker(source_ip, source_mac)  # Log the attacker details
        elif source_ip in ip_mac_mapping:
            if source_mac not in ip_mac_mapping[source_ip]:
                ip_mac_mapping[source_ip].add(source_mac)
                print(f"WARNING: Possible ARP spoofing detected!")
                print(f"IP address {source_ip} is being claimed by multiple MAC addresses: {', '.join(ip_mac_mapping[source_ip])}")
        else:
            ip_mac_mapping[source_ip] = {source_mac}

        print(f"{source_mac:20} {destination_mac:20} {protocol:10} {length:6} {info}")

# Print the header
print(f"{'Source MAC':20} {'Destination MAC':20} {'Protocol':10} {'Length':6} {'Info'}")

# Start sniffing, filtering only ARP responses
sniff(prn=arp_display, filter="arp", store=0)
