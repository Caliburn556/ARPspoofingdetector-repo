#! /usr/bin/env python3
from scapy.all import ARP, sniff

# Dictionary to store IP to MAC mappings
ip_mac_mapping = {}

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
        if source_ip in ip_mac_mapping:
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
