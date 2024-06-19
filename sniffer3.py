#! /usr/bin/env python3
from scapy.all import ARP, sniff
from collections import defaultdict

# Dictionary to store IP to MAC mappings
arp_table = defaultdict(set)

def arp_display(pkt):
    if ARP in pkt and pkt[ARP].op == 2:  # is-at (response)
        source_ip = pkt[ARP].psrc
        source_mac = pkt[ARP].hwsrc

        # Update the ARP table
        arp_table[source_ip].add(source_mac)

        # Detect ARP spoofing
        if len(arp_table[source_ip]) > 1:
            print(f"WARNING: Possible ARP spoofing detected for IP {source_ip}!")
            print(f"IP address {source_ip} is being claimed by multiple MAC addresses: {', '.join(arp_table[source_ip])}")
        else:
            print(f"ARP entry: {source_ip} is at {source_mac}")

def print_arp_table():
    print("\nCurrent ARP Table:")
    print(f"{'IP Address':15} {'MAC Addresses'}")
    print("="*40)
    for ip, macs in arp_table.items():
        print(f"{ip:15} {', '.join(macs)}")

# Print the header
print(f"{'Source MAC':20} {'Destination MAC':20} {'Protocol':10} {'Length':6} {'Info'}")

try:
    # Start sniffing, filtering only ARP responses
    sniff(prn=arp_display, filter="arp", store=0)
except KeyboardInterrupt:
    print_arp_table()