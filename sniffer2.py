#! /usr/bin/env python3
from scapy.all import ARP, sniff
def arp_display(pkt):
    if ARP in pkt and pkt[ARP].op == 2:  # is-at (response)
        source_mac = pkt[ARP].hwsrc
        destination_mac = pkt[ARP].hwdst
        protocol = 'ARP'
        length = len(pkt)
        info = f"{pkt[ARP].psrc} is at {pkt[ARP].hwsrc}"

        # Label as broadcast if destination MAC is 00:00:00:00:00:00
        if destination_mac == '00:00:00:00:00:00':
            destination_mac = 'Broadcast'

        print(f"{source_mac:20} {destination_mac:20} {protocol:10} {length:6} {info}")

# Print the header
print(f"{'Source MAC':20} {'Destination MAC':20} {'Protocol':10} {'Length':6} {'Info'}")

# Start sniffing, filtering only ARP responses
sniff(prn=arp_display, filter="arp", store=0)
