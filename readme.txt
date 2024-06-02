ARP Reply Filtering:

The script captures only ARP reply packets by checking if pkt[ARP].op == 2.
Formatting the Output:
The info variable is constructed to match the format you requested, showing the IP address followed by the source MAC address.
The destination_mac is labeled as 'Broadcast' if it is 00:00:00:00:00:00.
Headers:

The headers are printed before starting the sniffing process to align the output columns properly.