#! /usr/bin/env python3
from scapy.all import ARP, sniff
import datetime
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# Dictionary to store IP to MAC mappings
ip_mac_mapping = {}
# Set to keep track of attackers already reported
reported_attackers = set()

# Define gateway IP and MAC address
gateway_ip = "192.168.100.1"  # Replace with your gateway IP address
gateway_mac = "6c:14:6e:e5:a6:f0"  # Replace with your gateway MAC address

# File to store attacker details
log_file = "arp_spoofing_log.txt"

# Email details
smtp_server = "smtp.gmail.com"
smtp_port = 587
email_user = "isaac.kipruto@strathmore.edu"
email_password = "uzjr mofo ysqt yajl"
email_to = "kowwaski@gmail.com"



def send_email(source_ip, source_mac):
    """Send an email with the attacker's information."""
    subject = "ALERT: Gateway ARP Spoofing Detected"
    body = f"""
    WARNING: Gateway ARP spoofing detected!
    
    Gateway IP address {gateway_ip} is being claimed by MAC address {source_mac}, expected MAC address is {gateway_mac}
    
    Attacker details:
    - IP address: {source_ip}
    - MAC address: {source_mac}
    
    Please take the necessary actions to blacklist this device from the network.
    """

    msg = MIMEMultipart()
    msg['From'] = email_user
    msg['To'] = email_to
    msg['Subject'] = subject
    msg.attach(MIMEText(body, 'plain'))

    try:
        server = smtplib.SMTP(smtp_server, smtp_port)
        server.starttls()
        server.login(email_user, email_password)
        text = msg.as_string()
        server.sendmail(email_user, email_to, text)
        server.quit()
        print(f"Email sent to {email_to} regarding gateway ARP spoofing.")
    except Exception as e:
        print(f"Failed to send email: {e}")

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
            attacker = (source_ip, source_mac)
            if attacker not in reported_attackers:
                print(f"WARNING: Gateway ARP spoofing detected!")
                print(f"Gateway IP address {source_ip} is being claimed by MAC address {source_mac}, expected MAC address is {gateway_mac}")
                log_attacker(source_ip, source_mac)  # Log the attacker details
                send_email(source_ip, source_mac)  # Send email notification
                reported_attackers.add(attacker)  # Mark attacker as reported
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
