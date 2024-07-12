## ARPspoofingdetector-repo
## ARP Spoofing Detector

This document provides an explanation of an ARP Spoofing Detector script, detailing its purpose, overview, prerequisites, implementation, setup, and configuration.

### Purpose

The ARP Spoofing Detector script is designed to monitor a network for ARP spoofing attacks. ARP spoofing is a type of cyber attack where an attacker sends false ARP (Address Resolution Protocol) messages to a local network. This results in the linking of the attacker's MAC address with the IP address of a legitimate computer or server on the network. Consequently, the attacker can intercept, modify, or stop data in-transit.

### Overview

The ARP Spoofing Detector works by:

1. Monitoring ARP responses on the network.
2. Comparing the source MAC address of ARP packets claiming to be from the gateway with the known MAC address of the gateway.
3. Logging and reporting any discrepancies via email.
4. Maintaining a log of detected attacks.

### Prerequisites

Before running the script, ensure the following prerequisites are met:

1. **Python 3**: The script requires Python 3 to run.
2. **Scapy**: A powerful Python library used to interact with network packets. Install it using pip:
    ```sh
    pip install scapy
    ```
3. **SMTP Server Credentials**: For sending email alerts, you need valid SMTP server credentials. The script is configured to use Gmail's SMTP server.

### Implementation

The script consists of several key components:

1. **Imports and Initial Setup**:
    - `scapy.all` for network packet handling.
    - `datetime` for timestamping logs.
    - `smtplib` and `email.mime` for sending email notifications.

2. **Global Variables**:
    - `ip_mac_mapping`: A dictionary to store IP to MAC mappings.
    - `reported_attackers`: A set to keep track of attackers already reported.
    - `gateway_ip` and `gateway_mac`: Define the gateway's IP and MAC addresses.
    - `log_file`: The file to store attacker details.
    - Email details (`smtp_server`, `smtp_port`, `email_user`, `email_password`, `email_to`).

3. **Functions**:
    - `send_email(source_ip, source_mac)`: Sends an email with the attacker's information.
    - `log_attacker(source_ip, source_mac)`: Logs the attacker's information to a file.
    - `arp_display(pkt)`: Callback function to process each captured ARP packet.

4. **Main Execution**:
    - Prints a header for the ARP sniffing output.
    - Starts sniffing ARP packets using the `sniff` function from Scapy.

### Setup and Configuration

To set up and configure the ARP Spoofing Detector:

1. **Edit Gateway Information**:
    - Replace `gateway_ip` and `gateway_mac` with your network's gateway IP and MAC addresses.

    ```python
    gateway_ip = "192.168.100.1"  # Replace with your gateway IP address
    gateway_mac = "6c:14:6e:e5:a6:f0"  # Replace with your gateway MAC address
    ```

2. **Email Configuration**:
    - Update the email details with your SMTP server credentials and the recipient email address.

    ```python
    smtp_server = "smtp.gmail.com"
    smtp_port = 587
    email_user = "your_email@gmail.com"
    email_password = "your_email_password"
    email_to = "recipient_email@gmail.com"
    ```

3. **Run the Script**:
    - Execute the script with Python 3.

    ```sh
    python3 arp_spoofing_detector.py
    ```

### How It Works

1. The script starts by initializing the required variables and settings.
2. It then defines the `send_email`, `log_attacker`, and `arp_display` functions to handle email notifications, logging, and processing ARP packets, respectively.
3. When an ARP packet is captured, the `arp_display` function checks if the packet claims to be from the gateway but has a different MAC address than expected.
4. If such a discrepancy is found, it logs the details, sends an email notification, and updates the set of reported attackers to avoid duplicate notifications.
5. Finally, the script starts sniffing for ARP packets and processes them as they are captured.

This ARP Spoofing Detector script provides a robust solution for detecting and alerting on ARP spoofing attempts within a network. By following the setup and configuration steps, you can adapt it to your specific network environment and security requirements.
