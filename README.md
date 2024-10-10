# Packet Sniffer Tool

## Overview
This project is a basic packet sniffer tool developed using Python and Scapy. The tool captures and analyzes network packets, providing information such as source and destination IP addresses, protocol, and payload data. This is my **fifth project** as part of my internship at **Prodigy InfoTech**.

## Features
- Captures network packets in real-time.
- Displays:
  - Source IP address
  - Destination IP address
  - Protocol (TCP, UDP, ICMP)
  - Source and Destination ports (for TCP and UDP)
  - Packet payload data (if available).
- Simple and easy to use.

## Requirements
- Python 3.x
- Scapy library

## Installation
To install the necessary dependencies,
use: pip install scapy

Usage

Clone the repository: git clone https://github.com/irfanahmd1/PRODIGY_CS_5.git

cd PRODIGY_CS_5

Run the script with superuser privileges:

sudo python3 packet_sniffer.py
The tool will capture and display relevant packet information in the terminal.

Example Output
yaml
Copy code
[*] Starting packet sniffer...

[+] Packet Captured:
Source IP: 10.0.2.15
Destination IP: 192.168.200.185
Protocol: 17
Source Port: 51975
Destination Port: 53
Payload: b'\x00...'
