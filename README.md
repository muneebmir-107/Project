# Project
# Personal Firewall using Python

## Project Overview
This project implements a simple yet functional personal firewall using Python and Scapy. It monitors live network traffic and filters packets based on user-defined rules such as blocked IP addresses, restricted ports, and allowed protocols. Suspicious packets are logged for later analysis.

## Objective
To build a lightweight firewall application that provides:
- Custom rule-based filtering of incoming/outgoing traffic
- Real-time packet inspection and monitoring
- Logging of all blocked and allowed packets

## Tools Used
- **Python 3.x** – Core language
- **Scapy** – For packet sniffing and analysis
- **Logging module** – For audit logs
- *(Optional)* **iptables** – For Linux-level rule enforcement
- *(Optional)* **Tkinter** – To build a GUI

## Installation & Setup

### 1. Clone or Download the Repository
```
git clone https://github.com/yourusername/personal-firewall.git
cd personal-firewall
```

### 2. Install Required Python Packages
```
pip install scapy


## 🚀 How to Run
``
python firewall.py
```

You’ll see output like:
```
Firewall is running... Press Ctrl+C to stop.
[BLOCKED] IP 192.169.1.7
[ALLOWED] 192.169.1.2:1234 → 8.8.8.8:80 TCP
```

## How It Works
1. **Packet Sniffing** – Uses Scapy’s `sniff()` to monitor network packets in real-time.
2. **Rule Checking** – Matches source IPs, destination ports, and protocols against the rule set.
3. **Logging** – All activity is recorded in `firewall_log.txt` using Python’s `logging` module.
4. **(Optional)** – Enforces deeper system rules using `iptables` on Linux.

