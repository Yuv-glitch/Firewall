# 🛡️ Custom Python Firewall & Port Scan Detector

A simple but powerful network security project built entirely in Python — demonstrating real-time packet interception, IP/Port/DNS blocking, structured logging, and basic intrusion detection.

---

## 📌 Overview

This project is a lightweight, custom firewall that hooks directly into the Linux networking stack using **iptables** and **NetfilterQueue**. It inspects packets live, applies rules for blocking, detects port scans, and logs all actions to structured **JSON** files — similar to how a real IDS/IPS or SOC tool might work.

**Use Case:**  
- Personal learning project for aspiring SOC Analysts or Network Engineers  
- Demonstrates practical understanding of packet inspection, stateful detection, and basic threat response

---

## ✅ Features

- **IP Blocking:** Block packets from malicious or unwanted IP addresses.
- **Port Blocking:** Block traffic to specific destination ports.
- **DNS Filtering:** Drop DNS queries for blacklisted domains.
- **ICMP Packet Handling:** Drop ICMP packets from blocked IPs.
- **Port Scan Detection:** Detects when an IP scans more than *N* ports in a short window (default: 5 ports in 10 sec).
- **Auto-Banning:** Automatically bans suspicious IPs for a configurable duration (default: 10 minutes ban if IP is detected to detected by Port Scan Detection function).
- **Threaded Detection:** Runs detection logic in a separate thread while filtering continues.
- **JSON Logging:** Logs all blocked events, scans, and DNS requests in a structured, easy to understand format.

---

## ⚙️ How It Works

1. **Intercept Packets:** Uses `iptables` to forward packets to a user-space NetfilterQueue.
2. **Process Packets:** The Python script inspects packets with Scapy and applies custom rules.
3. **Detect Threats:** Maintains stateful tracking of unique ports accessed by each IP.
4. **Take Action:** Drops or accepts packets based on:
   - Blocked IP/Port lists
   - DNS domain blacklist
   - Port scan detection threshold
5. **Log Everything:** Records all actions in JSON files for easy analysis or future integration with a SIEM.

---

## 🚀 Getting Started

### 🔗 **Prerequisites**
- Linux (Ubuntu/Kali recommended)
- Python 3.8+
- `scapy` and `netfilterqueue` Python packages
- Root privileges (for `iptables`)

### 🗂️ **Installation**

```bash
# Install Python dependencies
pip install scapy NetfilterQueue

# Add iptables rule to forward packets to NFQUEUE
sudo iptables -I FORWARD -j NFQUEUE --queue-num 1
sudo iptables -I OUTPUT -j NFQUEUE --queue-num 1
sudo iptables -I INPUT -j NFQUEUE --queue-num 1

# Run the firewall
sudo python3 firewall.py

# To Reset iptables after use
sudo iptables -F
```
## ⭐ Final Words
- This project was created as more of a learning project -- PRs, ideas, improvements are welcome!
- Contact me on [Linkedin](https://www.linkedin.com/in/yuvraj-dudhal-0288a3248/)
- Made with :heart: in Python
