# 🛡️ Mini Firewall (Python)

[![Python](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/) 


A lightweight Python firewall for intercepting TCP/UDP network packets and applying user-defined rules. Designed for **learning network security, packet inspection, and firewall logic**.

---

## 🔹 Features

- **Protocol Filtering:** Supports TCP (6) and UDP (17).  
- **Port-Based Rules:** Allow or deny packets based on destination port.  
- **Logging:** Logs all actions in `firewall_log.txt`.  
- **Interactive Rules:** Prompt-based setup for protocol, port, and action (`allow`, `deny`, or `log`).  
- **Real-Time Packet Handling:** Uses `NetfilterQueue` for live packet interception.  

---

## ⚙️ Installation

1. Clone the repository:

```bash
git clone https://github.com/yourusername/mini-firewall.git
cd mini-firewall
```
2. Install dependencies:

```bash
pip install NetfilterQueue
```
Note: Root privileges are required to intercept packets. Run the firewall script:
```bash
sudo python3 mini_firewall.py
```
Follow the interactive prompts to configure rules:

Protocol (6 for TCP, 17 for UDP)

Destination port (0–65535)

Action (allow, deny, or log)

## Limitations
-Supports IPv4 only.

-Basic TCP/UDP inspection, no deep packet inspection.

-Intended for educational purposes only, not production security.

