Mini Firewall (Python)

A simple Python-based firewall that inspects incoming packets at the network layer and applies user-defined rules on TCP/UDP traffic. Designed for educational and testing purposes.

Features

Protocol Filtering: Supports TCP (6) and UDP (17).

Port-Based Rules: Allow or deny packets based on destination port.

Logging: All actions are logged to firewall_log.txt.

Interactive Rule Input: Prompt-based setup for protocol, destination port, and action (allow, deny, or log).

Netfilter Integration: Uses NetfilterQueue to intercept and handle packets in real-time.

Usage

Install dependencies:

pip install NetfilterQueue


Run the script with root privileges (required for packet interception):

sudo python3 mini_firewall.py


Input rules as prompted (protocol, destination port, action).

Firewall logs actions in firewall_log.txt.

Limitations

Only supports IPv4.

Basic TCP/UDP inspection; no deep packet inspection.

Designed for learning purposes, not production-grade security.
