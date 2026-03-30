# Network Packet Sniffer

A real-time network packet sniffer built with Scapy that captures, parses, and analyzes network traffic with ARP spoofing detection.

> Copyright (c) 2026 Bighiu Rares — [github.com/Raresney](https://github.com/Raresney)
> Part of [Cyber-Lab](../README.md)

---

## Features

- Real-time packet capture and analysis
- Protocol parsing: TCP, UDP, ICMP, DNS, HTTP, ARP
- ARP spoofing detection — alerts when a MAC address changes for a known IP
- HTTP request inspection (method + URL)
- DNS query logging
- Color-coded output by protocol
- Traffic statistics summary at the end

---

## Requirements

- Python 3.7+
- Scapy (`pip install scapy`)
- **Windows:** Npcap ([npcap.com](https://npcap.com)) — install with "WinPcap API-compatible Mode"
- **Linux:** root privileges (`sudo`)

---

## Usage

```bash
# Capture 50 packets (default)
python main.py

# Capture 100 packets
python main.py 100

# Capture 200 packets on a specific interface
python main.py 200 eth0
```

> **Important:** Must run as **Administrator** (Windows) or with **sudo** (Linux) to capture packets.

---

## Sample Output

```
============================================================
  Packet Sniffer — capturing 50 packets
  Press Ctrl+C to stop early
============================================================

[TCP]  192.168.1.5    :54321 -> 142.250.74.46  :443    Flags: A     Size: 66
[DNS]  192.168.1.5     -> 192.168.1.1      Query: github.com
[HTTP] 192.168.1.5     -> 93.184.216.34    GET /index.html HTTP/1.1
[ICMP] 192.168.1.5     -> 8.8.8.8          Echo Request
[ARP]  Who has 192.168.1.1? Tell 192.168.1.5
[UDP]  192.168.1.5    :5353  -> 224.0.0.251  :5353   Size: 82

============================================================
  Capture Statistics (12.3s)
============================================================
  Total packets:      50
  TCP    packets:     28  (56.0%)
  UDP    packets:     10  (20.0%)
  DNS    packets:      6  (12.0%)
  ICMP   packets:      3  (6.0%)
  HTTP   packets:      2  (4.0%)
  ARP    packets:      1  (2.0%)
============================================================
```

---

## ARP Spoofing Detection

The sniffer monitors ARP replies and maintains a mapping of IP to MAC addresses. If an IP suddenly appears with a different MAC, it triggers an alert:

```
  [!! ARP SPOOF DETECTED !!] 192.168.1.1 changed MAC: aa:bb:cc:dd:ee:ff -> 11:22:33:44:55:66
```

---

## Protocols Analyzed

| Protocol | What it shows |
|----------|---------------|
| TCP      | Source/dest IP:port, flags, packet size |
| UDP      | Source/dest IP:port, packet size |
| ICMP     | Source/dest IP, type (Echo Request/Reply, Unreachable, TTL Expired) |
| DNS      | Source/dest IP, queried domain name |
| HTTP     | Source/dest IP, request method and URL |
| ARP      | ARP requests and replies, spoof detection |

---

## Skills Demonstrated

- Network protocol analysis (TCP/IP stack)
- Packet capture with Scapy
- ARP spoofing detection (defensive security)
- Real-time traffic monitoring
- Python networking fundamentals

---

## Disclaimer

Use only on networks you own or have explicit permission to monitor.
Unauthorized packet sniffing may violate local laws.
