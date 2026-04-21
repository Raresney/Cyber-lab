# 🔐 Cyber-Lab

> A personal lab for hands-on cybersecurity and Python practice.
> Built step by step — tools, notes, and experiments as I learn and improve.

---

## 🧰 Tools

| Tool                                                      | Description                                             | Type             |
| --------------------------------------------------------- | ------------------------------------------------------- | ---------------- |
| 🔍 [Port Scanner](./Port_Scanner/main.py)                 | Scans a target for open ports and grabs service banners | 🔴 Red / 🔵 Blue |
| 🔎 [Subdomain Enumerator](./Subdomain_Enumerator/main.py) | Enumerates subdomains using wordlist + DNS lookup       | 🔴 Red           |
| 🔐 [Hydra BruteForce](./Hydra_BruteForce/)                | FTP brute force demo using Hydra and a custom wordlist  | 🔴 Red           |
| 📡 [Packet Sniffer](./Packet_Sniffer/main.py)             | Real-time packet capture with ARP spoof detection       | 🔵 Blue          |
| 🛡️ [VulnScanner](./VulnScanner/)                          | Multi-module web vulnerability scanner with HTML reports | 🔴 Red           |
| 🧠 [DeepfakeDetector](./DeepfakeDetector/)                | Detects deepfake video/audio using biometric + neural analysis | 🔵 Blue / 🤖 AI |

---

## 📚 Areas of Practice

- 🔴 **Offensive Security** — port scanning, banner grabbing, reconnaissance, brute force, web vulnerability scanning
- 🔵 **Defensive Security** — log analysis, threat detection, SOC concepts, deepfake detection
- 🤖 **AI / ML for Security** — neural networks for media authenticity, biometric signal analysis
- 🐍 **Python for Security** — building tools from scratch to reinforce fundamentals
- 🧪 **Labs** — TryHackMe, Hack The Box, hands-on experiments

---

## 🗂️ Structure

```
Cyber-Lab/
│
├── 📄 README.md
├── 🔍 Port_Scanner/
│   └── main.py               # Port scanner with banner grabbing
│
├── 🔎 Subdomain_Enumerator/
│   ├── main.py               # Subdomain enumeration via DNS lookup
│   └── wordlist.txt          # Default subdomain wordlist
│
├── 🔐 Hydra_BruteForce/
│   ├── setup.sh              # Automated setup script
│   ├── wordlists/
│   │   └── test_wordlist.txt
│   └── README.md
│
├── 📡 Packet_Sniffer/
│   ├── main.py               # Packet sniffer with ARP spoof detection
│   └── README.md
│
├── 🛡️ VulnScanner/
│   ├── main.py               # CLI entry point
│   ├── config.yaml           # Scanner configuration
│   ├── scanner/              # Core engine, crawler, reporter, modules
│   ├── payloads/             # SQLi, XSS, traversal, directory wordlists
│   ├── testlab/              # Vulnerable Flask app for testing
│   └── README.md
│
└── 🧠 DeepfakeDetector/
    ├── main.py               # CLI entry point
    ├── app.py                # Streamlit web UI with gauges & charts
    ├── train.py              # Training script for FaceForensics++
    ├── detector/             # Video, audio, face, neural analyzers
    ├── utils/                # Frame extraction helpers
    └── README.md
```

---

_⚡ This repo grows as I learn. Check back often._
