# 🔍 Port Scanner

A lightweight Python port scanner that checks for open ports on a target and grabs service banners where possible.

> Copyright (c) 2026 Bighiu Rares — [github.com/Raresney](https://github.com/Raresney)  
> Part of [Cyber-Lab](../README.md)

---

## 📋 Features

- Scans a predefined list of common ports
- Identifies service running on each port
- Grabs HTTP banners on ports 80, 443, 8080
- Shows open/closed status for each port

---

## ⚙️ Requirements

- Python 3.7+
- No external libraries — pure Python `socket`

---

## 🚀 Usage

```bash
python main.py
```

Change the target at the top of the file:

```python
target = "scanme.nmap.org"  # replace with your target
```

---

## 📊 Sample Output

```
Scanning scanme.nmap.org...

[OPEN]  Port    22 — SSH
[OPEN]  Port    80 — HTTP
         Banner: HTTP/1.1 200 OK
[closed] Port   443 — HTTPS
[closed] Port  3306 — MySQL

Scan complete.
```

---

## 🔎 Ports Scanned

| Port | Service  |
| ---- | -------- |
| 21   | FTP      |
| 22   | SSH      |
| 23   | Telnet   |
| 25   | SMTP     |
| 53   | DNS      |
| 80   | HTTP     |
| 110  | POP3     |
| 143  | IMAP     |
| 443  | HTTPS    |
| 3306 | MySQL    |
| 3389 | RDP      |
| 8080 | HTTP-Alt |

---

## 🛠️ Skills Demonstrated

- TCP socket programming
- Port scanning & service detection
- Banner grabbing (HTTP)
- Network reconnaissance basics

---

## ⚠️ Disclaimer

Use only on systems you own or have explicit permission to scan.  
`scanme.nmap.org` is a legal target provided by Nmap for testing purposes.
