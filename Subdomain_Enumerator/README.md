# 🔎 Subdomain Enumerator

A fast Python subdomain enumerator that uses DNS resolution and multithreading to discover live subdomains of a target domain.

> Copyright (c) 2026 Bighiu Rares — [github.com/Raresney](https://github.com/Raresney)  
> Part of [Cyber-Lab](../README.md)

---

## 📋 Features

- Enumerates subdomains using an external wordlist (50 common entries included)
- DNS resolution via `socket.gethostbyname`
- 50 parallel threads for fast scanning
- Displays discovered subdomains with resolved IPs

---

## ⚙️ Requirements

- Python 3.7+
- No external libraries — pure Python `socket` + `concurrent.futures`

---

## 🚀 Usage

```bash
python main.py                  # default: nmap.org
python main.py example.com      # custom target
```

The script reads subdomains from `wordlist.txt` in the same directory. Edit the file to add your own entries.

---

## 📊 Sample Output

```
Enumerating subdomains for: nmap.org
Wordlist size: 50 entries

[FOUND]  www.nmap.org                             -> 45.33.49.119
[FOUND]  mail.nmap.org                            -> 45.33.49.119

Scan complete. 2 subdomain(s) found.
```

---

## 🛠️ Skills Demonstrated

- DNS enumeration & subdomain discovery
- Multithreading with `concurrent.futures`
- Passive reconnaissance techniques
- Python socket programming

---

## ⚠️ Disclaimer

Use only on domains you own or have explicit permission to scan.
