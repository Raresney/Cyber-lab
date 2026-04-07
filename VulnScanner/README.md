# VulnScanner - Web Vulnerability Scanner

A modular, multi-threaded web vulnerability scanner built in Python. Designed for authorized penetration testing and security assessments.

![Python](https://img.shields.io/badge/Python-3.8+-blue?style=flat-square&logo=python)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)
![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey?style=flat-square)

## Features

- **Web Crawler/Spider** — Automatic discovery of pages, forms, and parameters
- **SQL Injection Detection** — Error-based, boolean-based, and time-based blind SQLi
- **Cross-Site Scripting (XSS)** — Reflected XSS detection in parameters and forms
- **Path Traversal / LFI** — Local file inclusion with encoding bypass techniques
- **Security Headers Audit** — Checks for missing CSP, HSTS, X-Frame-Options, etc.
- **Directory Bruteforce** — Discovers hidden files, admin panels, backups, and exposed configs
- **Professional HTML Reports** — Risk scoring, severity classification, remediation guidance
- **Configurable via YAML** — Payloads, threading, rate-limiting, and module toggles
- **Rate Limiting** — Responsible scanning with configurable request delays

## Architecture

```
VulnScanner/
├── main.py                  # CLI entry point
├── config.yaml              # Scanner configuration
├── scanner/
│   ├── core.py              # Scan engine & orchestrator
│   ├── crawler.py           # Web spider / link discovery
│   ├── reporter.py          # HTML & JSON report generator
│   └── modules/
│       ├── sqli.py          # SQL Injection scanner
│       ├── xss.py           # XSS scanner
│       ├── traversal.py     # Path Traversal / LFI scanner
│       ├── headers.py       # Security Headers auditor
│       └── dirbrute.py      # Directory bruteforce
├── payloads/                # Payload wordlists
│   ├── sqli.txt
│   ├── xss.txt
│   ├── traversal.txt
│   └── directories.txt
├── reports/                 # Generated scan reports
└── testlab/                 # Vulnerable test application (Flask)
    └── app.py
```

## Installation

```bash
# Clone the repository
git clone https://github.com/Raresney/Cyber-Lab.git
cd Cyber-Lab/VulnScanner

# Install dependencies
pip install -r requirements.txt
```

## Usage

### Basic Scan

```bash
python main.py http://target.com
```

### Select Specific Modules

```bash
python main.py http://target.com -m sqli xss headers
```

### Verbose Output + JSON Report

```bash
python main.py http://target.com -vv -o json
```

### Custom Configuration

```bash
python main.py http://target.com -c custom_config.yaml --threads 20 --depth 5
```

### All Options

```
positional arguments:
  target                Target URL to scan

options:
  -m, --modules         Modules to run: sqli, xss, traversal, headers, dirbrute
  -v, --verbose         Increase verbosity (-v, -vv)
  -q, --quiet           Minimal output
  -o, --output          Report format: html, json
  -c, --config          Config file path
  --threads             Thread count
  --depth               Crawler depth
  --timeout             Request timeout (seconds)
  --no-crawl            Skip crawling, scan target URL only
```

## Testing with TestLab

A deliberately vulnerable Flask app is included for safe testing:

```bash
# Terminal 1: Start the vulnerable app
cd testlab
python app.py

# Terminal 2: Run the scanner against it
python main.py http://127.0.0.1:5000
```

The TestLab app includes:

- SQL Injection (search, login, profile pages)
- Reflected & Stored XSS (search, guestbook, profile)
- Path Traversal (file reader)
- Missing security headers
- Exposed admin panel, backup directory, debug info, .env file

## Sample Report

The scanner generates professional HTML reports with:

- Risk score calculation
- Severity classification (Critical / High / Medium / Low / Info)
- Evidence and proof-of-concept payloads
- Remediation guidance for each finding

## Disclaimer

**This tool is for authorized security testing only.** Only use VulnScanner against systems you have explicit permission to test. Unauthorized scanning is illegal and unethical. The authors are not responsible for misuse.

## Technologies

- Python 3.8+
- Requests (HTTP library)
- BeautifulSoup4 (HTML parsing)
- Flask (test application)
- PyYAML (configuration)
