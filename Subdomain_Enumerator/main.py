import socket
import sys
import os
import concurrent.futures

target = sys.argv[1] if len(sys.argv) > 1 else "nmap.org"

# Citeste wordlist din fisier daca exista, altfel foloseste lista default
wordlist_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "wordlist.txt")

if os.path.isfile(wordlist_path):
    with open(wordlist_path) as f:
        wordlist = [line.strip() for line in f if line.strip()]
else:
    wordlist = [
        "www", "mail", "ftp", "smtp", "pop", "imap",
        "webmail", "admin", "portal", "vpn", "remote",
        "dev", "staging", "test", "api", "app",
        "blog", "forum", "shop", "store", "static",
        "cdn", "media", "img", "images", "assets",
        "ns1", "ns2", "dns", "mx", "relay",
        "ssh", "shell", "git", "gitlab", "github",
        "jira", "confluence", "jenkins", "ci", "cd",
        "monitor", "status", "health", "dashboard",
        "backup", "db", "database", "mysql", "postgres",
        "internal", "intranet", "corp", "office", "cloud"
    ]

def check_subdomain(sub):
    hostname = f"{sub}.{target}"
    try:
        ip = socket.gethostbyname(hostname)
        return (hostname, ip)
    except socket.gaierror:
        return None

print(f"Enumerating subdomains for: {target}")
print(f"Wordlist size: {len(wordlist)} entries\n")

found = []

with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
    for result in executor.map(check_subdomain, wordlist):
        if result:
            hostname, ip = result
            print(f"[FOUND]  {hostname:40} -> {ip}")
            found.append(result)

print(f"\nScan complete. {len(found)} subdomain(s) found.")
