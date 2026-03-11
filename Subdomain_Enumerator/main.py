import socket
import concurrent.futures

target = "nmap.org"

# Wordlist de subdomains comune
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

# Threading pentru viteza — 50 de threaduri in paralel
with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
    results = executor.map(check_subdomain, wordlist)

for result in results:
    if result:
        hostname, ip = result
        print(f"[FOUND]  {hostname:40} -> {ip}")
        found.append(result)

print(f"\nScan complete. {len(found)} subdomain(s) found.")