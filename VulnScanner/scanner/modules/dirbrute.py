"""
Directory Bruteforce Scanner Module
Discovers hidden files and directories on the target.
"""

import time
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urljoin
from ..models import Vulnerability


INTERESTING_FINDINGS = {
    ".git": ("HIGH", "Git repository exposed - source code and history may be accessible"),
    ".git/config": ("HIGH", "Git config exposed - may contain credentials or repo info"),
    ".git/HEAD": ("HIGH", "Git HEAD exposed - confirms repository presence"),
    ".env": ("CRITICAL", "Environment file exposed - may contain secrets, API keys, passwords"),
    ".env.local": ("CRITICAL", "Local environment file exposed"),
    ".env.production": ("CRITICAL", "Production environment file exposed"),
    ".env.backup": ("CRITICAL", "Backup environment file exposed"),
    ".htpasswd": ("CRITICAL", "Password file exposed"),
    ".htaccess": ("MEDIUM", "Apache config exposed"),
    "phpinfo.php": ("HIGH", "PHP info page exposed - reveals server configuration"),
    "info.php": ("HIGH", "PHP info page exposed"),
    "phpmyadmin": ("HIGH", "phpMyAdmin interface accessible"),
    "adminer": ("HIGH", "Adminer database tool accessible"),
    "wp-admin": ("MEDIUM", "WordPress admin panel found"),
    "admin": ("MEDIUM", "Admin panel found"),
    "backup": ("HIGH", "Backup directory found"),
    "backups": ("HIGH", "Backups directory found"),
    "dump": ("HIGH", "Database dump directory found"),
    "config.php": ("HIGH", "PHP config file accessible"),
    "config.yml": ("MEDIUM", "YAML config file accessible"),
    "config.yaml": ("MEDIUM", "YAML config file accessible"),
    "config.json": ("MEDIUM", "JSON config file accessible"),
    "web.config": ("MEDIUM", "IIS config file accessible"),
    "robots.txt": ("INFO", "Robots.txt found - may reveal hidden paths"),
    "sitemap.xml": ("INFO", "Sitemap found"),
    "security.txt": ("INFO", "Security.txt found"),
    ".well-known/security.txt": ("INFO", "Security.txt found"),
    "server-status": ("MEDIUM", "Apache server-status exposed"),
    "server-info": ("MEDIUM", "Apache server-info exposed"),
    "swagger": ("INFO", "Swagger API docs found"),
    "graphql": ("INFO", "GraphQL endpoint found"),
    "api": ("INFO", "API endpoint found"),
    "console": ("HIGH", "Debug console found - may allow code execution"),
    "debug": ("HIGH", "Debug endpoint found"),
}


class DirBruteScanner:
    def __init__(self, wordlist: list, timeout: int = 10, rate_limit: float = 0.05,
                 threads: int = 20, status_codes: list = None,
                 config: dict = None, verbose: int = 1):
        self.wordlist = wordlist
        self.timeout = timeout
        self.rate_limit = rate_limit
        self.threads = threads
        self.status_codes = status_codes or [200, 201, 301, 302, 403]
        self.config = config or {}
        self.verbose = verbose
        self.session = requests.Session()
        self.session.verify = False

    def scan(self, urls: list, forms: list) -> list:
        if not urls:
            return []

        # Use the base URL for directory brute forcing
        target = urls[0]
        if not target.endswith("/"):
            target = target.rsplit("/", 1)[0] + "/"

        vulnerabilities = []

        # Get a 404 baseline to avoid false positives
        baseline_length = self._get_404_baseline(target)

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {}
            for path in self.wordlist:
                url = urljoin(target, path)
                future = executor.submit(self._check_path, url, baseline_length)
                futures[future] = path

            for future in as_completed(futures):
                result = future.result()
                if result:
                    vulnerabilities.append(result)

        return vulnerabilities

    def _get_404_baseline(self, target: str) -> int:
        try:
            resp = self.session.get(
                urljoin(target, "nonexistent_path_xyzzy_404_test"),
                timeout=self.timeout,
            )
            return len(resp.text)
        except requests.RequestException:
            return 0

    def _check_path(self, url: str, baseline_404_length: int) -> Vulnerability:
        time.sleep(self.rate_limit)
        try:
            resp = self.session.get(url, timeout=self.timeout, allow_redirects=False)
        except requests.RequestException:
            return None

        if resp.status_code not in self.status_codes:
            return None

        # Filter out soft 404s (pages that return 200 but are actually error pages)
        if resp.status_code == 200 and baseline_404_length > 0:
            if abs(len(resp.text) - baseline_404_length) < 50:
                return None

        # Determine the path from URL
        from urllib.parse import urlparse
        path = urlparse(url).path.lstrip("/")

        info = INTERESTING_FINDINGS.get(path, None)
        if info:
            severity, desc = info
        else:
            severity = "INFO"
            desc = f"Directory/file found (HTTP {resp.status_code})"

        # Upgrade severity for 200 status on sensitive files
        if resp.status_code == 200 and severity in ("INFO", "LOW"):
            severity = "MEDIUM" if path in ("admin", "console", "debug") else severity

        status_desc = {
            200: "accessible",
            301: "redirects",
            302: "redirects",
            403: "forbidden (exists but restricted)",
        }.get(resp.status_code, f"HTTP {resp.status_code}")

        return Vulnerability(
            url=url,
            module="Directory Bruteforce",
            severity=severity,
            title=f"Found: /{path} ({status_desc})",
            description=desc,
            evidence=f"HTTP {resp.status_code} | Size: {len(resp.text)} bytes | "
                     f"Content-Type: {resp.headers.get('Content-Type', 'N/A')}",
            remediation="Restrict access to sensitive files and directories. "
                        "Remove unnecessary files from production. "
                        "Configure proper access controls.",
        )
