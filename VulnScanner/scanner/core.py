"""
VulnScanner Core Engine
Orchestrates crawling, scanning modules, and reporting.
"""

import time
import yaml
import os
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional
from urllib.parse import urlparse

from .models import Vulnerability, ScanResult
from .crawler import Crawler
from .modules.sqli import SQLiScanner
from .modules.xss import XSSScanner
from .modules.traversal import TraversalScanner
from .modules.headers import HeadersScanner
from .modules.dirbrute import DirBruteScanner
from .reporter import ReportGenerator


BANNER = r"""
 __      __    _        _____
 \ \    / /   | |      / ____|
  \ \  / /   _| |_ __ | (___   ___ __ _ _ __  _ __   ___ _ __
   \ \/ / | | | | '_ \ \___ \ / __/ _` | '_ \| '_ \ / _ \ '__|
    \  /| |_| | | | | |____) | (_| (_| | | | | | | |  __/ |
     \/  \__,_|_|_| |_|_____/ \___\__,_|_| |_|_| |_|\___|_|
                                                        v1.0.0
    [ Web Vulnerability Scanner ]
    [ For authorized testing only ]
"""

COLORS = {
    "RED": "\033[91m",
    "GREEN": "\033[92m",
    "YELLOW": "\033[93m",
    "BLUE": "\033[94m",
    "MAGENTA": "\033[95m",
    "CYAN": "\033[96m",
    "WHITE": "\033[97m",
    "BOLD": "\033[1m",
    "RESET": "\033[0m",
}


def colorize(color: str, text: str) -> str:
    return f"{COLORS.get(color, '')}{text}{COLORS['RESET']}"


class VulnScanner:
    def __init__(self, config_path: str = "config.yaml", verbose: int = 1):
        self.verbose = verbose
        self.config = self._load_config(config_path)
        self.result = None

        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        self.payloads_dir = os.path.join(base_dir, "payloads")
        self.reports_dir = os.path.join(base_dir, self.config["reporting"]["output_dir"])
        os.makedirs(self.reports_dir, exist_ok=True)

    def _load_config(self, path: str) -> dict:
        base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        full_path = os.path.join(base_dir, path) if not os.path.isabs(path) else path
        if os.path.exists(full_path):
            with open(full_path, "r") as f:
                return yaml.safe_load(f)
        # Default config if file not found
        return {
            "scanner": {
                "threads": 10,
                "timeout": 10,
                "rate_limit": 0.1,
                "max_depth": 3,
                "max_pages": 100,
                "user_agent": "VulnScanner/1.0",
                "follow_redirects": True,
                "verify_ssl": False,
            },
            "modules": {
                "sqli": {"enabled": True},
                "xss": {"enabled": True},
                "traversal": {"enabled": True},
                "headers": {"enabled": True},
                "dirbrute": {"enabled": True},
            },
            "reporting": {"format": "html", "output_dir": "reports", "include_evidence": True},
        }

    def _load_payloads(self, filename: str) -> list:
        path = os.path.join(self.payloads_dir, filename)
        if not os.path.exists(path):
            self.log(f"  [!] Payload file not found: {path}", "YELLOW")
            return []
        with open(path, "r", encoding="utf-8") as f:
            return [
                line.strip()
                for line in f
                if line.strip() and not line.startswith("#")
            ]

    def log(self, message: str, color: str = "WHITE", level: int = 1):
        if self.verbose >= level:
            print(colorize(color, message))

    def scan(self, target: str, modules: Optional[list] = None) -> ScanResult:
        parsed = urlparse(target)
        if not parsed.scheme:
            target = f"http://{target}"

        self.result = ScanResult(target=target)
        self.result.start_time = time.time()

        print(colorize("CYAN", BANNER))
        self.log(f"  Target: {target}", "BOLD")
        self.log(f"  Started: {time.strftime('%Y-%m-%d %H:%M:%S')}", "WHITE")
        print(colorize("CYAN", "  " + "=" * 56))

        # Phase 1: Crawl
        self.log("\n[*] Phase 1: Crawling & Discovery", "BLUE")
        crawler = Crawler(
            target,
            max_depth=self.config["scanner"]["max_depth"],
            max_pages=self.config["scanner"]["max_pages"],
            timeout=self.config["scanner"]["timeout"],
            rate_limit=self.config["scanner"]["rate_limit"],
            user_agent=self.config["scanner"]["user_agent"],
            verify_ssl=self.config["scanner"]["verify_ssl"],
        )
        urls, forms = crawler.crawl()
        self.result.urls_discovered = urls
        self.result.forms_discovered = forms
        self.result.pages_crawled = len(urls)

        self.log(f"    Found {len(urls)} URLs", "GREEN")
        self.log(f"    Found {len(forms)} forms", "GREEN")
        for url in urls:
            self.log(f"      {url}", "WHITE", level=2)

        # Phase 2: Active Scanning
        self.log("\n[*] Phase 2: Active Scanning", "BLUE")

        active_modules = self._get_active_modules(modules)

        for mod_name, mod_instance in active_modules:
            self.log(f"\n  [{mod_name}] Running...", "MAGENTA")
            try:
                vulns = mod_instance.scan(urls, forms)
                self.result.vulnerabilities.extend(vulns)
                if vulns:
                    self.log(f"  [{mod_name}] Found {len(vulns)} issue(s)!", "RED")
                    for v in vulns:
                        sev_color = {
                            "CRITICAL": "RED",
                            "HIGH": "RED",
                            "MEDIUM": "YELLOW",
                            "LOW": "CYAN",
                            "INFO": "WHITE",
                        }.get(v.severity, "WHITE")
                        self.log(
                            f"    [{v.severity}] {v.title} @ {v.url}", sev_color
                        )
                        if v.payload:
                            self.log(f"      Payload: {v.payload}", "WHITE", level=2)
                else:
                    self.log(f"  [{mod_name}] No issues found", "GREEN")
            except Exception as e:
                self.log(f"  [{mod_name}] Error: {e}", "RED")

        # Phase 3: Report
        self.result.end_time = time.time()
        self.log("\n[*] Phase 3: Generating Report", "BLUE")

        reporter = ReportGenerator(self.reports_dir, self.config["reporting"])
        report_path = reporter.generate(self.result)
        self.log(f"    Report saved: {report_path}", "GREEN")

        # Summary
        self._print_summary()

        return self.result

    def _get_active_modules(self, requested: Optional[list] = None) -> list:
        sc = self.config["scanner"]
        mod_config = self.config["modules"]

        all_modules = {
            "SQLi": (
                mod_config.get("sqli", {}),
                lambda cfg: SQLiScanner(
                    payloads=self._load_payloads("sqli.txt"),
                    timeout=sc["timeout"],
                    rate_limit=sc["rate_limit"],
                    config=cfg,
                    verbose=self.verbose,
                ),
            ),
            "XSS": (
                mod_config.get("xss", {}),
                lambda cfg: XSSScanner(
                    payloads=self._load_payloads("xss.txt"),
                    timeout=sc["timeout"],
                    rate_limit=sc["rate_limit"],
                    config=cfg,
                    verbose=self.verbose,
                ),
            ),
            "Path Traversal": (
                mod_config.get("traversal", {}),
                lambda cfg: TraversalScanner(
                    payloads=self._load_payloads("traversal.txt"),
                    timeout=sc["timeout"],
                    rate_limit=sc["rate_limit"],
                    config=cfg,
                    verbose=self.verbose,
                ),
            ),
            "Security Headers": (
                mod_config.get("headers", {}),
                lambda cfg: HeadersScanner(
                    timeout=sc["timeout"],
                    config=cfg,
                    verbose=self.verbose,
                ),
            ),
            "Dir Bruteforce": (
                mod_config.get("dirbrute", {}),
                lambda cfg: DirBruteScanner(
                    wordlist=self._load_payloads("directories.txt"),
                    timeout=sc["timeout"],
                    rate_limit=sc["rate_limit"],
                    threads=cfg.get("threads", 20),
                    status_codes=cfg.get("status_codes", [200, 301, 302, 403]),
                    config=cfg,
                    verbose=self.verbose,
                ),
            ),
        }

        active = []
        for name, (cfg, factory) in all_modules.items():
            if requested and name.lower().replace(" ", "") not in [
                r.lower().replace(" ", "") for r in requested
            ]:
                continue
            if cfg.get("enabled", True):
                active.append((name, factory(cfg)))

        return active

    def _print_summary(self):
        r = self.result
        counts = r.severity_counts

        print(colorize("CYAN", "\n  " + "=" * 56))
        print(colorize("BOLD", "  SCAN SUMMARY"))
        print(colorize("CYAN", "  " + "=" * 56))
        self.log(f"  Target:        {r.target}", "WHITE")
        self.log(f"  Duration:      {r.duration:.1f}s", "WHITE")
        self.log(f"  Pages crawled: {r.pages_crawled}", "WHITE")
        self.log(f"  Forms found:   {len(r.forms_discovered)}", "WHITE")
        print()
        self.log(f"  Vulnerabilities: {len(r.vulnerabilities)}", "BOLD")
        if counts["CRITICAL"]:
            self.log(f"    CRITICAL: {counts['CRITICAL']}", "RED")
        if counts["HIGH"]:
            self.log(f"    HIGH:     {counts['HIGH']}", "RED")
        if counts["MEDIUM"]:
            self.log(f"    MEDIUM:   {counts['MEDIUM']}", "YELLOW")
        if counts["LOW"]:
            self.log(f"    LOW:      {counts['LOW']}", "CYAN")
        if counts["INFO"]:
            self.log(f"    INFO:     {counts['INFO']}", "WHITE")
        print(colorize("CYAN", "  " + "=" * 56))
