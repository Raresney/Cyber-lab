"""
Path Traversal Scanner Module
Detects Local File Inclusion (LFI) and directory traversal vulnerabilities.
"""

import re
import time
import requests
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from ..models import Vulnerability


# Patterns that indicate successful file read
FILE_SIGNATURES = [
    # Linux
    (r"root:.*:0:0:", "/etc/passwd"),
    (r"daemon:.*:1:1:", "/etc/passwd"),
    (r"bin:.*:2:2:", "/etc/passwd"),
    (r"\[boot loader\]", "boot.ini"),
    # Windows
    (r"# Copyright.*Microsoft", "win.ini / hosts"),
    (r"127\.0\.0\.1\s+localhost", "hosts file"),
    (r"\[fonts\]", "win.ini"),
    (r"\[extensions\]", "win.ini"),
    # Generic
    (r"HTTP_USER_AGENT", "/proc/self/environ"),
    (r"DOCUMENT_ROOT", "/proc/self/environ"),
    (r"Linux version", "/proc/version"),
]


class TraversalScanner:
    def __init__(self, payloads: list, timeout: int = 10, rate_limit: float = 0.1,
                 config: dict = None, verbose: int = 1):
        self.payloads = payloads
        self.timeout = timeout
        self.rate_limit = rate_limit
        self.config = config or {}
        self.verbose = verbose
        self.session = requests.Session()
        self.session.verify = False

    def scan(self, urls: list, forms: list) -> list:
        vulnerabilities = []

        # Test URL parameters (most common vector for LFI)
        for url in urls:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            if not params:
                continue

            # Prioritize parameters that look file-related
            for param_name in params:
                vulns = self._test_parameter(url, param_name)
                vulnerabilities.extend(vulns)

        # Test form inputs
        for form in forms:
            for inp in form.inputs:
                if inp["type"] in ("submit", "button"):
                    continue
                vulns = self._test_form(form, inp["name"])
                vulnerabilities.extend(vulns)

        return vulnerabilities

    def _test_parameter(self, url: str, param: str) -> list:
        vulns = []
        parsed = urlparse(url)

        for payload in self.payloads:
            time.sleep(self.rate_limit)
            params = parse_qs(parsed.query, keep_blank_values=True)
            params[param] = [payload]

            new_query = urlencode(params, doseq=True)
            test_url = urlunparse(parsed._replace(query=new_query))

            try:
                resp = self.session.get(test_url, timeout=self.timeout)
            except requests.RequestException:
                continue

            detected_file = self._check_file_content(resp.text)
            if detected_file:
                severity = "CRITICAL" if "passwd" in detected_file or "shadow" in detected_file else "HIGH"
                vulns.append(Vulnerability(
                    url=url,
                    module="Path Traversal",
                    severity=severity,
                    title=f"Path Traversal / LFI in '{param}'",
                    description=f"Successfully read server file ({detected_file}) via parameter '{param}'.",
                    evidence=resp.text[:300],
                    payload=payload,
                    parameter=param,
                    remediation="Never use user input directly in file paths. "
                                "Use a whitelist of allowed files. "
                                "Implement proper input validation and sanitization.",
                ))
                return vulns

        return vulns

    def _test_form(self, form, input_name: str) -> list:
        vulns = []

        for payload in self.payloads:
            time.sleep(self.rate_limit)
            data = {}
            for inp in form.inputs:
                if inp["name"] == input_name:
                    data[inp["name"]] = payload
                else:
                    data[inp["name"]] = inp.get("value", "test")

            try:
                if form.method == "POST":
                    resp = self.session.post(form.action, data=data, timeout=self.timeout)
                else:
                    resp = self.session.get(form.action, params=data, timeout=self.timeout)
            except requests.RequestException:
                continue

            detected_file = self._check_file_content(resp.text)
            if detected_file:
                vulns.append(Vulnerability(
                    url=form.url,
                    module="Path Traversal",
                    severity="CRITICAL",
                    title=f"Path Traversal / LFI in form field '{input_name}'",
                    description=f"Successfully read server file ({detected_file}) via form field '{input_name}'.",
                    evidence=resp.text[:300],
                    payload=payload,
                    parameter=input_name,
                    remediation="Never use user input directly in file paths. Use a whitelist.",
                ))
                return vulns

        return vulns

    def _check_file_content(self, response_text: str) -> str:
        for pattern, file_name in FILE_SIGNATURES:
            if re.search(pattern, response_text, re.IGNORECASE):
                return file_name
        return ""
