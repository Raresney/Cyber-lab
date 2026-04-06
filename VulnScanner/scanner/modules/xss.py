"""
XSS (Cross-Site Scripting) Scanner Module
Detects reflected XSS in URL parameters and form inputs.
"""

import re
import time
import requests
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from ..models import Vulnerability


class XSSScanner:
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

        # Test URL parameters
        for url in urls:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            if not params:
                continue

            for param_name in params:
                vulns = self._test_parameter(url, param_name)
                vulnerabilities.extend(vulns)

        # Test form inputs
        for form in forms:
            for inp in form.inputs:
                if inp["type"] in ("submit", "hidden", "button", "password"):
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

            if self._is_reflected(payload, resp.text):
                vulns.append(Vulnerability(
                    url=url,
                    module="XSS",
                    severity="HIGH",
                    title=f"Reflected XSS in parameter '{param}'",
                    description=f"The payload was reflected unescaped in the response for parameter '{param}'.",
                    evidence=self._extract_context(payload, resp.text),
                    payload=payload,
                    parameter=param,
                    remediation="Encode all user input before rendering in HTML. "
                                "Use Content-Security-Policy headers. "
                                "Apply context-aware output encoding.",
                ))
                return vulns  # One per param

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

            if self._is_reflected(payload, resp.text):
                vulns.append(Vulnerability(
                    url=form.url,
                    module="XSS",
                    severity="HIGH",
                    title=f"Reflected XSS in form field '{input_name}'",
                    description=f"XSS payload reflected unescaped in form field '{input_name}' at {form.action}.",
                    evidence=self._extract_context(payload, resp.text),
                    payload=payload,
                    parameter=input_name,
                    remediation="Encode all user input before rendering in HTML. "
                                "Use Content-Security-Policy headers.",
                ))
                return vulns

        return vulns

    def _is_reflected(self, payload: str, response_body: str) -> bool:
        # Check if payload appears in response unescaped
        if payload in response_body:
            # Verify it's in HTML context (not just in a script variable as a string)
            dangerous_patterns = [
                r"<script[^>]*>",
                r"onerror\s*=",
                r"onload\s*=",
                r"onfocus\s*=",
                r"onclick\s*=",
                r"onmouseover\s*=",
                r"ontoggle\s*=",
                r"onstart\s*=",
                r"<img[^>]+onerror",
                r"<svg[^>]+onload",
                r"javascript:",
                r"<iframe",
            ]
            for pattern in dangerous_patterns:
                if re.search(pattern, response_body, re.IGNORECASE):
                    return True
            # Even plain reflection is worth reporting
            return True
        return False

    def _extract_context(self, payload: str, html: str) -> str:
        idx = html.find(payload)
        if idx == -1:
            return ""
        start = max(0, idx - 40)
        end = min(len(html), idx + len(payload) + 40)
        return html[start:end].strip()
