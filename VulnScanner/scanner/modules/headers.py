"""
Security Headers Audit Module
Checks for missing or misconfigured security headers.
"""

import requests
from ..models import Vulnerability


HEADER_INFO = {
    "Content-Security-Policy": {
        "severity": "MEDIUM",
        "description": "CSP helps prevent XSS, clickjacking, and other code injection attacks.",
        "remediation": "Implement a Content-Security-Policy header with strict directives. "
                       "Example: Content-Security-Policy: default-src 'self'; script-src 'self'",
    },
    "X-Content-Type-Options": {
        "severity": "LOW",
        "description": "Prevents MIME-type sniffing which can lead to security vulnerabilities.",
        "remediation": "Add header: X-Content-Type-Options: nosniff",
    },
    "X-Frame-Options": {
        "severity": "MEDIUM",
        "description": "Protects against clickjacking attacks by controlling iframe embedding.",
        "remediation": "Add header: X-Frame-Options: DENY or X-Frame-Options: SAMEORIGIN",
    },
    "Strict-Transport-Security": {
        "severity": "MEDIUM",
        "description": "HSTS forces browsers to use HTTPS, preventing downgrade attacks and cookie hijacking.",
        "remediation": "Add header: Strict-Transport-Security: max-age=31536000; includeSubDomains",
    },
    "X-XSS-Protection": {
        "severity": "LOW",
        "description": "Enables browser's built-in XSS filter (legacy but still useful for older browsers).",
        "remediation": "Add header: X-XSS-Protection: 1; mode=block",
    },
    "Referrer-Policy": {
        "severity": "LOW",
        "description": "Controls how much referrer information is sent with requests.",
        "remediation": "Add header: Referrer-Policy: strict-origin-when-cross-origin",
    },
    "Permissions-Policy": {
        "severity": "LOW",
        "description": "Controls which browser features can be used (camera, microphone, geolocation, etc.).",
        "remediation": "Add header: Permissions-Policy: camera=(), microphone=(), geolocation=()",
    },
}


class HeadersScanner:
    def __init__(self, timeout: int = 10, config: dict = None, verbose: int = 1):
        self.timeout = timeout
        self.config = config or {}
        self.verbose = verbose
        self.session = requests.Session()
        self.session.verify = False

        self.required_headers = self.config.get(
            "required_headers", list(HEADER_INFO.keys())
        )

    def scan(self, urls: list, forms: list) -> list:
        vulnerabilities = []

        # Only test the main target URL (first one)
        if not urls:
            return vulnerabilities

        target = urls[0]

        try:
            resp = self.session.get(target, timeout=self.timeout)
        except requests.RequestException:
            return vulnerabilities

        headers = resp.headers

        # Check for missing headers
        for header_name in self.required_headers:
            if header_name not in headers:
                info = HEADER_INFO.get(header_name, {})
                vulnerabilities.append(Vulnerability(
                    url=target,
                    module="Security Headers",
                    severity=info.get("severity", "LOW"),
                    title=f"Missing Security Header: {header_name}",
                    description=info.get("description", f"The {header_name} header is not set."),
                    evidence=f"Header '{header_name}' not found in response",
                    remediation=info.get("remediation", f"Add the {header_name} header to server responses."),
                ))

        # Check for information disclosure headers
        disclosure_headers = {
            "Server": "Server version disclosure",
            "X-Powered-By": "Technology stack disclosure",
            "X-AspNet-Version": "ASP.NET version disclosure",
            "X-AspNetMvc-Version": "ASP.NET MVC version disclosure",
        }

        for header_name, desc in disclosure_headers.items():
            if header_name in headers:
                vulnerabilities.append(Vulnerability(
                    url=target,
                    module="Security Headers",
                    severity="INFO",
                    title=f"Information Disclosure: {desc}",
                    description=f"The server exposes {header_name}: {headers[header_name]}",
                    evidence=f"{header_name}: {headers[header_name]}",
                    remediation=f"Remove or obfuscate the {header_name} header to reduce information leakage.",
                ))

        # Check for insecure cookie flags
        set_cookies = resp.headers.get("Set-Cookie", "")
        if set_cookies:
            if "httponly" not in set_cookies.lower():
                vulnerabilities.append(Vulnerability(
                    url=target,
                    module="Security Headers",
                    severity="MEDIUM",
                    title="Cookie missing HttpOnly flag",
                    description="Cookies without HttpOnly can be accessed via JavaScript, enabling XSS-based cookie theft.",
                    evidence=f"Set-Cookie: {set_cookies[:100]}",
                    remediation="Add the HttpOnly flag to all session cookies.",
                ))
            if "secure" not in set_cookies.lower():
                vulnerabilities.append(Vulnerability(
                    url=target,
                    module="Security Headers",
                    severity="MEDIUM",
                    title="Cookie missing Secure flag",
                    description="Cookies without Secure flag can be sent over unencrypted HTTP connections.",
                    evidence=f"Set-Cookie: {set_cookies[:100]}",
                    remediation="Add the Secure flag to all cookies.",
                ))

        return vulnerabilities
