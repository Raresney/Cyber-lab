"""
SQL Injection Scanner Module
Detects error-based, boolean-based, and time-based blind SQLi.
"""

import re
import time
import requests
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from ..models import Vulnerability


# Common SQL error patterns from various DBMS
SQL_ERRORS = [
    # MySQL
    r"you have an error in your sql syntax",
    r"warning.*mysql",
    r"unclosed quotation mark",
    r"mysql_fetch",
    r"mysql_num_rows",
    r"MySqlException",
    # PostgreSQL
    r"pg_query\(\)",
    r"pg_exec\(\)",
    r"PostgreSQL.*ERROR",
    r"unterminated quoted string",
    # MS SQL
    r"microsoft ole db provider for sql server",
    r"\bOLE DB\b.*\berror\b",
    r"mssql_query\(\)",
    r"Unclosed quotation mark after the character string",
    r"Microsoft SQL Native Client error",
    # SQLite
    r"SQLite/JDBCDriver",
    r"SQLite\.Exception",
    r"SQLITE_ERROR",
    r"sqlite3\.OperationalError",
    r"near \".*?\": syntax error",
    # Oracle
    r"ORA-\d{5}",
    r"oracle.*error",
    r"quoted string not properly terminated",
    # Generic
    r"SQL syntax.*?error",
    r"syntax error.*?SQL",
    r"unexpected end of SQL command",
    r"SQL command not properly ended",
    r"invalid query",
    r"SQL.*?error",
]


class SQLiScanner:
    def __init__(self, payloads: list, timeout: int = 10, rate_limit: float = 0.1,
                 config: dict = None, verbose: int = 1):
        self.payloads = payloads
        self.timeout = timeout
        self.rate_limit = rate_limit
        self.config = config or {}
        self.verbose = verbose
        self.session = requests.Session()
        self.session.verify = False

        self.techniques = self.config.get("techniques", ["error_based", "boolean_based", "time_based"])
        self.time_delay = self.config.get("time_delay", 5)

    def scan(self, urls: list, forms: list) -> list:
        vulnerabilities = []

        # Test URL parameters
        for url in urls:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            if not params:
                continue

            for param_name in params:
                vulns = self._test_parameter(url, param_name, method="GET")
                vulnerabilities.extend(vulns)

        # Test form inputs
        for form in forms:
            for inp in form.inputs:
                if inp["type"] in ("submit", "hidden", "button"):
                    continue
                vulns = self._test_form(form, inp["name"])
                vulnerabilities.extend(vulns)

        return vulnerabilities

    def _test_parameter(self, url: str, param: str, method: str = "GET") -> list:
        vulns = []

        # Get baseline response
        try:
            baseline = self.session.get(url, timeout=self.timeout)
            baseline_text = baseline.text
            baseline_length = len(baseline_text)
        except requests.RequestException:
            return vulns

        for payload in self.payloads:
            time.sleep(self.rate_limit)
            parsed = urlparse(url)
            params = parse_qs(parsed.query, keep_blank_values=True)
            original_value = params.get(param, [""])[0]
            params[param] = [original_value + payload]

            new_query = urlencode(params, doseq=True)
            test_url = urlunparse(parsed._replace(query=new_query))

            try:
                start_time = time.time()
                resp = self.session.get(test_url, timeout=self.timeout + self.time_delay + 2)
                elapsed = time.time() - start_time
            except requests.RequestException:
                continue

            # Error-based detection
            if "error_based" in self.techniques:
                for pattern in SQL_ERRORS:
                    if re.search(pattern, resp.text, re.IGNORECASE):
                        vulns.append(Vulnerability(
                            url=url,
                            module="SQL Injection",
                            severity="HIGH",
                            title=f"SQL Injection (Error-Based) in '{param}'",
                            description=f"SQL error detected in parameter '{param}' with payload injection. "
                                        f"The server returned a database error message.",
                            evidence=self._extract_error(resp.text, pattern),
                            payload=payload,
                            parameter=param,
                            remediation="Use parameterized queries / prepared statements. "
                                        "Never concatenate user input into SQL queries.",
                        ))
                        return vulns  # One finding per param is enough

            # Time-based blind detection
            if "time_based" in self.techniques and "SLEEP" in payload.upper():
                if elapsed >= self.time_delay - 1:
                    # Verify with a second request
                    time.sleep(self.rate_limit)
                    start2 = time.time()
                    try:
                        self.session.get(test_url, timeout=self.timeout + self.time_delay + 2)
                        elapsed2 = time.time() - start2
                    except requests.RequestException:
                        continue

                    if elapsed2 >= self.time_delay - 1:
                        vulns.append(Vulnerability(
                            url=url,
                            module="SQL Injection",
                            severity="HIGH",
                            title=f"SQL Injection (Time-Based Blind) in '{param}'",
                            description=f"Time-based blind SQL injection detected in parameter '{param}'. "
                                        f"Server response was delayed by ~{elapsed:.1f}s (confirmed: ~{elapsed2:.1f}s).",
                            evidence=f"Response delayed {elapsed:.1f}s / {elapsed2:.1f}s (threshold: {self.time_delay}s)",
                            payload=payload,
                            parameter=param,
                            remediation="Use parameterized queries / prepared statements.",
                        ))
                        return vulns

            # Boolean-based detection
            if "boolean_based" in self.techniques:
                if "AND 1=1" in payload or "AND 'a'='a" in payload:
                    resp_len = len(resp.text)
                    # Now test the false condition
                    false_payload = payload.replace("1=1", "1=2").replace("'a'='a", "'a'='b")
                    params[param] = [original_value + false_payload]
                    false_query = urlencode(params, doseq=True)
                    false_url = urlunparse(parsed._replace(query=false_query))

                    try:
                        time.sleep(self.rate_limit)
                        false_resp = self.session.get(false_url, timeout=self.timeout)
                    except requests.RequestException:
                        continue

                    true_diff = abs(resp_len - baseline_length)
                    false_diff = abs(len(false_resp.text) - baseline_length)

                    # If true condition returns similar to baseline but false doesn't
                    if true_diff < 50 and false_diff > 200:
                        vulns.append(Vulnerability(
                            url=url,
                            module="SQL Injection",
                            severity="HIGH",
                            title=f"SQL Injection (Boolean-Based) in '{param}'",
                            description=f"Boolean-based SQL injection detected in parameter '{param}'. "
                                        f"True/false conditions produce different responses.",
                            evidence=f"True response: {resp_len} bytes, False response: {len(false_resp.text)} bytes, "
                                     f"Baseline: {baseline_length} bytes",
                            payload=payload,
                            parameter=param,
                            remediation="Use parameterized queries / prepared statements.",
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
                start_time = time.time()
                if form.method == "POST":
                    resp = self.session.post(form.action, data=data, timeout=self.timeout + self.time_delay + 2)
                else:
                    resp = self.session.get(form.action, params=data, timeout=self.timeout + self.time_delay + 2)
                elapsed = time.time() - start_time
            except requests.RequestException:
                continue

            # Error-based
            for pattern in SQL_ERRORS:
                if re.search(pattern, resp.text, re.IGNORECASE):
                    vulns.append(Vulnerability(
                        url=form.url,
                        module="SQL Injection",
                        severity="HIGH",
                        title=f"SQL Injection (Error-Based) in form field '{input_name}'",
                        description=f"SQL error detected in form field '{input_name}' at {form.action}.",
                        evidence=self._extract_error(resp.text, pattern),
                        payload=payload,
                        parameter=input_name,
                        remediation="Use parameterized queries / prepared statements.",
                    ))
                    return vulns

            # Time-based
            if "SLEEP" in payload.upper() and elapsed >= self.time_delay - 1:
                vulns.append(Vulnerability(
                    url=form.url,
                    module="SQL Injection",
                    severity="HIGH",
                    title=f"SQL Injection (Time-Based Blind) in form field '{input_name}'",
                    description=f"Time-based blind SQLi in form field '{input_name}' at {form.action}. "
                                f"Response delayed ~{elapsed:.1f}s.",
                    evidence=f"Response delayed {elapsed:.1f}s",
                    payload=payload,
                    parameter=input_name,
                    remediation="Use parameterized queries / prepared statements.",
                ))
                return vulns

        return vulns

    def _extract_error(self, html: str, pattern: str) -> str:
        match = re.search(pattern, html, re.IGNORECASE)
        if match:
            start = max(0, match.start() - 50)
            end = min(len(html), match.end() + 50)
            return html[start:end].strip()
        return ""
