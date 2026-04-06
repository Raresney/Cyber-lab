"""
Data models for VulnScanner
"""

from dataclasses import dataclass, field


@dataclass
class Vulnerability:
    url: str
    module: str
    severity: str
    title: str
    description: str
    evidence: str = ""
    payload: str = ""
    parameter: str = ""
    remediation: str = ""


@dataclass
class ScanResult:
    target: str
    start_time: float = 0.0
    end_time: float = 0.0
    pages_crawled: int = 0
    urls_discovered: list = field(default_factory=list)
    forms_discovered: list = field(default_factory=list)
    vulnerabilities: list = field(default_factory=list)

    @property
    def duration(self) -> float:
        return self.end_time - self.start_time

    @property
    def severity_counts(self) -> dict:
        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for vuln in self.vulnerabilities:
            counts[vuln.severity] = counts.get(vuln.severity, 0) + 1
        return counts
