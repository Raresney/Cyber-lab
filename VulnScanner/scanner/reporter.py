"""
Report Generator
Creates professional HTML and JSON vulnerability reports.
"""

import json
import os
import time
from datetime import datetime


class ReportGenerator:
    def __init__(self, output_dir: str, config: dict = None):
        self.output_dir = output_dir
        self.config = config or {}
        os.makedirs(output_dir, exist_ok=True)

    def generate(self, scan_result) -> str:
        fmt = self.config.get("format", "html")
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        if fmt == "json":
            return self._generate_json(scan_result, timestamp)
        else:
            return self._generate_html(scan_result, timestamp)

    def _generate_json(self, result, timestamp: str) -> str:
        path = os.path.join(self.output_dir, f"vulnscan_{timestamp}.json")
        data = {
            "target": result.target,
            "scan_date": datetime.now().isoformat(),
            "duration_seconds": round(result.duration, 2),
            "pages_crawled": result.pages_crawled,
            "urls_discovered": result.urls_discovered,
            "forms_discovered": len(result.forms_discovered),
            "summary": result.severity_counts,
            "vulnerabilities": [
                {
                    "url": v.url,
                    "module": v.module,
                    "severity": v.severity,
                    "title": v.title,
                    "description": v.description,
                    "evidence": v.evidence,
                    "payload": v.payload,
                    "parameter": v.parameter,
                    "remediation": v.remediation,
                }
                for v in result.vulnerabilities
            ],
        }
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        return path

    def _generate_html(self, result, timestamp: str) -> str:
        path = os.path.join(self.output_dir, f"vulnscan_{timestamp}.html")
        counts = result.severity_counts
        total_vulns = len(result.vulnerabilities)

        # Risk score
        risk_score = (
            counts["CRITICAL"] * 40
            + counts["HIGH"] * 25
            + counts["MEDIUM"] * 10
            + counts["LOW"] * 3
            + counts["INFO"] * 1
        )
        if risk_score == 0:
            risk_label, risk_color = "SECURE", "#27ae60"
        elif risk_score < 30:
            risk_label, risk_color = "LOW RISK", "#2ecc71"
        elif risk_score < 80:
            risk_label, risk_color = "MEDIUM RISK", "#f39c12"
        elif risk_score < 150:
            risk_label, risk_color = "HIGH RISK", "#e74c3c"
        else:
            risk_label, risk_color = "CRITICAL RISK", "#c0392b"

        # Group vulnerabilities by module
        by_module = {}
        for v in result.vulnerabilities:
            by_module.setdefault(v.module, []).append(v)

        # Build vulnerability rows
        vuln_html = ""
        for module_name, vulns in by_module.items():
            vuln_html += f'<h3 class="module-title">{_esc(module_name)} ({len(vulns)} findings)</h3>\n'
            for v in vulns:
                sev_class = v.severity.lower()
                vuln_html += f"""
                <div class="vuln-card {sev_class}">
                    <div class="vuln-header">
                        <span class="severity-badge {sev_class}">{_esc(v.severity)}</span>
                        <span class="vuln-title">{_esc(v.title)}</span>
                    </div>
                    <div class="vuln-body">
                        <p><strong>URL:</strong> <code>{_esc(v.url)}</code></p>
                        {f'<p><strong>Parameter:</strong> <code>{_esc(v.parameter)}</code></p>' if v.parameter else ''}
                        <p><strong>Description:</strong> {_esc(v.description)}</p>
                        {f'<p><strong>Payload:</strong> <code>{_esc(v.payload)}</code></p>' if v.payload else ''}
                        {f'<div class="evidence"><strong>Evidence:</strong><pre>{_esc(v.evidence)}</pre></div>' if v.evidence else ''}
                        <p class="remediation"><strong>Remediation:</strong> {_esc(v.remediation)}</p>
                    </div>
                </div>
"""

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>VulnScanner Report - {_esc(result.target)}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: #0a0a1a;
            color: #e0e0e0;
            line-height: 1.6;
        }}
        .container {{ max-width: 1100px; margin: 0 auto; padding: 20px; }}

        /* Header */
        .header {{
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
            border: 1px solid #0f3460;
            border-radius: 12px;
            padding: 30px;
            margin-bottom: 24px;
            text-align: center;
        }}
        .header h1 {{
            font-size: 28px;
            color: #00d2ff;
            margin-bottom: 8px;
        }}
        .header .subtitle {{ color: #888; font-size: 14px; }}
        .header .target {{
            font-size: 18px;
            color: #fff;
            background: rgba(0,210,255,0.1);
            padding: 8px 16px;
            border-radius: 6px;
            margin-top: 12px;
            display: inline-block;
            font-family: monospace;
        }}

        /* Risk Score */
        .risk-score {{
            text-align: center;
            padding: 20px;
            margin-bottom: 24px;
        }}
        .risk-circle {{
            width: 120px;
            height: 120px;
            border-radius: 50%;
            border: 4px solid {risk_color};
            display: inline-flex;
            align-items: center;
            justify-content: center;
            flex-direction: column;
            margin-bottom: 10px;
        }}
        .risk-circle .score {{ font-size: 32px; font-weight: bold; color: {risk_color}; }}
        .risk-circle .label {{ font-size: 10px; color: #888; }}
        .risk-label {{ font-size: 20px; font-weight: bold; color: {risk_color}; }}

        /* Stats Grid */
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 16px;
            margin-bottom: 24px;
        }}
        .stat-card {{
            background: #1a1a2e;
            border: 1px solid #2a2a4a;
            border-radius: 8px;
            padding: 20px;
            text-align: center;
        }}
        .stat-card .value {{ font-size: 28px; font-weight: bold; }}
        .stat-card .label {{ font-size: 12px; color: #888; margin-top: 4px; }}

        /* Severity colors */
        .critical {{ --accent: #ff2d55; }}
        .high {{ --accent: #ff6b35; }}
        .medium {{ --accent: #ffc107; }}
        .low {{ --accent: #17a2b8; }}
        .info {{ --accent: #6c757d; }}

        .severity-badge {{
            display: inline-block;
            padding: 3px 10px;
            border-radius: 4px;
            font-size: 11px;
            font-weight: bold;
            text-transform: uppercase;
        }}
        .severity-badge.critical {{ background: rgba(255,45,85,0.2); color: #ff2d55; border: 1px solid #ff2d55; }}
        .severity-badge.high {{ background: rgba(255,107,53,0.2); color: #ff6b35; border: 1px solid #ff6b35; }}
        .severity-badge.medium {{ background: rgba(255,193,7,0.2); color: #ffc107; border: 1px solid #ffc107; }}
        .severity-badge.low {{ background: rgba(23,162,184,0.2); color: #17a2b8; border: 1px solid #17a2b8; }}
        .severity-badge.info {{ background: rgba(108,117,125,0.2); color: #6c757d; border: 1px solid #6c757d; }}

        /* Severity summary bar */
        .severity-bar {{
            display: flex;
            gap: 16px;
            justify-content: center;
            margin-bottom: 24px;
            flex-wrap: wrap;
        }}
        .severity-item {{
            display: flex;
            align-items: center;
            gap: 6px;
        }}
        .severity-dot {{
            width: 12px;
            height: 12px;
            border-radius: 50%;
        }}

        /* Vulnerability Cards */
        .module-title {{
            color: #00d2ff;
            font-size: 18px;
            margin: 24px 0 12px;
            padding-bottom: 8px;
            border-bottom: 1px solid #2a2a4a;
        }}
        .vuln-card {{
            background: #1a1a2e;
            border: 1px solid #2a2a4a;
            border-left: 4px solid var(--accent);
            border-radius: 8px;
            margin-bottom: 12px;
            overflow: hidden;
        }}
        .vuln-header {{
            padding: 12px 16px;
            display: flex;
            align-items: center;
            gap: 12px;
            background: rgba(255,255,255,0.02);
        }}
        .vuln-title {{ font-weight: 600; font-size: 14px; }}
        .vuln-body {{
            padding: 16px;
            font-size: 13px;
        }}
        .vuln-body p {{ margin-bottom: 8px; }}
        .vuln-body code {{
            background: rgba(0,210,255,0.1);
            padding: 2px 6px;
            border-radius: 3px;
            font-size: 12px;
            word-break: break-all;
        }}
        .evidence {{
            background: #0d0d1a;
            border: 1px solid #2a2a4a;
            border-radius: 6px;
            padding: 12px;
            margin: 8px 0;
        }}
        .evidence pre {{
            white-space: pre-wrap;
            word-break: break-all;
            font-size: 11px;
            color: #aaa;
            margin-top: 6px;
        }}
        .remediation {{
            background: rgba(39, 174, 96, 0.1);
            border: 1px solid rgba(39, 174, 96, 0.3);
            border-radius: 6px;
            padding: 10px;
            margin-top: 8px;
        }}

        /* Footer */
        .footer {{
            text-align: center;
            padding: 24px;
            color: #555;
            font-size: 12px;
            border-top: 1px solid #2a2a4a;
            margin-top: 40px;
        }}

        /* No vulns */
        .no-vulns {{
            text-align: center;
            padding: 60px;
            color: #27ae60;
            font-size: 18px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>VulnScanner Report</h1>
            <p class="subtitle">Automated Web Vulnerability Assessment</p>
            <div class="target">{_esc(result.target)}</div>
        </div>

        <div class="risk-score">
            <div class="risk-circle">
                <span class="score">{risk_score}</span>
                <span class="label">RISK SCORE</span>
            </div>
            <div class="risk-label">{risk_label}</div>
        </div>

        <div class="stats-grid">
            <div class="stat-card">
                <div class="value" style="color: #00d2ff;">{result.pages_crawled}</div>
                <div class="label">Pages Crawled</div>
            </div>
            <div class="stat-card">
                <div class="value" style="color: #00d2ff;">{len(result.forms_discovered)}</div>
                <div class="label">Forms Found</div>
            </div>
            <div class="stat-card">
                <div class="value" style="color: {risk_color};">{total_vulns}</div>
                <div class="label">Vulnerabilities</div>
            </div>
            <div class="stat-card">
                <div class="value" style="color: #888;">{result.duration:.1f}s</div>
                <div class="label">Scan Duration</div>
            </div>
        </div>

        <div class="severity-bar">
            <div class="severity-item">
                <div class="severity-dot" style="background: #ff2d55;"></div>
                <span>Critical: {counts['CRITICAL']}</span>
            </div>
            <div class="severity-item">
                <div class="severity-dot" style="background: #ff6b35;"></div>
                <span>High: {counts['HIGH']}</span>
            </div>
            <div class="severity-item">
                <div class="severity-dot" style="background: #ffc107;"></div>
                <span>Medium: {counts['MEDIUM']}</span>
            </div>
            <div class="severity-item">
                <div class="severity-dot" style="background: #17a2b8;"></div>
                <span>Low: {counts['LOW']}</span>
            </div>
            <div class="severity-item">
                <div class="severity-dot" style="background: #6c757d;"></div>
                <span>Info: {counts['INFO']}</span>
            </div>
        </div>

        <h2 style="color: #fff; margin-bottom: 16px;">Findings</h2>
        {vuln_html if vuln_html else '<div class="no-vulns">No vulnerabilities detected.</div>'}

        <div class="footer">
            Generated by VulnScanner v1.0.0 | {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} | For authorized testing only
        </div>
    </div>
</body>
</html>"""

        with open(path, "w", encoding="utf-8") as f:
            f.write(html)
        return path


def _esc(text: str) -> str:
    if not text:
        return ""
    return (
        str(text)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&#x27;")
    )
