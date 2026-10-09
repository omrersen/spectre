"""Report generation for Spectre scan results."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def generate_report(data: dict[str, Any], fmt: str = "json") -> str:
    """Generate a report from scan result data."""
    if fmt == "json":
        return json.dumps(data, indent=2, default=str)
    if fmt == "markdown":
        return _generate_markdown(data)
    if fmt == "html":
        return _generate_html(data)
    if fmt == "sarif":
        return _generate_sarif(data)
    raise ValueError(f"Unsupported format: {fmt}")


def _generate_markdown(data: dict[str, Any]) -> str:
    findings = data.get("findings", [])
    summary = _count_by_severity(findings)
    lines = [
        "# 🔮 Spectre Scan Report",
        "",
        f"**Target:** {data.get('target', 'N/A')}",
        f"**Generated:** {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
        f"**Duration:** {data.get('duration', 0):.1f}s",
        f"**Scanners:** {', '.join(data.get('scanners_used', []))}",
        "",
        "## Summary",
        "",
        "| Severity | Count |",
        "|----------|-------|",
    ]
    for sev in ["critical", "high", "medium", "low", "info"]:
        lines.append(f"| {sev.upper()} | {summary.get(sev, 0)} |")

    if findings:
        lines += ["", "## Findings", ""]
        for f in findings:
            sev = f.get("severity", "info")
            icon = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵", "info": "ℹ️"}.get(sev, "•")
            lines.append(f"### {icon} {f.get('title', 'Untitled')}")
            lines.append(f"- **Severity:** {sev.upper()}")
            lines.append(f"- **Target:** {f.get('target', 'N/A')}")
            if f.get("evidence"):
                lines.append(f"- **Evidence:** `{f['evidence'][:300]}`")
            if f.get("remediation"):
                lines.append(f"- **Remediation:** {f['remediation']}")
            lines.append("")

    return "\n".join(lines)


def _generate_html(data: dict[str, Any]) -> str:
    findings = data.get("findings", [])
    summary = _count_by_severity(findings)

    rows = ""
    for f in findings:
        sev = f.get("severity", "info")
        color = {
            "critical": "#dc2626", "high": "#ea580c",
            "medium": "#ca8a04", "low": "#2563eb", "info": "#0891b2",
        }.get(sev, "#6b7280")
        evidence = f.get("evidence", "")[:200]
        rows += f"""
        <tr>
          <td><span class="badge" style="background:{color}">{sev.upper()}</span></td>
          <td>{_esc(f.get('title', ''))}</td>
          <td>{_esc(f.get('target', ''))}</td>
          <td><code>{_esc(evidence)}</code></td>
        </tr>"""

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Spectre Scan Report</title>
<style>
  :root {{ --bg:#0f172a; --card:#1e293b; --text:#e2e8f0; --muted:#94a3b8; }}
  * {{ box-sizing:border-box; margin:0; padding:0; }}
  body {{ font-family:'Segoe UI',system-ui,sans-serif; background:var(--bg); color:var(--text); padding:2rem; }}
  h1 {{ font-size:2rem; margin-bottom:.5rem; }}
  .meta {{ color:var(--muted); margin-bottom:2rem; }}
  .summary {{ display:flex; gap:1rem; flex-wrap:wrap; margin-bottom:2rem; }}
  .card {{ background:var(--card); border-radius:12px; padding:1.25rem; min-width:140px; flex:1; }}
  .card .count {{ font-size:2rem; font-weight:700; }}
  .card .label {{ color:var(--muted); font-size:.875rem; }}
  table {{ width:100%; border-collapse:collapse; background:var(--card); border-radius:12px; overflow:hidden; }}
  th,td {{ padding:.75rem 1rem; text-align:left; border-bottom:1px solid #334155; }}
  th {{ background:#334155; font-size:.8rem; text-transform:uppercase; letter-spacing:.05em; }}
  .badge {{ padding:.2rem .6rem; border-radius:6px; color:#fff; font-size:.75rem; font-weight:700; }}
  code {{ color:#a5b4fc; font-size:.8rem; }}
</style>
</head>
<body>
<h1>🔮 Spectre Scan Report</h1>
<p class="meta">
  Target: <strong>{_esc(data.get('target', 'N/A'))}</strong> &middot;
  Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')} &middot;
  Duration: {data.get('duration', 0):.1f}s
</p>
<div class="summary">
  <div class="card"><div class="count" style="color:#dc2626">{summary.get('critical', 0)}</div><div class="label">Critical</div></div>
  <div class="card"><div class="count" style="color:#ea580c">{summary.get('high', 0)}</div><div class="label">High</div></div>
  <div class="card"><div class="count" style="color:#ca8a04">{summary.get('medium', 0)}</div><div class="label">Medium</div></div>
  <div class="card"><div class="count" style="color:#2563eb">{summary.get('low', 0)}</div><div class="label">Low</div></div>
  <div class="card"><div class="count" style="color:#0891b2">{summary.get('info', 0)}</div><div class="label">Info</div></div>
</div>
<table>
<thead><tr><th>Severity</th><th>Title</th><th>Target</th><th>Evidence</th></tr></thead>
<tbody>{rows or '<tr><td colspan="4">No findings</td></tr>'}</tbody>
</table>
</body>
</html>"""


def _esc(text: str) -> str:
    return str(text).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")


def _count_by_severity(findings: list[dict]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for f in findings:
        sev = f.get("severity", "info")
        counts[sev] = counts.get(sev, 0) + 1
    return counts


_SARIF_LEVEL = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
}

_SARIF_RULES = [
    {"id": "spectre-sql-injection", "name": "SQL Injection", "shortDescription": {"text": "SQL Injection vulnerability"}},
    {"id": "spectre-xss", "name": "Cross-Site Scripting", "shortDescription": {"text": "Cross-Site Scripting (XSS)"}},
    {"id": "spectre-ssrf", "name": "SSRF", "shortDescription": {"text": "Server-Side Request Forgery"}},
    {"id": "spectre-lfi", "name": "LFI", "shortDescription": {"text": "Local File Inclusion"}},
    {"id": "spectre-rce", "name": "RCE", "shortDescription": {"text": "Remote Code Execution"}},
    {"id": "spectre-command-injection", "name": "Command Injection", "shortDescription": {"text": "OS Command Injection"}},
    {"id": "spectre-path-traversal", "name": "Path Traversal", "shortDescription": {"text": "Path Traversal"}},
    {"id": "spectre-open-redirect", "name": "Open Redirect", "shortDescription": {"text": "Open Redirect"}},
    {"id": "spectre-tls", "name": "TLS Weakness", "shortDescription": {"text": "Weak TLS configuration"}},
    {"id": "spectre-secret", "name": "Exposed Secret", "shortDescription": {"text": "Hardcoded secret or credential"}},
    {"id": "spectre-missing-header", "name": "Missing Security Header", "shortDescription": {"text": "Missing security header"}},
    {"id": "spectre-cve", "name": "Known CVE", "shortDescription": {"text": "Component with known CVE"}},
    {"id": "spectre-sensitive-file", "name": "Sensitive File Exposed", "shortDescription": {"text": "Sensitive file or directory exposed"}},
    {"id": "spectre-info-leak", "name": "Information Leak", "shortDescription": {"text": "Server information disclosure"}},
    {"id": "spectre-generic", "name": "Security Finding", "shortDescription": {"text": "Generic security finding"}},
]


def _classify_rule(title: str) -> str:
    t = title.lower()
    mapping = [
        ("sql", "spectre-sql-injection"),
        ("xss", "spectre-xss"),
        ("cross-site", "spectre-xss"),
        ("ssrf", "spectre-ssrf"),
        ("file inclusion", "spectre-lfi"),
        ("lfi", "spectre-lfi"),
        ("rce", "spectre-rce"),
        ("remote code", "spectre-rce"),
        ("command injection", "spectre-command-injection"),
        ("path traversal", "spectre-path-traversal"),
        ("redirect", "spectre-open-redirect"),
        ("tls", "spectre-tls"),
        ("ssl", "spectre-tls"),
        ("secret", "spectre-secret"),
        ("credential", "spectre-secret"),
        ("api key", "spectre-secret"),
        ("api_key", "spectre-secret"),
        ("password", "spectre-secret"),
        ("token", "spectre-secret"),
        ("aws key", "spectre-secret"),
        ("key", "spectre-secret"),
        ("header", "spectre-missing-header"),
        ("cve", "spectre-cve"),
        ("file", "spectre-sensitive-file"),
        ("directory", "spectre-sensitive-file"),
        ("leak", "spectre-info-leak"),
        ("disclosure", "spectre-info-leak"),
    ]
    for keyword, rule_id in mapping:
        if keyword in t:
            return rule_id
    return "spectre-generic"


def _generate_sarif(data: dict[str, Any]) -> str:
    """Generate a SARIF 2.1.0 report (GitHub code-scanning compatible)."""
    findings = data.get("findings", [])
    rules_by_id = {r["id"]: r for r in _SARIF_RULES}

    results = []
    for f in findings:
        rule_id = _classify_rule(f.get("title", ""))
        severity = f.get("severity", "info")
        level = _SARIF_LEVEL.get(severity, "note")

        message = f.get("title", "Finding")
        if f.get("evidence"):
            message += f" — Evidence: {f['evidence'][:200]}"

        results.append(
            {
                "ruleId": rule_id,
                "level": level,
                "message": {"text": message},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": f.get("target", data.get("target", ""))},
                        }
                    }
                ],
                "properties": {
                    "severity": severity,
                    "scanner": f.get("scanner", ""),
                    "remediation": f.get("remediation", ""),
                    "cvss": f.get("cvss"),
                    "cve": f.get("cve", []),
                },
            }
        )

    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Spectre",
                        "informationUri": "https://github.com/omrersen/spectre",
                        "version": "0.1.0",
                        "rules": list(rules_by_id.values()),
                    }
                },
                "results": results,
            }
        ],
    }
    return json.dumps(sarif, indent=2, default=str)
