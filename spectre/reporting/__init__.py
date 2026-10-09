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
