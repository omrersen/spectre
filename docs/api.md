# API Reference

## Core Classes

### ScanEngine

```python
from spectre.core import ScanEngine

engine = ScanEngine(
    max_concurrent=50,
    timeout=30,
    proxy="http://127.0.0.1:8080",  # optional HTTP proxy
    rate_limit=10,                   # requests per second, 0 = unlimited
)

# Register scanners
from spectre.scanners.web import WebScanner
engine.register_scanner(WebScanner())

# Scan a target
result = await engine.scan("https://example.com", scanners=["web", "tech"])

# Scan multiple targets
results = await engine.scan_multiple(["https://a.com", "https://b.com"])
```

### Finding

```python
from spectre.models import Finding, Severity

finding = Finding(
    title="SQL Injection",
    severity=Severity.CRITICAL,
    target="https://example.com/api?id=1",
    evidence="' OR 1=1--",
    remediation="Use parameterized queries",
    scanner="web",
    cvss=9.8,
    cve=["CVE-2023-1234"],
)
```

### ScanResult

```python
from spectre.models import ScanResult

result = ScanResult(target="example.com")
result.findings
result.summary  # {"critical": 1, "high": 0, ...}
result.critical_count
result.high_count
result.duration
```

## AI Analyzer

```python
from spectre.ai import AIAnalyzer

analyzer = AIAnalyzer(provider="openai", model="gpt-4")

# Executive summary
summary = await analyzer.analyze(result)

# False positive reduction
findings = await analyzer.reduce_false_positives(result.findings)

# PoC suggestion
poc = await analyzer.suggest_exploit(result.findings[0])
```

## Notifications

```python
from spectre.integrations import SlackNotifier, DiscordNotifier, WebhookNotifier

slack = SlackNotifier(webhook_url="https://hooks.slack.com/...")
await slack.notify(result)

discord = DiscordNotifier(webhook_url="https://discord.com/api/webhooks/...")
await discord.notify(result)

webhook = WebhookNotifier(url="https://example.com/hook")
await webhook.notify(result)
```

## Reporting

```python
from spectre.reporting import generate_report

json_str = generate_report(result.model_dump(mode="json"), "json")
html_str = generate_report(result.model_dump(mode="json"), "html")
md_str = generate_report(result.model_dump(mode="json"), "markdown")
sarif_str = generate_report(result.model_dump(mode="json"), "sarif")  # GitHub code-scanning compatible
```

### SARIF Format

The SARIF output is compatible with GitHub code scanning:

```bash
spectre report scan-results.json -o report.sarif --format sarif
```

Upload to GitHub code scanning in your workflow:

```yaml
- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: report.sarif
```
