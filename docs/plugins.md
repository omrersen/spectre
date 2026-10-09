# Plugin Development

## Overview

Spectre's plugin system lets you add custom scanners without modifying core code.

## Built-in Scanners

| Scanner | Name | Description |
|---------|------|-------------|
| 🔍 Web Scanner | `web` | SQLi, XSS, SSRF, LFI, RCE, command injection, path traversal, open redirect |
| 🌐 Subdomain Enum | `subdomain` | crt.sh, HackerTarget, VirusTotal, DNS brute-force |
| 🔌 Port Scanner | `port` | 1127 ports, banner grabbing, service fingerprinting |
| 📝 Secret Scanner | `secrets` | 27 regex patterns + Shannon entropy |
| 🏗️ Tech Detection | `tech` | 66 fingerprints (CMS, CDN, WAF, frameworks) |
| 📜 CVE Correlation | `cve` | NVD API 2.0 + GitHub Advisories, CPE mapping |
| 🔐 SSL/TLS | `ssl` | Protocol versions, certificates, weak ciphers, HSTS |
| 📁 Directory Discovery | `dirscan` | 155-path wordlist, soft-404 detection |
| 🛡️ WAF Detection | `waf` | 14 WAF signatures |
| 🕸️ Web Archive | `archive` | Wayback Machine + URLhaus |
| 🤖 Robots Analyzer | `robots` | robots.txt, sitemap.xml, security.txt |

## Creating a Plugin

### 1. Basic Plugin

```python
# my_plugin.py
from spectre.plugins import PluginBase, register
from spectre.models import Finding, Severity


@register
class MyScanner(PluginBase):
    name = "my-scanner"
    description = "Custom security check"
    version = "1.0.0"
    author = "your-name"

    async def scan(self, target: str) -> list[Finding]:
        findings = []

        # Your scanning logic here
        is_vulnerable = await self._check(target)

        if is_vulnerable:
            findings.append(Finding(
                title="Custom Vulnerability",
                severity=Severity.HIGH,
                target=target,
                evidence="Proof of vulnerability",
                remediation="Fix by doing X",
                scanner=self.name,
            ))

        return findings

    async def _check(self, target: str) -> bool:
        # Implementation
        return False
```

### 2. Install Your Plugin

```bash
# Copy to plugins directory
cp my_plugin.py ~/.spectre/plugins/

# Or install as package
pip install -e .
```

### 3. Register in pyproject.toml (for distribution)

```toml
[project.entry-points."spectre.plugins"]
my-scanner = "my_plugin:MyScanner"
```

## Using Plugins

```bash
# Plugins are auto-discovered
spectre scan https://example.com --scanner my-scanner
```

## Best Practices

- Handle network errors gracefully
- Use async HTTP (httpx.AsyncClient)
- Respect rate limits
- Provide clear evidence and remediation
- Test with unit tests
