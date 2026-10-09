<div align="center">

# 🔮 Spectre

### AI-Powered Security Scanner Platform

[![Python](https://img.shields.io/badge/Python-3.11+-blue?style=flat-square&logo=python&logoColor=white)](https://www.python.org)
[![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)](LICENSE)
[![CI](https://img.shields.io/badge/CI-GitHub_Actions-orange?style=flat-square&logo=github)](https://github.com/actions)
[![Code Style](https://img.shields.io/badge/Code%20Style-Black-black?style=flat-square)](https://github.com/psf/black)
[![Security](https://img.shields.io/badge/Security-Research-red?style=flat-square)](SECURITY.md)

**Lightning-fast security scanning with AI-powered vulnerability analysis**

[Features](#-features) • [Installation](#-installation) • [Usage](#-usage) • [Architecture](#-architecture) • [Plugins](#-plugins) • [Contributing](#-contributing)

</div>

---

## 📋 Overview

Spectre is a next-generation security scanning platform that combines high-performance async scanning with AI-powered vulnerability analysis. Built for security researchers, penetration testers, and DevSecOps teams.

### Why Spectre?

- **🔥 Blazing Fast** — Async architecture scans 1000+ endpoints concurrently
- **🤖 AI-Powered** — LLM-assisted vulnerability detection and false positive reduction
- **🧩 Plugin System** — Extend with custom scanners in minutes
- **📊 Beautiful Output** — Rich terminal UI + multiple report formats
- **🔗 Integrations** — GitHub Actions, GitLab CI, Slack, Discord, Webhooks
- **🎯 Zero False Positives** — Smart verification engine eliminates noise

---

## ✨ Features

### Core Scanners

| Scanner | Description | Status |
|---------|-------------|--------|
| 🔍 Web Scanner | XSS, SQLi, SSRF, LFI, RCE detection with WAF bypass | ✅ |
| 🌐 Subdomain Enumeration | crt.sh, HackerTarget, VirusTotal, DNS brute-force | ✅ |
| 🔌 Port Scanner | 1127 ports, banner grabbing, service fingerprinting | ✅ |
| 📝 Secret Scanner | 27 patterns + Shannon entropy detection | ✅ |
| 🏗️ Tech Stack Detection | 66 technology fingerprints (CMS, CDN, WAF, frameworks) | ✅ |
| 📜 CVE Correlation | NVD API 2.0, CPE mapping, CVSS severity scoring | ✅ |
| 🔐 SSL/TLS Analyzer | Protocol versions, certificates, weak ciphers, HSTS | ✅ |
| 📁 Directory Discovery | Smart fuzzing, 155-path wordlist, soft-404 detection | ✅ |
| 🛡️ WAF Detection | 14 WAF signatures (Cloudflare, AWS, Akamai, Imperva...) | ✅ |
| 🕸️ Web Archive | Wayback Machine historical data + URLhaus | ✅ |
| 🤖 Robots Analyzer | robots.txt, sitemap.xml, security.txt analysis | ✅ |

### Report Formats

| Format | Description |
|--------|-------------|
| JSON | Machine-readable scan results |
| Markdown | Human-readable reports |
| HTML | Styled security reports with severity badges |
| SARIF | GitHub code-scanning compatible format |

### AI Features

- **Intelligent Analysis** — LLM analyzes scan results for complex vulnerability chains
- **False Positive Reduction** — AI verifies findings to eliminate noise
- **Exploit Suggestion** — Recommends proof-of-concept approaches
- **Risk Scoring** — Context-aware severity assessment
- **Natural Language Reports** — AI-generated executive summaries

### Plugin Architecture

```python
from spectre.plugins import ScannerPlugin, register

@register
class CustomScanner(ScannerPlugin):
    name = "custom-check"
    description = "My custom security check"
    
    async def scan(self, target: str) -> list[Finding]:
        # Your scanning logic here
        pass
```

---

## 🚀 Installation

### From PyPI (Recommended)

```bash
pip install spectre-scanner
```

### From Source

```bash
git clone https://github.com/omrersen/spectre.git
cd spectre
pip install -e ".[dev,ai]"
```

### Docker

```bash
docker pull ghcr.io/omrersen/spectre:latest
docker run -it ghcr.io/omrersen/spectre:latest scan https://example.com
```

### Quick Setup

```bash
# Install
pip install spectre-scanner

# Configure API keys (optional, for AI features)
spectre config set openai_api_key "sk-..."
spectre config set anthropic_api_key "sk-ant-..."

# Verify installation
spectre --version
```

---

## 💻 Usage

### Basic Scan

```bash
# Quick scan
spectre scan https://example.com

# Full scan with all modules
spectre scan https://example.com --full

# Specific scanner
spectre scan https://example.com --scanner web,xss,sqli
```

### Advanced Options

```bash
# Scan with AI analysis
spectre scan https://example.com --ai

# Custom threads and timeout
spectre scan https://example.com --threads 100 --timeout 30

# Export results
spectre scan https://example.com -o report.html --format html

# Scan from file (list of targets)
spectre scan -F targets.txt --parallel

# SARIF export (GitHub code-scanning compatible)
spectre report scan-results.json -o report.sarif --format sarif
```

### Multi-Target Scanning

```bash
# Create a targets file
cat > targets.txt << 'EOF'
https://example.com
https://app.example.com
https://api.example.com
EOF

# Scan all targets sequentially
spectre scan -F targets.txt

# Scan in parallel (faster)
spectre scan -F targets.txt --parallel --scanner web,tech,ssl
```

### GitHub Action

Add Spectre to any repository's CI:

```yaml
# .github/workflows/security.yml
name: Security Scan

on:
  push:
    branches: [main]
  schedule:
    - cron: '0 0 * * 1'  # Weekly scan

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: omrersen/spectre@v0.2.0
        with:
          target: ${{ github.repository_url }}
          scanners: web,tech,ssl,secrets
          ai: false
          output: spectre-report.sarif
          fail-on: critical
```

### Subdomain Enumeration

```bash
# Enumerate subdomains
spectre subdomains example.com

# With brute force
spectre subdomains example.com --brute --wordlist common.txt

# Passive only (no direct requests)
spectre subdomains example.com --passive
```

### Secret Scanning

```bash
# Scan current directory
spectre secrets .

# Scan with git history
spectre secrets . --git-history

# Scan specific patterns
spectre secrets . --pattern "api_key,token,secret"
```

### Report Generation

```bash
# Generate HTML report
spectre report scan-results.json -o report.html

# Generate PDF
spectre report scan-results.json -o report.pdf

# Generate Markdown
spectre report scan-results.json -o report.md
```

---

## 🏗️ Architecture

```
spectre/
├── spectre/
│   ├── __init__.py
│   ├── cli.py                 # Click-based CLI
│   ├── config.py              # Configuration management
│   ├── core/
│   │   ├── engine.py          # Async scanning engine
│   │   ├── scheduler.py       # Task scheduler
│   │   └── verifier.py        # Finding verification
│   ├── scanners/
│   │   ├── base.py            # Base scanner class
│   │   ├── web.py             # Web vulnerability scanner
│   │   ├── subdomain.py       # Subdomain enumeration
│   │   ├── port.py            # Port scanner
│   │   ├── secrets.py         # Secret detection
│   │   ├── tech.py            # Technology detection
│   │   └── ssl.py             # SSL/TLS analyzer
│   ├── ai/
│   │   ├── analyzer.py        # AI-powered analysis
│   │   ├── verifier.py        # FP reduction
│   │   └── providers/         # LLM providers
│   │       ├── openai.py
│   │       ├── anthropic.py
│   │       └── local.py
│   ├── plugins/
│   │   ├── base.py            # Plugin base class
│   │   ├── loader.py          # Plugin loader
│   │   └── registry.py        # Plugin registry
│   ├── reporting/
│   │   ├── json.py            # JSON exporter
│   │   ├── html.py            # HTML report
│   │   ├── markdown.py        # Markdown report
│   │   └── templates/         # Report templates
│   ├── integrations/
│   │   ├── github.py          # GitHub integration
│   │   ├── slack.py           # Slack notifications
│   │   ├── discord.py         # Discord webhooks
│   │   └── webhook.py         # Generic webhooks
│   └── utils/
│       ├── http.py            # HTTP utilities
│       ├── async_utils.py     # Async helpers
│       └── parsers.py         # Data parsers
├── tests/                     # Unit tests
├── docs/                      # Documentation
├── examples/                  # Example configs
├── pyproject.toml             # Project metadata
├── Dockerfile                 # Docker build
└── docker-compose.yml         # Docker compose
```

---

## 🧩 Plugins

### Writing a Plugin

```python
# my_scanner.py
from spectre.plugins import ScannerPlugin, register
from spectre.models import Finding, Severity

@register
class MyScanner(ScannerPlugin):
    name = "my-scanner"
    description = "Custom vulnerability scanner"
    version = "1.0.0"
    
    async def scan(self, target: str) -> list[Finding]:
        findings = []
        
        # Your scanning logic
        result = await self.check_vulnerability(target)
        
        if result.vulnerable:
            findings.append(Finding(
                title="Custom Vulnerability Found",
                severity=Severity.HIGH,
                target=target,
                evidence=result.evidence,
                remediation="Fix by doing X",
            ))
        
        return findings
    
    async def check_vulnerability(self, target: str):
        # Implementation
        pass
```

### Installing Plugins

```bash
# Install from PyPI
pip install spectre-plugin-myplugin

# Install from Git
spectre plugins install git+https://github.com/user/plugin.git

# Enable in config
spectre config set plugins.enabled '["my-scanner"]'
```

---

## ⚙️ Configuration

### Config File (`~/.spectre/config.yaml`)

```yaml
# Scan settings
scan:
  threads: 50
  timeout: 30
  retries: 3
  user_agent: "Spectre/1.0"

# AI settings
ai:
  enabled: true
  provider: "openai"  # or "anthropic", "local"
  model: "gpt-4"
  api_key: "${OPENAI_API_KEY}"
  max_tokens: 4096

# Scanner settings
scanners:
  web:
    enabled: true
    payloads: "default"  # or path to custom
    waf_bypass: true
  subdomain:
    enabled: true
    sources:
      - "crtsh"
      - "virustotal"
      - "securitytrails"
      - "hackertarget"
  secrets:
    enabled: true
    entropy_threshold: 4.5

# Reporting
reporting:
  formats: ["json", "html"]
  output_dir: "./reports"
  templates: "default"

# Integrations
integrations:
  slack:
    enabled: false
    webhook_url: "${SLACK_WEBHOOK}"
  discord:
    enabled: false
    webhook_url: "${DISCORD_WEBHOOK}"
```

---

## 🔌 Integrations

### GitHub Actions

```yaml
# .github/workflows/security.yml
name: Security Scan

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Run Spectre Scan
        uses: omrersen/spectre-action@v1
        with:
          target: ${{ github.repository_url }}
          scanners: web,secrets
          ai: true
          output: report.html
          
      - name: Upload Report
        uses: actions/upload-artifact@v4
        with:
          name: security-report
          path: report.html
```

### Slack Integration

```yaml
integrations:
  slack:
    enabled: true
    webhook_url: "https://hooks.slack.com/services/..."
    channel: "#security"
    notify_on: ["critical", "high"]
```

---

## 📊 Report Example

```
┌─────────────────────────────────────────────────────────────┐
│                    🔮 Spectre Scan Report                    │
├─────────────────────────────────────────────────────────────┤
│ Target: https://example.com                                  │
│ Scan Duration: 45.2 seconds                                  │
│ Scanners Used: web, subdomain, tech, ssl                     │
│ AI Analysis: Enabled (GPT-4)                                │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  📊 Summary                                                  │
│  ├── Critical: 1                                             │
│  ├── High: 3                                                 │
│  ├── Medium: 7                                               │
│  ├── Low: 12                                                 │
│  └── Info: 45                                                │
│                                                              │
│  🔴 CRITICAL: SQL Injection                                  │
│  ├── URL: /api/users?id=1                                    │
│  ├── Parameter: id                                           │
│  └── Evidence: ' OR 1=1--                                   │
│                                                              │
│  🟠 HIGH: Cross-Site Scripting (XSS)                        │
│  ├── URL: /search?q=<script>alert(1)</script>               │
│  └── Type: Reflected XSS                                    │
│                                                              │
│  🟡 MEDIUM: Missing Security Headers                        │
│  ├── X-Frame-Options: Missing                               │
│  └── Content-Security-Policy: Missing                       │
│                                                              │
│  🤖 AI Insights:                                             │
│  └── SQLi + XSS chain could lead to full database           │
│      compromise. Recommend immediate patching.               │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

---

## 🧪 Testing

```bash
# Run tests
pytest

# With coverage
pytest --cov=spectre --cov-report=html

# Run specific test
pytest tests/test_scanners/test_web.py -v
```

---

## 📚 Documentation

- [Getting Started](docs/getting-started.md)
- [Configuration Reference](docs/configuration.md)
- [Plugin Development](docs/plugins.md)
- [API Reference](docs/api.md)
- [Security Policy](SECURITY.md)
- [Contributing Guidelines](CONTRIBUTING.md)

---

## 🤝 Contributing

Contributions are welcome! Please read [CONTRIBUTING.md](CONTRIBUTING.md) first.

```bash
# Fork and clone
git clone https://github.com/yourusername/spectre.git
cd spectre

# Install dev dependencies
pip install -e ".[dev]"

# Run tests
pytest

# Submit PR
```

---

## 📄 License

MIT License - see [LICENSE](LICENSE) for details

---

## 🙏 Acknowledgments

- [Nuclei](https://github.com/projectdiscovery/nuclei) - Template inspiration
- [httpx](https://github.com/projectdiscovery/httpx) - HTTP library reference
- [Wappalyzer](https://github.com/AliasIO/wappalyzer) - Tech detection patterns

---

## 📈 Stats

![GitHub Stars](https://img.shields.io/github/stars/omrersen/spectre?style=social)
![GitHub Forks](https://img.shields.io/github/forks/omrersen/spectre?style=social)
![GitHub Issues](https://img.shields.io/github/issues/omrersen/spectre)

---

<div align="center">
Made with ❤️ for the security community
</div>
