# 📚 Spectre Documentation

## Contents

- [Getting Started](getting-started.md)
- [Configuration](configuration.md)
- [Plugin Development](plugins.md)
- [API Reference](api.md)
- [Contributing](../CONTRIBUTING.md)
- [Security Policy](../SECURITY.md)

## Overview

Spectre is an AI-powered security scanner platform with:

- **Core Engine** — Async scanning with concurrency control
- **Scanner Modules** — Web vulns, subdomains, secrets, ports, tech, SSL
- **AI Analysis** — LLM-powered vulnerability analysis and FP reduction
- **Plugin System** — Extend with custom scanners
- **Reporting** — JSON, Markdown, HTML reports
- **Integrations** — Slack, Discord, Webhooks, GitHub Actions

## Quick Links

```bash
# Install
pip install spectre-scanner

# Quick scan
spectre scan https://example.com

# Full scan with AI
spectre scan https://example.com --full --ai

# Generate report
spectre report results.json -o report.html
```
