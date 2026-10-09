# Architecture

## Overview

Spectre follows a modular, async-first architecture:

```
┌─────────────────────────────────────────────────┐
│                     CLI                          │
│  spectre scan / subdomains / secrets / report    │
└──────────────────┬──────────────────────────────┘
                   │
┌──────────────────▼──────────────────────────────┐
│               ScanEngine                         │
│  • Semaphore (max_concurrent)                    │
│  • Timeout per scanner                           │
│  • Proxy + rate limiter pass-through             │
│  • Parallel multi-target support                 │
└──────────────────┬──────────────────────────────┘
                   │
    ┌──────────────┼──────────────────┐
    ▼              ▼                  ▼
┌────────┐  ┌──────────┐  ┌──────────────────┐
│Scanner │  │Scanner   │  │Scanner           │
│Web     │  │Subdomain │  │... (8 total)     │
└────┬───┘  └────┬─────┘  └────┬─────────────┘
     │           │             │
     └───────────┼─────────────┘
                 ▼
         ┌──────────────┐
         │Finding/Result│
         └──────┬───────┘
                │
    ┌───────────┼───────────────┐
    ▼           ▼               ▼
┌───────┐  ┌─────────┐  ┌──────────────┐
│Report │  │AI       │  │Integrations  │
│JSON   │  │Analyzer │  │Slack/Discord │
│HTML   │  │OpenAI   │  │Webhooks      │
│SARIF  │  │Anthropic│  │GitHub Action │
│MD     │  └─────────┘  └──────────────┘
└───────┘
```

## Core Components

### ScanEngine (`spectre/core/engine.py`)
- Manages scanner registration and execution
- Controls concurrency via `asyncio.Semaphore`
- Applies per-scanner timeout
- Supports proxy and rate limiting
- Can scan single or multiple targets

### BaseScanner (`spectre/scanners/base.py`)
- Abstract base class for all scanners
- Required: `name`, `description`, `version`, `scan(target) -> list[Finding]`
- Each scanner is self-contained
- Built-in scanners: `web`, `subdomain`, `port`, `secrets`, `tech`, `ssl`, `dirscan`, `cve`, `waf`, `archive`, `robots`

### Finding (`spectre/models/finding.py`)
- Pydantic model with severity, evidence, remediation
- CVSS and CVE fields for vulnerability correlation
- Timestamped and scanner-tagged

### Plugin System (`spectre/plugins/base.py`)
- Decorator-based registration: `@register`
- Entry-point discovery for pip packages
- Directory loading for local plugins

### AI Analyzer (`spectre/ai/analyzer.py`)
- OpenAI and Anthropic providers
- Executive summary generation
- False positive reduction
- PoC suggestion (safe, non-weaponized)

## Design Principles

1. **Async-first** — All network I/O is async for maximum throughput
2. **Fail-soft** — Scanner errors never crash the engine; findings are still collected
3. **Evidence-based** — Every finding includes concrete evidence
4. **Extensible** — New scanners are one file + one registration
5. **Composable** — Scanners can be combined or run individually
