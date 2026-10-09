# Changelog

All notable changes to Spectre will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.3.0] - Unreleased

### Added
- **WAF Detection scanner** (`waf`) — 14 WAF signatures (Cloudflare, AWS WAF, Akamai, Sucuri, Imperva, F5 BIG-IP, ModSecurity, Wordfence, FortiWeb, Barracuda, DenyAll, Reblaze, Fastly, Varnish)
- **Web Archive scanner** (`archive`) — Wayback Machine CDX API, historical sensitive paths, URLhaus malicious URL check
- **Robots Analyzer** (`robots`) — robots.txt, sitemap.xml, security.txt, humans.txt analysis
- CLI auto-registration for optional scanners (try/except imports)
- ruff lint fixes across core/models/ai/plugins/reporting/integrations/utils/cli/config (65 auto-fixed)

### Changed
- ruff config moved to `[tool.ruff.lint]` section (deprecated top-level keys)
- README scanner table expanded to 11 scanners
- docs/getting-started.md updated with full scanner list

## [0.2.0] - 2026-10-09

### Added
- **Directory Discovery scanner** (`dirscan`) — Smart fuzzing with built-in 155-path wordlist, soft-404 detection, sensitive-path severity mapping
- **CVE Correlation scanner** (`cve`) — NVD API 2.0 integration, CPE mapping, CVSS-based severity
- **SARIF report format** — GitHub code-scanning compatible export with rule classification
- **GitHub Action** (`action.yml`) — Drop-in Spectre scan for any workflow with SARIF upload + fail-on-critical
- **PyPI publish workflow** — Trusted publishing on release
- **Plugin management CLI** — `spectre plugins list` and `spectre plugins install`
- **Multi-target scanning** — `spectre scan -F targets.txt --parallel`
- **Proxy support** — `scan_proxy` / engine `proxy=` parameter
- **Rate limiting** — `scan_rate_limit` / engine `rate_limit=` parameter
- **HTTP client factory** — `spectre.utils.http.create_client` with proxy/UA/timeout defaults
- **Issue templates** — Bug report and feature request
- **Pre-commit config** — ruff, black, basic hooks
- **Makefile** — Common dev commands
- **Architecture docs** — System design overview
- **API example** — `examples/basic_usage.py` programmatic usage
- **68 passing tests** — core, scanners, HTTP, SARIF

### Changed
- `spectre report` now supports `sarif` format
- Fixed `--format` parameter naming bug in report command
- Pydantic v2 `ConfigDict` migration (removed deprecated `class Config`)
- `datetime.utcnow()` replaced with timezone-aware `datetime.now(timezone.utc)`
- Expanded SARIF rule classification with secret/token/password/key keywords
- Engine passes proxy and rate limiter to registered scanners

## [0.1.0] - 2026-10-09

### Added
- **Async scanning engine** — Concurrent scanner execution with semaphore control
- **6 scanner modules:**
  - `web` — SQLi, XSS, SSRF, LFI, RCE, command injection, path traversal, open redirect with WAF bypass
  - `subdomain` — crt.sh, HackerTarget, VirusTotal, DNS brute-force with verification
  - `port` — 1127-port sweep, banner grabbing, service fingerprinting
  - `secrets` — 27 regex patterns + Shannon entropy detection
  - `tech` — 66 technology fingerprints (frameworks, CMS, CDN, WAF, analytics)
  - `ssl` — TLS protocol analysis, certificate checks, weak cipher detection
- **AI integration** — OpenAI/Anthropic: executive summaries, false positive reduction, PoC suggestions
- **Plugin system** — Registry, decorator-based registration, entry-point loading
- **Report formats** — JSON, Markdown, HTML
- **Integrations** — Slack, Discord, generic webhook notifications
- **Rich CLI** — Progress bars, severity tables, color-coded findings
- **Configuration** — YAML-based config with CLI management
- **CI/CD** — GitHub Actions (test matrix, lint, type-check, build)
- **Docker** — Dockerfile + docker-compose
- **Documentation** — Getting started, configuration, plugin development, API reference
- **Tests** — 15 passing tests (models, helpers, plugins, reporting)
