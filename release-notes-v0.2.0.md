## 🔮 Spectre v0.2.0

### New Scanners
- **Directory Discovery** (`dirscan`) — 155-path wordlist, soft-404 detection, sensitive-path severity mapping
- **CVE Correlation** (`cve`) — NVD API 2.0 + GitHub Advisories, CPE mapping, CVSS severity

### New Features
- **SARIF export** — GitHub code-scanning compatible
- **GitHub Action** — Drop-in scan for any workflow
- **Multi-target scanning** — `spectre scan -F targets.txt --parallel`
- **Plugin management** — `spectre plugins list` / `install`
- **Proxy + rate limiting** — Engine and config support

### Infrastructure
- PyPI publish workflow, issue templates, pre-commit, Makefile
- 68 passing tests
- Pydantic v2 migration

### Install
```bash
pip install spectre-scanner
spectre scan https://example.com --full
```
