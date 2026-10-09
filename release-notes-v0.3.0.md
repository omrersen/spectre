## 🔮 Spectre v0.3.0

### New Scanners
- **WAF Detection** (`waf`) — 14 WAF signatures: Cloudflare, AWS WAF, Akamai, Sucuri, Imperva/Incapsula, F5 BIG-IP, ModSecurity, Wordfence, FortiWeb, Barracuda, DenyAll, Reblaze, Fastly, Varnish. Passive + active probe detection.
- **Web Archive** (`archive`) — Wayback Machine CDX API historical exposure, URLhaus malicious URL check
- **Robots Analyzer** (`robots`) — robots.txt hidden paths, sitemap.xml, security.txt, humans.txt analysis

### Changes
- CLI auto-registration for optional scanners
- ruff lint fixes (65 auto-fixed)
- README/docs updated with 11-scanner table
- 80 passing tests

### Total: 11 Scanners
web, subdomain, secrets, port, tech, ssl, dirscan, cve, waf, archive, robots

### Install
```bash
pip install spectre-scanner
spectre scan https://example.com --full
```
