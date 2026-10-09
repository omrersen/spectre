"""Technology stack fingerprinting scanner: servers, CMS, frameworks, CDNs and WAFs."""

import re
from urllib.parse import urljoin, urlparse

import httpx

from .base import BaseScanner
from ..models import Finding, Severity

try:  # bs4 is a declared dependency; degrade to regex parsing if absent
    from bs4 import BeautifulSoup
except ImportError:  # pragma: no cover
    BeautifulSoup = None  # type: ignore[assignment]

USER_AGENT = ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
              "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
TIMEOUT = 10.0
MAX_BODY = 500_000          # Cap HTML we parse so huge pages stay cheap
VERSION_RE = re.compile(r"\d+(?:\.\d+)+")
TECH_REMEDIATION = ("Informational fingerprint. Use the detected product and version to "
                    "scope version-specific checks for known vulnerabilities.")


class TechScanner(BaseScanner):
    name = "tech"
    description = "Technology stack fingerprinting"
    version = "1.0.0"

    # technology -> (category, matchers). A technology is reported when ANY matcher hits.
    # Matcher keys: headers (name -> substring, "" = presence), cookies (name substrings),
    # generator (meta generator substring), scripts/links (URL substrings), html (substrings),
    # html_regex (regexes), robots (substrings of robots.txt).
    FINGERPRINTS: dict[str, tuple[str, dict]] = {
        # --- Web servers / caches (HTTP response headers) ---
        "nginx": ("web server", {"headers": {"server": "nginx"}}),
        "apache": ("web server", {"headers": {"server": "apache"}}),
        "microsoft iis": ("web server", {"headers": {"server": "microsoft-iis", "x-aspnet-version": ""}}),
        "litespeed": ("web server", {"headers": {"server": "litespeed"}}),
        "caddy": ("web server", {"headers": {"server": "caddy"}}),
        "openresty": ("web server", {"headers": {"server": "openresty"}}),
        "gunicorn": ("web server", {"headers": {"server": "gunicorn"}}),
        "uvicorn": ("web server", {"headers": {"server": "uvicorn"}}),
        "apache tomcat": ("web server", {"headers": {"server": "tomcat"}, "html": ["apache tomcat"]}),
        "lighttpd": ("web server", {"headers": {"server": "lighttpd"}}),
        "haproxy": ("web server", {"headers": {"server": "haproxy"}}),
        "varnish": ("cache", {"headers": {"x-varnish": ""}}),
        # --- Languages / server-side frameworks ---
        "php": ("language", {"headers": {"x-powered-by": "php"}, "cookies": ["phpsessid"]}),
        "java": ("language", {"cookies": ["jsessionid"], "headers": {"server": "jetty"}}),
        "django": ("framework", {"cookies": ["csrftoken"], "html": ["csrfmiddlewaretoken"]}),
        "flask": ("framework", {"headers": {"server": "werkzeug"}}),
        "laravel": ("framework", {"cookies": ["laravel_session", "xsrf-token"]}),
        "ruby on rails": ("framework", {"cookies": ["_rails_session"], "html": ["rails-ujs", "data-remote="]}),
        "express": ("framework", {"headers": {"x-powered-by": "express"}}),
        "asp.net": ("framework", {"headers": {"x-powered-by": "asp.net"}, "cookies": ["asp.net_sessionid"]}),
        "asp.net core": ("framework", {"headers": {"server": "kestrel"}, "cookies": [".aspnetcore"]}),
        "spring": ("framework", {"headers": {"x-application-context": ""}, "html": ["/actuator/"]}),
        "next.js": ("framework", {"html": ["__next_data__", "/_next/static/"]}),
        "nuxt": ("framework", {"html": ["__nuxt__", "/_nuxt/"]}),
        "swagger ui": ("framework", {"scripts": ["swagger-ui"], "html": ["swagger-ui"]}),
        # --- Content management systems ---
        "wordpress": ("cms", {"generator": "wordpress", "html": ["wp-content/", "wp-includes/"], "robots": ["wp-admin"]}),
        "joomla": ("cms", {"generator": "joomla", "html": ["/media/jui/", "/components/com_"]}),
        "drupal": ("cms", {"generator": "drupal", "html": ["drupal-settings-json", "/sites/default/files/"]}),
        "shopify": ("cms", {"generator": "shopify", "html": ["cdn.shopify.com", "shopify.theme"]}),
        "magento": ("cms", {"html_regex": [r"mage/cache|magento"]}),
        "wix": ("cms", {"html": ["wixstatic.com", "wix.com/site"]}),
        "squarespace": ("cms", {"html": ["static1.squarespace.com"]}),
        "ghost": ("cms", {"generator": "ghost", "html": ["ghost-sdk"]}),
        "typo3": ("cms", {"generator": "typo3", "html": ["/typo3conf/"]}),
        "prestashop": ("cms", {"html": ["/modules/prestashop", "prestashop"]}),
        "mediawiki": ("cms", {"html": ["mw-parser-output", "mediawiki"]}),
        "webflow": ("cms", {"html": ["webflow.js", "data-wf-page"]}),
        # --- Client-side libraries (script/link tags, HTML markers) ---
        "jquery": ("javascript", {"scripts": ["jquery"]}),
        "react": ("javascript", {"scripts": ["react.", "react-dom"], "html": ["data-reactroot"]}),
        "vue.js": ("javascript", {"scripts": ["vue."], "html": ["data-v-"]}),
        "angular": ("javascript", {"scripts": ["angular."], "html": ["ng-version="]}),
        "angularjs": ("javascript", {"scripts": ["angularjs", "angular.min.js"], "html": ["ng-app"]}),
        "bootstrap": ("javascript", {"scripts": ["bootstrap"], "links": ["bootstrap"]}),
        "lodash": ("javascript", {"scripts": ["lodash"]}),
        "axios": ("javascript", {"scripts": ["axios"]}),
        "moment": ("javascript", {"scripts": ["moment"]}),
        "font awesome": ("javascript", {"links": ["font-awesome", "fontawesome"]}),
        "socket.io": ("javascript", {"scripts": ["socket.io"]}),
        "tailwind css": ("javascript", {"links": ["tailwind"], "html": ["tailwindcss"]}),
        # --- CDN / edge (response headers) ---
        "cloudflare": ("cdn/waf", {"headers": {"cf-ray": "", "cf-cache-status": ""}}),
        "aws cloudfront": ("cdn", {"headers": {"x-amz-cf-id": ""}}),
        "fastly": ("cdn", {"headers": {"x-fastly-request-id": ""}}),
        "akamai": ("cdn", {"headers": {"x-akamai-transformed": "", "akamai-origin-hop": ""}}),
        "bunny cdn": ("cdn", {"headers": {"server": "bunnycdn"}}),
        # --- Security tooling (WAF headers) ---
        "sucuri": ("waf", {"headers": {"x-sucuri-id": "", "x-sucuri-cache": ""}}),
        "aws waf": ("waf", {"headers": {"x-aws-waf": ""}}),
        "imperva incapsula": ("waf", {"headers": {"x-cdn": "incapsula", "x-iinfo": ""}}),
        "modsecurity": ("waf", {"headers": {"server": "mod_security", "x-mod-security": ""}}),
        # --- Analytics / marketing ---
        "google analytics": ("analytics", {"scripts": ["google-analytics.com", "googletagmanager.com/gtag"]}),
        "google tag manager": ("analytics", {"scripts": ["googletagmanager.com/gtm.js"]}),
        "hotjar": ("analytics", {"scripts": ["static.hotjar.com"]}),
        "matomo": ("analytics", {"scripts": ["matomo.js", "piwik.js"]}),
        "mixpanel": ("analytics", {"scripts": ["mixpanel.com"]}),
        "segment": ("analytics", {"scripts": ["cdn.segment.com"]}),
        "facebook pixel": ("analytics", {"scripts": ["connect.facebook.net", "fbevents.js"]}),
        "hubspot": ("analytics", {"scripts": ["js.hs-scripts.com", "js.hs-analytics"]}),
    }

    # -------------------------------------------------------------- scanning
    async def scan(self, target: str) -> list[Finding]:
        """Fingerprint the site at ``target``; one INFO finding per technology found."""
        url = target if "://" in target else f"https://{target}"
        parsed = urlparse(url)
        if not parsed.hostname:
            return []
        base = f"{parsed.scheme}://{parsed.netloc}"

        async with httpx.AsyncClient(follow_redirects=True, timeout=TIMEOUT, verify=False,
                                     headers={"User-Agent": USER_AGENT}) as client:
            resp = await self._fetch(client, url)
            if resp is None and parsed.scheme == "https":
                resp = await self._fetch(client, base.replace("https://", "http://", 1))
            if resp is None:
                return []  # Connection failure: nothing to fingerprint

            body = resp.text[:MAX_BODY]
            generator, scripts, links, icon = self._parse_html(body)
            headers = {k.lower(): v for k, v in resp.headers.items()}
            cookies = [c.split("=", 1)[0].strip().lower()
                       for c in resp.headers.get_list("set-cookie")]
            robots = await self._fetch(client, f"{base}/robots.txt", require_ok=True)
            icon_url = urljoin(str(resp.url), icon) if icon else f"{base}/favicon.ico"
            favicon = await self._fetch(client, icon_url, require_ok=True)

        findings = self._detect(base, headers, cookies, generator, scripts, links,
                                body.lower(), robots.text if robots is not None else "")
        if robots is not None:  # robots.txt presence is a fingerprint signal too
            disallow = sum(1 for line in robots.text.splitlines()
                           if line.lower().startswith("disallow:"))
            findings.append(self._finding(
                title="robots.txt present", severity=Severity.INFO, target=base,
                evidence=f"/robots.txt with {disallow} Disallow directive(s)",
                metadata={"type": "robots", "disallow": disallow}))
        if favicon is not None:
            findings.append(self._finding(
                title="Favicon present", severity=Severity.INFO, target=base,
                evidence=f"{favicon.url} ({len(favicon.content)} bytes)",
                metadata={"type": "favicon", "url": str(favicon.url)}))
        return findings

    @staticmethod
    async def _fetch(client: httpx.AsyncClient, url: str,
                     require_ok: bool = False) -> httpx.Response | None:
        """GET ``url``, returning None on transport errors (or 4xx/5xx when required)."""
        try:
            resp = await client.get(url)
        except httpx.HTTPError:
            return None
        return None if (require_ok and resp.status_code >= 400) else resp

    # -------------------------------------------------------------- matching
    def _detect(self, target: str, headers: dict[str, str], cookies: list[str],
                generator: str, scripts: list[str], links: list[str], html: str,
                robots: str) -> list[Finding]:
        findings: list[Finding] = []
        for tech, (category, matchers) in sorted(self.FINGERPRINTS.items()):
            signals: list[str] = []
            sources: list[str] = []  # Texts a version number may be parsed from
            for header, needle in matchers.get("headers", {}).items():
                value = headers.get(header, "")
                if value and needle in value.lower():
                    signals.append(f"{header}: {value}")
                    sources.append(value)
            gen_needle = matchers.get("generator")
            if gen_needle and gen_needle in generator.lower():
                signals.append(f"meta generator: {generator}")
                sources.append(generator)
            for needle in matchers.get("cookies", []):
                if any(needle in c for c in cookies):
                    signals.append(f"cookie: {needle}")
            for bucket, haystacks in (("scripts", scripts), ("links", links)):
                for needle in matchers.get(bucket, []):
                    hit = next((s for s in haystacks if needle in s), None)
                    if hit:
                        signals.append(f"{bucket[:-1]}: {hit}")
                        sources.append(hit)
            for needle in matchers.get("html", []):
                if needle in html:
                    signals.append(f"html: {needle}")
            for needle in matchers.get("robots", []):
                if needle in robots:
                    signals.append(f"robots.txt: {needle}")
            for pattern in matchers.get("html_regex", []):
                if re.search(pattern, html, re.I):
                    signals.append(f"html~: {pattern}")
            if not signals:
                continue
            version = next((m.group(0) for s in sources if (m := VERSION_RE.search(s))), None)
            findings.append(self._finding(
                title=f"{tech} detected" + (f" {version}" if version else ""),
                severity=Severity.INFO, target=target, evidence="; ".join(signals[:3]),
                metadata={"type": "technology", "technology": tech, "category": category,
                          "version": version, "signals": signals}))
        return findings

    # --------------------------------------------------------------- helpers
    @staticmethod
    def _parse_html(html: str) -> tuple[str, list[str], list[str], str]:
        """Return (meta generator, script srcs, link hrefs, favicon href)."""
        if BeautifulSoup is not None:
            soup = BeautifulSoup(html, "html.parser")
            generator = ""
            for meta in soup.find_all("meta"):
                if str(meta.get("name", "")).lower() == "generator":
                    generator = str(meta.get("content", ""))
                    break
            scripts = [str(s.get("src", "")).lower() for s in soup.find_all("script", src=True)]
            links = [str(l.get("href", "")).lower() for l in soup.find_all("link", href=True)]
            icon = next((str(l.get("href", "")) for l in soup.find_all("link", href=True)
                         if "icon" in " ".join(l.get("rel") or []).lower()), "")
            return generator, scripts, links, icon
        generator = ""  # Regex fallback when bs4 is not installed
        for pattern in (r'name=["\']generator["\'][^>]*content=["\']([^"\']+)',
                        r'content=["\']([^"\']+)["\'][^>]*name=["\']generator["\']'):
            found = re.search(pattern, html, re.I)
            if found:
                generator = found.group(1)
                break
        scripts = [s.lower() for s in re.findall(r"<script[^>]+src=[\"']([^\"']+)", html, re.I)]
        links = [l.lower() for l in re.findall(r"<link[^>]+href=[\"']([^\"']+)", html, re.I)]
        icons = re.findall(r"rel=[\"'][^\"']*icon[^\"']*[\"'][^>]*href=[\"']([^\"']+)", html, re.I)
        return generator, scripts, links, (icons[0] if icons else "")

    @staticmethod
    def _finding(*, title: str, severity: Severity, target: str, evidence: str,
                 metadata: dict) -> Finding:
        return Finding(title=title, severity=severity, target=target, evidence=evidence,
                       remediation=TECH_REMEDIATION, scanner=TechScanner.name,
                       metadata=metadata)
