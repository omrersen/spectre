"""CVE correlation scanner: maps detected technology versions to NVD and GitHub advisories."""

from __future__ import annotations

import asyncio
import time

import httpx

from .base import BaseScanner
from .tech import TechScanner
from ..models import Finding, Severity

TIMEOUT = 15.0
RATE_LIMIT_DELAY = 1.5   # NVD allows ~6 requests / 30s without an API key
DESC_LENGTH = 200         # Evidence description snippet cap
GH_SCORES = {"critical": 9.0, "high": 7.0, "moderate": 4.0, "medium": 4.0, "low": 1.0}  # GH severities as scores
SEVERITY_BY_SCORE = ((9.0, Severity.CRITICAL), (7.0, Severity.HIGH), (4.0, Severity.MEDIUM))


class CVEScanner(BaseScanner):
    name = "cve"
    description = "CVE correlation scanner"
    version = "1.0.0"

    NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    GH_API = "https://api.github.com/advisories"

    # Detected technology -> (NVD vendor, product) for cpe:2.3:a:vendor:product:version:*
    CPE_MAP: dict[str, tuple[str, str]] = {
        # Servers / infrastructure
        "nginx": ("f5", "nginx"), "apache": ("apache", "http_server"), "apache tomcat": ("apache", "tomcat"), "microsoft iis": ("microsoft", "iis"),
        "openresty": ("openresty", "openresty"), "litespeed": ("litespeedtech", "litespeed_server"), "lighttpd": ("lighttpd", "lighttpd"), "haproxy": ("haproxy", "haproxy"),
        "caddy": ("caddyserver", "caddy"), "varnish": ("varnish-software", "varnish_cache"), "modsecurity": ("modsecurity", "modsecurity"),
        # Languages / frameworks
        "php": ("php", "php"), "django": ("djangoproject", "django"), "flask": ("pallets", "flask"), "laravel": ("laravel", "laravel"),
        "ruby on rails": ("rubyonrails", "rails"), "express": ("expressjs", "express"), "asp.net": ("microsoft", "asp.net"), "asp.net core": ("microsoft", "asp.net_core"),
        "spring": ("vmware", "spring_framework"), "next.js": ("vercel", "next.js"), "nuxt": ("nuxtlabs", "nuxt.js"),
        # CMS
        "wordpress": ("wordpress", "wordpress"), "joomla": ("joomla", "joomla"), "drupal": ("drupal", "drupal"), "magento": ("magento", "magento"),
        "prestashop": ("prestashop", "prestashop"), "mediawiki": ("mediawiki", "mediawiki"), "typo3": ("typo3", "typo3"), "ghost": ("tryghost", "ghost"),
        # Client-side libraries
        "jquery": ("jquery", "jquery"), "react": ("facebook", "react"), "vue.js": ("vuejs", "vue.js"), "angular": ("angularjs", "angular"),
        "angularjs": ("angularjs", "angularjs"), "bootstrap": ("getbootstrap", "bootstrap"), "lodash": ("lodash", "lodash"), "axios": ("axios", "axios"),
        "moment": ("momentjs", "moment"), "socket.io": ("socketio", "socket.io"), "swagger ui": ("smartbear", "swagger_ui"),
    }

    # Detected technology -> (GitHub advisory ecosystem, package name)
    GH_PACKAGES: dict[str, tuple[str, str]] = {
        "jquery": ("npm", "jquery"), "bootstrap": ("npm", "bootstrap"), "lodash": ("npm", "lodash"), "axios": ("npm", "axios"), "react": ("npm", "react"),
        "vue.js": ("npm", "vue"), "express": ("npm", "express"), "next.js": ("npm", "next"), "nuxt": ("npm", "nuxt"), "moment": ("npm", "moment"),
        "socket.io": ("npm", "socket.io"), "angular": ("npm", "@angular/core"), "angularjs": ("npm", "angular"), "django": ("pip", "django"), "flask": ("pip", "flask"),
        "laravel": ("composer", "laravel"), "ruby on rails": ("rubygems", "rails"), "wordpress": ("wordpress", "wordpress"),
    }

    def __init__(self, api_key: str | None = None, max_techs: int = 15, delay: float = RATE_LIMIT_DELAY, time_budget: float = 20.0):
        self.api_key = api_key
        self.max_techs = max_techs
        self.delay = delay
        self.time_budget = time_budget   # Stop lookups early enough to return partial results
        self._cache: dict[str, list[dict]] = {}   # In-memory cache for the current scan
        self._rate_limited = False

    # -------------------------------------------------------------- scanning
    async def scan(self, target: str) -> list[Finding]:
        """Discover technologies at ``target`` and correlate them with known CVEs."""
        self._cache.clear()
        self._rate_limited = False
        techs = await self._discover(target)
        if not techs:
            return []
        findings: list[Finding] = []
        seen: set[str] = set()
        started = time.monotonic()
        headers = {"User-Agent": "SpectreScanner/1.0", **({"apiKey": self.api_key} if self.api_key else {})}
        async with httpx.AsyncClient(timeout=TIMEOUT, headers=headers) as client:
            for index, (tech, version) in enumerate(techs[: self.max_techs]):
                if index and time.monotonic() - started > self.time_budget:
                    break  # Return partial results instead of hitting the engine timeout
                if index:
                    await asyncio.sleep(self.delay)  # Respect NVD's anonymous rate limit
                nvd, gh = await asyncio.gather(self._query_nvd(client, tech, version),
                                               self._query_github(client, tech, version),
                                               return_exceptions=True)
                for source, results in (("nvd", nvd), ("github", gh)):
                    for record in results if isinstance(results, list) else []:
                        built = (self._nvd_finding if source == "nvd"
                                 else self._gh_finding)(record, tech, version)
                        if built and built[0] not in seen:
                            seen.add(built[0])   # Advisory seen already (e.g. CVE via both APIs)
                            findings.append(built[1])
                if self._rate_limited:
                    break
        return findings[:100]

    async def _discover(self, target: str) -> list[tuple[str, str]]:
        """Fingerprint the target, keeping tech+version pairs we can look up."""
        try:
            detected = await TechScanner().scan(target)
        except Exception:  # A fingerprinting failure must not break correlation
            return []
        techs: list[tuple[str, str]] = []
        for finding in detected:
            meta = finding.metadata or {}
            tech, version = meta.get("technology"), meta.get("version")
            if (meta.get("type") == "technology" and tech and version
                    and (tech in self.CPE_MAP or tech in self.GH_PACKAGES)
                    and (tech, version) not in techs):
                techs.append((tech, version))
        return techs

    # ------------------------------------------------------------ NVD source
    async def _query_nvd(self, client: httpx.AsyncClient, tech: str, version: str) -> list[dict]:
        """Query NVD 2.0 for CVEs matching this technology's exact CPE name."""
        cpe = self._cpe(tech, version)
        if not cpe:
            return []
        if cpe not in self._cache:
            try:
                resp = await client.get(self.NVD_API, params={"cpeName": cpe})
            except httpx.HTTPError:
                return []
            if resp.status_code in (403, 429):  # Anonymous NVD rate limit exhausted
                self._rate_limited = True
                return []
            body = self._json(resp, {})  # 404 / non-200: no CVEs reference this CPE
            self._cache[cpe] = [v["cve"] for v in body.get("vulnerabilities", [])
                                if isinstance(v, dict) and v.get("cve")]
        return self._cache[cpe]

    def _nvd_finding(self, cve: dict, tech: str, version: str) -> tuple[str, Finding] | None:
        if not (cve_id := cve.get("id")):
            return None
        score, vector, severity = self._cvss(cve.get("metrics", {}))
        description = self._description(cve)
        url = next((r.get("url") for r in cve.get("references") or [] if r.get("url")),
                   f"https://nvd.nist.gov/vuln/detail/{cve_id}")
        return cve_id, Finding(
            title=f"{cve_id}: {self._summary(description)}",
            severity=severity, target=f"{tech} {version}",
            evidence=f"CVSS {score} {vector} | {description[:DESC_LENGTH]} | {url}",
            cvss=score, cve=[cve_id], scanner=self.name,
            remediation=self._remediation(tech, version, self._nvd_fixed(cve, tech, version)),
            metadata={"type": "cve", "source": "nvd", "cve": cve_id, "technology": tech, "version": version, "url": url})

    # -------------------------------------------------------- GitHub source
    async def _query_github(self, client: httpx.AsyncClient, tech: str, version: str) -> list[dict]:
        """Query GitHub's advisories API for the mapped package/version."""
        if not (mapping := self.GH_PACKAGES.get(tech)):
            return []
        ecosystem, package = mapping
        cache_key = f"gh:{ecosystem}:{package}:{version}"
        if cache_key not in self._cache:
            try:
                resp = await client.get(self.GH_API, params={"ecosystem": ecosystem,
                                                             "affects": f"{package}@{version}"})
            except httpx.HTTPError:
                return []
            # Errors and rate limits collapse to an empty result: never abort the scan
            items = self._json(resp, [])
            self._cache[cache_key] = items if isinstance(items, list) else []
        return self._cache[cache_key]

    @staticmethod
    def _json(resp: httpx.Response, default):
        try:
            return resp.json() if resp.status_code == 200 else default
        except ValueError:
            return default

    def _gh_finding(self, advisory: dict, tech: str, version: str) -> tuple[str, Finding] | None:
        if not (ident := advisory.get("cve_id") or advisory.get("ghsa_id")):
            return None
        score = float((advisory.get("cvss") or {}).get("score") or 0.0) or GH_SCORES.get(str(advisory.get("severity", "")).lower(), 0.0)
        summary = advisory.get("summary") or self._summary(advisory.get("description", ""))
        url = advisory.get("html_url") or f"https://github.com/advisories/{ident}"
        cve_id = advisory.get("cve_id") or ""
        _, package = self.GH_PACKAGES.get(tech, ("", ""))
        patched = next((v.get("first_patched_version") for v in advisory.get("vulnerabilities") or []
                        if isinstance(v, dict) and str((v.get("package") or {}).get("name", "")).lower() == package.lower()), "")
        fixed = patched.get("identifier", "") if isinstance(patched, dict) else str(patched or "")  # REST str / GraphQL object
        return ident, Finding(
            title=f"{ident}: {summary}",
            severity=self._severity(score), target=f"{tech} {version}",
            evidence=f"CVSS {score} | {(advisory.get('description') or summary)[:DESC_LENGTH]} | {url}",
            cvss=score, cve=[cve_id] if cve_id else [], scanner=self.name,
            remediation=self._remediation(tech, version, fixed),
            metadata={"type": "cve", "source": "github", "ghsa": advisory.get("ghsa_id"), "cve": cve_id, "technology": tech, "version": version, "url": url})

    # --------------------------------------------------------------- helpers
    @classmethod
    def _cpe(cls, tech: str, version: str) -> str | None:
        """Build the CPE 2.3 name for a detected technology/version pair."""
        if not (mapping := cls.CPE_MAP.get(tech)):
            return None
        vendor, product = mapping
        return f"cpe:2.3:a:{vendor}:{product}:{version}:*:*:*:*:*:*:*"

    @classmethod
    def _cvss(cls, metrics: dict) -> tuple[float, str, Severity]:
        """Extract (base score, vector, severity), preferring CVSS v3 over v2."""
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV3", "cvssMetricV2"):
            for metric in metrics.get(key) or []:
                data = metric.get("cvssData") or {}
                if data.get("baseScore") is not None:
                    score = float(data["baseScore"])
                    return score, str(data.get("vectorString") or ""), cls._severity(score)
        return 0.0, "", Severity.INFO

    @staticmethod
    def _severity(score: float) -> Severity:
        return (Severity.INFO if score <= 0 else
                next((s for threshold, s in SEVERITY_BY_SCORE if score >= threshold), Severity.LOW))

    @staticmethod
    def _description(cve: dict) -> str:
        descriptions = cve.get("descriptions") or []
        english = next((d.get("value", "") for d in descriptions if d.get("lang") == "en"), "")
        return english or (descriptions[0].get("value", "") if descriptions else "")

    @staticmethod
    def _summary(description: str) -> str:
        head = description.split(". ")[0].strip()
        return head if len(head) <= 90 else head[:87] + "..."

    @classmethod
    def _nvd_fixed(cls, cve: dict, tech: str, version: str) -> str:
        mapping = cls.CPE_MAP.get(tech)
        needle = f":a:{mapping[0]}:{mapping[1]}:" if mapping else ""
        current = cls._version_key(version)
        for config in cve.get("configurations") or []:
            for node in config.get("nodes") or []:
                for match in node.get("cpeMatch") or []:
                    candidate = str(match.get("versionEndExcluding") or "")
                    if (match.get("vulnerable") and needle in str(match.get("criteria", ""))
                            and cls._version_key(candidate) > current):
                        return candidate
        return ""

    @staticmethod
    def _version_key(version: str) -> tuple[int, ...]:
        try:
            return tuple(int(p) for p in version.split("."))
        except ValueError:
            return ()

    @staticmethod
    def _remediation(tech: str, version: str, fixed: str) -> str:
        return (f"Upgrade {tech} from {version} to {fixed} or later." if fixed else
                f"No fixed release listed; upgrade {tech} to the latest patched version.")
