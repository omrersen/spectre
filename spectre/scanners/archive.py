"""Web archive / historical exposure scanner: Wayback Machine snapshots and URLhaus."""

from __future__ import annotations

import re
from urllib.parse import urlparse

import httpx

from .base import BaseScanner
from ..models import Finding, Severity

USER_AGENT = "SpectreScanner/1.0"
TIMEOUT = 20.0
MAX_FINDINGS = 50
MAX_URLHAUS = 10
CDX_API = "https://web.archive.org/cdx/search/cdx"
WAYBACK_API = "https://archive.org/wayback/available"
URLHAUS_API = "https://urlhaus-api.abuse.ch/v1/host/"

# category -> severity, path pattern, remediation for URLs seen in historical archives
ARCHIVE_RULES: tuple[tuple[str, Severity, re.Pattern, str], ...] = (
    ("backup file", Severity.MEDIUM,
     re.compile(r"\.(sql|bak|backup|old|orig|zip|tar\.gz|tgz|gz|rar|7z|dump|db)(\?|#|$)", re.I),
     "Remove sensitive files from web root and archive.org (request removal)."),
    ("config/source file", Severity.MEDIUM,
     re.compile(r"/(\.git|\.env|\.ds_store|\.svn|\.hg|\.htpasswd|\.htaccess|\.aws|id_rsa"
                r"|wp-config|web\.config|config\.(php|json|yml|yaml|ini|bak)|phpinfo)", re.I),
     "Remove config and source files from web root and archive.org (request removal)."),
    ("admin/login panel", Severity.INFO,
     re.compile(r"/(admin|administrator|login|wp-login|wp-admin|signin|sign-in|dashboard"
                r"|phpmyadmin|manager)(/|$|\.|\?)", re.I),
     "Restrict admin/login endpoints with authentication and network-level access controls."),
    ("API endpoint", Severity.INFO,
     re.compile(r"/(api|graphql|swagger|swagger-ui|rest|actuator|v[0-9]+)(/|$)", re.I),
     "Ensure API endpoints require authentication and are not publicly enumerable."),
    ("debug/trace endpoint", Severity.INFO,
     re.compile(r"/(debug|trace|_profiler|server-status|server-info|console|elmah|_test"
                r"|phpinfo|actuator/health)(/|$|\.|\?)", re.I),
     "Disable debug, trace and status endpoints in production builds."),
)


class ArchiveScanner(BaseScanner):
    name = "archive"
    description = "Web archive / historical exposure scanner"
    version = "1.0.0"

    # -------------------------------------------------------------- scanning
    async def scan(self, target: str) -> list[Finding]:
        """Correlate the host with Wayback Machine history and URLhaus."""
        host = urlparse(target if "://" in target else f"https://{target}").hostname
        if not host:
            return []
        findings: list[Finding] = []
        async with httpx.AsyncClient(follow_redirects=True, timeout=TIMEOUT,
                                     headers={"User-Agent": USER_AGENT}) as client:
            closest = await self._closest(client, target)
            if closest is not None:
                findings.append(closest)
            seen: set[str] = set()
            for timestamp, url in await self._cdx(client, f"{host}/*"):
                if len(findings) >= MAX_FINDINGS:
                    break
                finding = self._classify(url, timestamp)
                if finding is not None and url not in seen:
                    seen.add(url)
                    findings.append(finding)
            findings.extend(await self._urlhaus(client, host))
            history = await self._robots_history(client, host)
            if history is not None:
                findings.append(history)
        return findings[:MAX_FINDINGS]

    # --------------------------------------------------------------- sources
    async def _closest(self, client: httpx.AsyncClient, target: str) -> Finding | None:
        """Wayback availability API: is the target itself archived?"""
        try:
            resp = await client.get(WAYBACK_API, params={"url": target})
        except httpx.HTTPError:
            return None
        try:
            closest = resp.json().get("archived_snapshots", {}).get("closest", {})
        except ValueError:
            return None
        if not closest.get("available"):
            return None
        archived_url = str(closest.get("url") or target)
        return self._finding(
            title="Target has historical Wayback Machine snapshots",
            severity=Severity.INFO, target=archived_url,
            evidence=f"wayback {closest.get('timestamp', '?')} | status {closest.get('status', '?')} "
                     f"| {archived_url}",
            remediation="Review archived snapshots for leaked secrets or sensitive content.",
            metadata={"type": "archive", "source": "wayback", "url": archived_url,
                      "timestamp": str(closest.get("timestamp") or "")})

    async def _cdx(self, client: httpx.AsyncClient, match: str,
                   limit: str = "100") -> list[tuple[str, str]]:
        """Return (timestamp, original URL) rows from the CDX API; [] on any error."""
        try:
            resp = await client.get(CDX_API, params={"url": match, "output": "json",
                                                     "limit": limit, "collapse": "urlkey"})
        except httpx.HTTPError:
            return []
        try:
            rows = resp.json()
        except ValueError:
            return []  # 404 / empty body when nothing matches the query
        if not isinstance(rows, list) or len(rows) < 2 or not isinstance(rows[0], list):
            return []
        header = [str(column) for column in rows[0]]
        if "timestamp" not in header or "original" not in header:
            return []
        ts_i, url_i = header.index("timestamp"), header.index("original")
        return [(str(row[ts_i]), str(row[url_i]))
                for row in rows[1:] if len(row) > max(ts_i, url_i)]

    async def _urlhaus(self, client: httpx.AsyncClient, host: str) -> list[Finding]:
        """URLhaus host report: known malicious URLs served from this host."""
        try:
            resp = await client.post(URLHAUS_API, data={"host": host})
        except httpx.HTTPError:
            return []
        try:
            data = resp.json()
        except ValueError:
            return []  # API unavailable, auth required, or non-JSON error page
        if not isinstance(data, dict) or data.get("query_status") != "ok":
            return []
        findings: list[Finding] = []
        for entry in (data.get("urls") or [])[:MAX_URLHAUS]:
            url = entry.get("url")
            if not url:
                continue
            threat = entry.get("threat") or "malware distribution"
            tags = ", ".join(entry.get("tags") or []) or "n/a"
            findings.append(self._finding(
                title=f"Known malicious URL on host: {url}",
                severity=Severity.HIGH, target=url,
                evidence=f"URLhaus | threat: {threat} | tags: {tags} | {entry.get('urlhaus_reference', '')}",
                remediation=("Investigate the host for compromise, remove the reported content and "
                             "block the URL."),
                metadata={"type": "malicious_url", "source": "urlhaus", "url": url,
                          "threat": threat}))
        return findings

    async def _robots_history(self, client: httpx.AsyncClient, host: str) -> Finding | None:
        """Compare live robots.txt with its newest archived snapshot (best effort)."""
        rows = await self._cdx(client, f"{host}/robots.txt", limit="5")
        if not rows:
            return None
        timestamp, original = rows[-1]  # CDX rows are ordered oldest first
        archived = await self._get(client, f"https://web.archive.org/web/{timestamp}id_/{original}")
        live = await self._get(client, f"https://{host}/robots.txt")
        if archived is None or live is None:
            return None  # Snapshot or live copy unavailable: skip gracefully
        added = sorted(set(self._disallow(live.text)) - set(self._disallow(archived.text)))
        removed = sorted(set(self._disallow(archived.text)) - set(self._disallow(live.text)))
        if not added and not removed:
            return None
        return self._finding(
            title="robots.txt differs from archived snapshot",
            severity=Severity.INFO, target=f"https://{host}/robots.txt",
            evidence=f"wayback {timestamp} | hidden now: {', '.join(added) or '-'} "
                     f"| no longer hidden: {', '.join(removed) or '-'}",
            remediation="Review robots.txt history for paths that were exposed or recently hidden.",
            metadata={"type": "archive", "source": "wayback", "timestamp": timestamp,
                      "added": added, "removed": removed})

    # -------------------------------------------------------------- analysis
    def _classify(self, url: str, timestamp: str) -> Finding | None:
        """Map an archived URL to a finding when it matches a sensitive-path rule."""
        path = urlparse(url).path or "/"
        for category, severity, pattern, remediation in ARCHIVE_RULES:
            if pattern.search(path):
                return self._finding(
                    title=f"Archived {category}: {path}",
                    severity=severity, target=url,
                    evidence=f"wayback {timestamp} | source: {CDX_API} | {url}",
                    remediation=remediation,
                    metadata={"type": "archive", "source": "wayback", "category": category,
                              "timestamp": timestamp, "url": url})
        return None

    # --------------------------------------------------------------- helpers
    @staticmethod
    async def _get(client: httpx.AsyncClient, url: str) -> httpx.Response | None:
        try:
            resp = await client.get(url)
        except httpx.HTTPError:
            return None
        return resp if resp.status_code == 200 else None

    @staticmethod
    def _disallow(text: str) -> list[str]:
        paths = []
        for raw in text.splitlines():
            line = raw.split("#", 1)[0].strip()
            if line.lower().startswith("disallow:") and ":" in line:
                value = line.split(":", 1)[1].strip()
                if value:
                    paths.append(value)
        return paths

    @staticmethod
    def _finding(*, title: str, severity: Severity, target: str, evidence: str,
                 remediation: str, metadata: dict) -> Finding:
        return Finding(title=title, severity=severity, target=target, evidence=evidence,
                       remediation=remediation, scanner=ArchiveScanner.name, metadata=metadata)
