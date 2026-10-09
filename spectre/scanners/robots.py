"""Robots, sitemap and security.txt analyzer: hidden paths, sitemap refs and contact policy."""

from __future__ import annotations

import re
from datetime import datetime, timezone
from urllib.parse import urljoin, urlparse

import httpx

from .base import BaseScanner
from ..models import Finding, Severity

USER_AGENT = "SpectreScanner/1.0"
TIMEOUT = 10.0
MAX_FINDINGS = 50
MAX_SITEMAPS = 3
MAX_HIDDEN_PATHS = 20

# Disallow prefixes that reveal interesting, non-public areas (recon value)
SENSITIVE_DISALLOW = ("/admin", "/backup", "/config", "/private", "/debug", "/console",
                      "/.git", "/wp-admin", "/api/internal", "/server-status", "/phpmyadmin")
# Path segments that make a sitemap entry worth a second look
SENSITIVE_SEGMENTS = {"admin", "wp-admin", "login", "wp-login", "signin", "api",
                      "graphql", "swagger"}
LOC_RE = re.compile(r"<loc>\s*([^<]+?)\s*</loc>", re.I)

HIDDEN_REMEDIATION = ("Hidden paths aid reconnaissance; keep internal routes out of robots.txt "
                      "and enforce access controls on them.")
SITEMAP_REMEDIATION = ("Remove sensitive URLs from the sitemap and require authentication for "
                       "the endpoints they reference.")
SECURITY_MISSING = ("Publish /.well-known/security.txt (RFC 9116) with Contact and Expires "
                    "fields.")
SECURITY_EXPIRED = "Refresh security.txt with a future Expires date so researchers can reach you."
INFO_REMEDIATION = "Informational: no action required unless the file leaks sensitive detail."


class RobotsScanner(BaseScanner):
    name = "robots"
    description = "Robots.txt, sitemap and security.txt analyzer"
    version = "1.0.0"

    # -------------------------------------------------------------- scanning
    async def scan(self, target: str) -> list[Finding]:
        """Analyze robots.txt, sitemap.xml, security.txt and well-known files."""
        base_url = target if "://" in target else f"https://{target}"
        parsed = urlparse(base_url)
        if not parsed.hostname:
            return []
        base = f"{parsed.scheme}://{parsed.netloc}"
        findings: list[Finding] = []

        async with httpx.AsyncClient(follow_redirects=True, timeout=TIMEOUT,
                                     headers={"User-Agent": USER_AGENT}) as client:
            robots = await self._fetch(client, f"{base}/robots.txt")
            if robots is None:
                return []  # Host unreachable: nothing to analyze
            disallow, allow, sitemaps = self._parse_robots(robots.text)
            findings.extend(self._hidden_paths(base, disallow, allow))
            findings.extend(await self._sitemaps(client, base, sitemaps))
            findings.extend(await self._security_txt(client, base))
            findings.extend(await self._well_known(client, base))
        return findings[:MAX_FINDINGS]

    # ------------------------------------------------------------- robots.txt
    @staticmethod
    def _parse_robots(text: str) -> tuple[list[str], list[str], list[str]]:
        """Split robots.txt into (Disallow, Allow, Sitemap) directive values."""
        disallow: list[str] = []
        allow: list[str] = []
        sitemaps: list[str] = []
        for raw in text.splitlines():
            line = raw.split("#", 1)[0].strip()
            if ":" not in line:
                continue
            key, _, value = line.partition(":")
            key, value = key.strip().lower(), value.strip()
            if not value:
                continue
            if key == "disallow":
                disallow.append(value)
            elif key == "allow":
                allow.append(value)
            elif key == "sitemap":
                sitemaps.append(value)
        return disallow, allow, sitemaps

    def _hidden_paths(self, base: str, disallow: list[str],
                      allow: list[str]) -> list[Finding]:
        """One INFO finding per sensitive Disallow entry (recon value)."""
        findings: list[Finding] = []
        sensitive = [p for p in disallow if p.rstrip("*").lower().startswith(SENSITIVE_DISALLOW)]
        for value in sensitive[:MAX_HIDDEN_PATHS]:
            path = value.rstrip("*")
            contradicted = any(a.rstrip("*") == path for a in allow)
            findings.append(self._finding(
                title=f"Hidden path in robots.txt: {path}",
                severity=Severity.INFO, target=urljoin(base, path),
                evidence=f"Disallow: {value} (from {base}/robots.txt)"
                         + (" | also Allow'd: contradictory rules" if contradicted else ""),
                remediation=HIDDEN_REMEDIATION,
                metadata={"type": "robots", "directive": "Disallow", "path": path,
                          "contradicted": contradicted}))
        return findings

    # ---------------------------------------------------------------- sitemap
    async def _sitemaps(self, client: httpx.AsyncClient, base: str,
                        sitemaps: list[str]) -> list[Finding]:
        """Count sitemap URLs and flag admin/login/api references."""
        findings: list[Finding] = []
        for sitemap in (sitemaps or [f"{base}/sitemap.xml"])[:MAX_SITEMAPS]:
            resp = await self._fetch(client, sitemap, require_ok=True)
            if resp is None:
                continue  # Absent or unreadable sitemap: skip gracefully
            locs = LOC_RE.findall(resp.text)
            flagged = sorted({loc for loc in locs if self._sensitive_loc(loc)})[:5]
            if flagged:
                findings.append(self._finding(
                    title="Sitemap references sensitive paths",
                    severity=Severity.INFO, target=sitemap,
                    evidence=f"{len(locs)} URL(s) | sensitive: {', '.join(flagged)}",
                    remediation=SITEMAP_REMEDIATION,
                    metadata={"type": "sitemap", "urls": len(locs), "flagged": flagged}))
        return findings

    @staticmethod
    def _sensitive_loc(loc: str) -> bool:
        segments = [segment.lower() for segment in urlparse(loc).path.split("/") if segment]
        return any(segment in SENSITIVE_SEGMENTS for segment in segments)

    # ------------------------------------------------------------ security.txt
    async def _security_txt(self, client: httpx.AsyncClient, base: str) -> list[Finding]:
        """RFC 9116 contact file: missing -> LOW, expired Expires -> MEDIUM."""
        url = f"{base}/.well-known/security.txt"
        resp = await self._fetch(client, url)
        if resp is None:
            return []  # Transport error: do not claim the file is absent
        if resp.status_code >= 400:
            return [self._finding(
                title="security.txt missing", severity=Severity.LOW, target=url,
                evidence=f"HTTP {resp.status_code} for /.well-known/security.txt",
                remediation=SECURITY_MISSING,
                metadata={"type": "securitytxt", "field": "missing",
                          "status": resp.status_code})]
        fields: dict[str, str] = {}
        for raw in resp.text.splitlines():
            key, sep, value = raw.partition(":")
            if sep and key.strip().lower() not in fields:
                fields[key.strip().lower()] = value.strip()
        expires = fields.get("expires", "")
        if expires and self._expired(expires):
            return [self._finding(
                title="security.txt has expired",
                severity=Severity.MEDIUM, target=url,
                evidence=f"Expires: {expires} (in the past) | "
                         f"Contact: {fields.get('contact', 'not set')}",
                remediation=SECURITY_EXPIRED,
                metadata={"type": "securitytxt", "field": "expires", "expires": expires,
                          "contact": fields.get("contact", "")})]
        return []

    @staticmethod
    def _expired(value: str) -> bool:
        try:
            expires = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return False  # Unparsable date: do not claim expiry
        if expires.tzinfo is None:
            expires = expires.replace(tzinfo=timezone.utc)
        return expires < datetime.now(timezone.utc)

    # ------------------------------------------------------------ well-known
    async def _well_known(self, client: httpx.AsyncClient, base: str) -> list[Finding]:
        """Optional change.txt / humans.txt presence (informational)."""
        findings: list[Finding] = []
        for path, title in (("/.well-known/change.txt", "change.txt published"),
                            ("/humans.txt", "humans.txt published")):
            resp = await self._fetch(client, f"{base}{path}", require_ok=True)
            if resp is None:
                continue
            body = next((line.strip() for line in resp.text.splitlines()
                         if line.strip() and not line.strip().startswith("#")), "")
            findings.append(self._finding(
                title=title, severity=Severity.INFO, target=f"{base}{path}",
                evidence=f"HTTP {resp.status_code} | {body[:120]}" if body
                         else f"HTTP {resp.status_code}",
                remediation=INFO_REMEDIATION,
                metadata={"type": "wellknown", "path": path}))
        return findings

    # --------------------------------------------------------------- helpers
    @staticmethod
    async def _fetch(client: httpx.AsyncClient, url: str,
                     require_ok: bool = False) -> httpx.Response | None:
        """GET ``url``, returning None on transport errors (or 4xx/5xx when required)."""
        try:
            resp = await client.get(url)
        except httpx.HTTPError:
            return None
        return None if (require_ok and resp.status_code >= 400) else resp

    @staticmethod
    def _finding(*, title: str, severity: Severity, target: str, evidence: str,
                 remediation: str, metadata: dict) -> Finding:
        return Finding(title=title, severity=severity, target=target, evidence=evidence,
                       remediation=remediation, scanner=RobotsScanner.name, metadata=metadata)
