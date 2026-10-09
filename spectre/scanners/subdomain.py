"""Subdomain enumeration scanner.

Discovers subdomains of a target domain using multiple sources:

* crt.sh         - Certificate Transparency log aggregation
* HackerTarget   - free hostsearch API
* VirusTotal     - v3 sub_domains endpoint (requires ``VT_API_KEY`` /
                   ``VIRUSTOTAL_API_KEY``; skipped gracefully when absent)
* DNS brute force - probes a built-in wordlist of common labels

Every candidate discovered by any source is verified with a real DNS
resolution (A/AAAA) before a Finding is reported, which filters out
stale/incorrect passive results.
"""

from __future__ import annotations

import asyncio
import os
import re

import dns.exception
import dns.resolver
import httpx

from ..models import Finding, Severity
from .base import BaseScanner


class SubdomainScanner(BaseScanner):
    """Discover subdomains through passive sources and DNS brute force."""

    name = "subdomain"
    description = "Subdomain enumeration scanner"
    version = "1.0.0"

    CRTSH_URL = "https://crt.sh/?q=%.{domain}&output=json"
    HACKERTARGET_URL = "https://api.hackertarget.com/hostsearch/?q={domain}"
    VIRUSTOTAL_URL = "https://www.virustotal.com/api/v3/domains/{domain}/sub_domains"
    USER_AGENT = "Spectre/1.0.0 (security scanner)"

    SOURCE_TIMEOUT = 10.0  # seconds per HTTP source
    DNS_TIMEOUT = 2.5  # seconds per DNS query
    DNS_CONCURRENCY = 50
    VIRUSTOTAL_PAGE_LIMIT = 3  # keep API usage bounded

    # Common sub-domain labels used for DNS brute forcing (150+ words).
    WORDLIST: list[str] = [
        # web / www variants
        "www", "www1", "www2", "www3", "web", "web1", "web2", "www-old",
        # mail / messaging
        "mail", "mail1", "mail2", "mx", "mx1", "mx2", "smtp", "pop", "pop3",
        "imap", "webmail", "email", "exch", "exchange", "owa", "autodiscover",
        # name service
        "ns", "ns1", "ns2", "ns3", "dns", "dns1", "dns2", "ns-old",
        # file transfer
        "ftp", "ftp1", "sftp", "files", "file", "share", "shares",
        # api / services
        "api", "api1", "api2", "api3", "apis", "apigw", "gateway", "gw",
        "rest", "graphql", "v1", "v2", "soap", "ws",
        # application tiers
        "app", "app1", "app2", "apps", "application", "mobile", "m", "ios",
        "android", "spa",
        # environments
        "dev", "dev1", "dev2", "development", "devel", "sandbox", "lab", "labs",
        "staging", "stage", "stg", "uat", "qa", "test", "testing", "test1",
        "test2", "demo", "preview", "beta", "alpha", "canary", "edge",
        # administration
        "admin", "administrator", "adm", "panel", "cp", "cpanel", "webadmin",
        "sysadmin", "panel1",
        # portals / dashboards
        "portal", "dashboard", "console", "manage", "management", "manager",
        "backend", "controlpanel",
        # content / commerce
        "blog", "news", "press", "forum", "community", "shop", "store",
        "commerce", "cart", "checkout", "pay", "payment", "payments", "billing",
        # static content / cdn
        "cdn", "static", "assets", "media", "img", "images", "image", "video",
        "videos", "stream", "live", "download", "downloads",
        # remote access
        "vpn", "remote", "citrix", "rdp", "ssh", "bastion", "jump", "jumpbox",
        "gateway1",
        # infrastructure
        "proxy", "loadbalancer", "lb", "lb1", "lb2", "haproxy", "nginx",
        "firewall", "fw", "router", "ntp", "time",
        # data stores
        "db", "db1", "db2", "database", "sql", "sql1", "mysql", "mysql1",
        "postgres", "postgresql", "mongo", "mongodb", "redis", "elastic",
        "elasticsearch", "memcached", "cache", "oracle", "mssql",
        # compute / nodes
        "node", "node1", "node2", "server", "server1", "server2", "srv",
        "host", "host1", "host2", "vm", "vps",
        # source control / ci
        "git", "gitlab", "github", "bitbucket", "svn", "repo", "repository",
        "ci", "cd", "jenkins", "build", "deploy", "argo", "argocd", "drone",
        # containers / orchestration
        "docker", "registry", "k8s", "kubernetes", "kube", "openshift",
        "rancher", "harbor",
        # observability
        "monitor", "monitoring", "grafana", "prometheus", "kibana", "log",
        "logs", "logging", "splunk", "status", "health", "metrics", "trace",
        "observability", "alertmanager",
        # collaboration / support
        "jira", "confluence", "wiki", "docs", "doc", "documentation", "kb",
        "help", "helpdesk", "support", "ticket", "tickets", "chat", "slack",
        "teams", "meet",
        # identity
        "auth", "sso", "login", "oauth", "saml", "identity", "idp", "ldap",
        "ad", "dc", "dc1", "dc2", "secure", "ssl", "cert", "certs",
        # corporate / internal
        "internal", "intranet", "extranet", "private", "corp", "corporate",
        "office", "lync", "sip", "hr", "crm", "erp", "sap", "invoicing",
        # partners / customers
        "partner", "partners", "client", "clients", "customer", "customers",
        "b2b", "affiliate",
        # data / analytics
        "search", "solr", "sitemap", "data", "bigdata", "ai", "ml",
        "analytics", "bi", "report", "reports", "reporting", "warehouse",
        # misc legacy / ops
        "backup", "backups", "bak", "old", "new", "tmp", "temp", "archive",
        "archives", "voip", "phone", "pbx", "asterisk", "freepbx", "ups",
        "xmail", "landing", "home", "shopapi", "devportal", "developers",
        "statuspage", "wiki1", "crm1", "erp1",
    ]

    def __init__(
        self,
        http_timeout: float = SOURCE_TIMEOUT,
        dns_timeout: float = DNS_TIMEOUT,
        concurrency: int = DNS_CONCURRENCY,
        vt_api_key: str | None = None,
    ):
        self.http_timeout = http_timeout
        self.dns_timeout = dns_timeout
        self.concurrency = max(1, concurrency)
        self.vt_api_key = (
            vt_api_key
            or os.environ.get("VT_API_KEY")
            or os.environ.get("VIRUSTOTAL_API_KEY")
            or ""
        ).strip()

    # ------------------------------------------------------------------ #
    # Main entry point
    # ------------------------------------------------------------------ #
    async def scan(self, target: str) -> list[Finding]:
        """Enumerate subdomains of ``target`` (a domain like ``example.com``)."""
        domain = self._normalize_domain(target)
        if not domain:
            return []
        # Subdomain enumeration does not apply to bare IP addresses.
        if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", domain):
            return []

        source_names = ("crt.sh", "HackerTarget", "VirusTotal", "DNS brute force")
        results = await asyncio.gather(
            self._crtsh(domain),
            self._hackertarget(domain),
            self._virustotal(domain),
            self._brute_force(domain),
            return_exceptions=True,
        )

        # Merge candidates while remembering which source found them.
        candidates: dict[str, set[str]] = {}
        for source, result in zip(source_names, results):
            if isinstance(result, BaseException) or not result:
                continue
            for subdomain in result:
                if self._is_subdomain(subdomain, domain):
                    candidates.setdefault(subdomain, set()).add(source)

        if not candidates:
            return []

        verified = await self._verify(candidates.keys())

        findings: list[Finding] = []
        for subdomain in sorted(verified):
            sources = sorted(candidates.get(subdomain, set()))
            findings.append(
                Finding(
                    title=f"Subdomain discovered: {subdomain}",
                    severity=Severity.INFO,
                    target=subdomain,
                    evidence=(
                        "DNS resolution confirmed. Discovered via: "
                        f"{', '.join(sources) if sources else 'unknown'}."
                    ),
                    scanner=self.name,
                    metadata={"domain": domain, "sources": sources},
                )
            )
        return findings

    # ------------------------------------------------------------------ #
    # Passive sources
    # ------------------------------------------------------------------ #
    async def _crtsh(self, domain: str) -> set[str]:
        """Query crt.sh certificate transparency logs."""
        url = self.CRTSH_URL.format(domain=domain)
        try:
            async with httpx.AsyncClient(
                timeout=self.http_timeout,
                headers={"User-Agent": self.USER_AGENT},
                follow_redirects=True,
            ) as client:
                response = await client.get(url)
                response.raise_for_status()
                rows = response.json()
        except (httpx.HTTPError, ValueError):
            return set()

        found: set[str] = set()
        if not isinstance(rows, list):
            return found
        for row in rows:
            if not isinstance(row, dict):
                continue
            name_value = row.get("name_value") or ""
            for raw_name in str(name_value).splitlines():
                name = raw_name.strip().lower().rstrip(".")
                if name.startswith("*."):
                    # Wildcard certificate -> only yields the apex domain,
                    # which is filtered out by ``_is_subdomain``.
                    name = name[2:]
                if self._is_subdomain(name, domain):
                    found.add(name)
        return found

    async def _hackertarget(self, domain: str) -> set[str]:
        """Query the HackerTarget hostsearch API (free tier)."""
        url = self.HACKERTARGET_URL.format(domain=domain)
        try:
            async with httpx.AsyncClient(
                timeout=self.http_timeout,
                headers={"User-Agent": self.USER_AGENT},
                follow_redirects=True,
            ) as client:
                response = await client.get(url)
                if response.status_code != 200:
                    return set()
                text = response.text
        except httpx.HTTPError:
            return set()

        found: set[str] = set()
        for line in text.splitlines():
            line = line.strip()
            if not line or "," not in line:
                # API errors look like "error check your api key" / "no records".
                continue
            host = line.split(",", 1)[0].strip().lower().rstrip(".")
            if self._is_subdomain(host, domain):
                found.add(host)
        return found

    async def _virustotal(self, domain: str) -> set[str]:
        """Query VirusTotal v3 for known subdomains.

        Silently returns an empty set when no API key is configured or when
        the API rejects the request (rate limit, bad key, ...).
        """
        if not self.vt_api_key:
            return set()

        headers = {
            "x-apikey": self.vt_api_key,
            "Accept": "application/json",
            "User-Agent": self.USER_AGENT,
        }
        found: set[str] = set()
        url: str | None = self.VIRUSTOTAL_URL.format(domain=domain)
        params: dict | None = {"limit": 40}
        pages = 0

        try:
            async with httpx.AsyncClient(
                timeout=self.http_timeout, headers=headers, follow_redirects=True
            ) as client:
                while url and pages < self.VIRUSTOTAL_PAGE_LIMIT:
                    response = await client.get(url, params=params)
                    if response.status_code in (401, 403, 429):
                        break  # bad key or rate limited -> give up quietly
                    response.raise_for_status()
                    payload = response.json()
                    data = payload.get("data") or []
                    if not isinstance(data, list):
                        break
                    for item in data:
                        if not isinstance(item, dict):
                            continue
                        name = str(item.get("id", "")).strip().lower().rstrip(".")
                        if self._is_subdomain(name, domain):
                            found.add(name)
                    url = (payload.get("links") or {}).get("next") or None
                    params = None
                    pages += 1
        except (httpx.HTTPError, ValueError, TypeError, KeyError):
            return found
        return found

    # ------------------------------------------------------------------ #
    # Active sources / verification
    # ------------------------------------------------------------------ #
    async def _brute_force(self, domain: str) -> set[str]:
        """Generate candidate subdomains from the built-in wordlist."""
        return {
            f"{word}.{domain}"
            for word in dict.fromkeys(
                w.strip().lower() for w in self.WORDLIST if w and w.strip()
            )
        }

    async def _verify(self, candidates) -> set[str]:
        """Keep only candidates that resolve to at least one A/AAAA record."""
        semaphore = asyncio.Semaphore(self.concurrency)

        async def check(name: str) -> str | None:
            async with semaphore:
                return name if await self._resolve(name) else None

        results = await asyncio.gather(
            *(check(name) for name in candidates), return_exceptions=True
        )
        return {r for r in results if isinstance(r, str)}

    async def _resolve(self, hostname: str) -> bool:
        """Return True when ``hostname`` has a resolvable A/AAAA record."""
        try:
            return await asyncio.wait_for(
                asyncio.to_thread(self._resolve_sync, hostname),
                timeout=self.dns_timeout + 1.0,
            )
        except Exception:
            # Timeouts, DNS errors and thread failures all mean "not resolvable".
            return False

    def _resolve_sync(self, hostname: str) -> bool:
        """Blocking dnspython resolution (executed in a worker thread)."""
        resolver = dns.resolver.Resolver(configure=True)
        resolver.lifetime = self.dns_timeout
        resolver.timeout = self.dns_timeout
        for rdtype in ("A", "AAAA"):
            try:
                answer = resolver.resolve(
                    hostname, rdtype, raise_on_no_answer=False
                )
                if answer.rrset is not None and len(answer) > 0:
                    return True
            except (dns.exception.DNSException, OSError):
                continue
        return False

    # ------------------------------------------------------------------ #
    # Helpers
    # ------------------------------------------------------------------ #
    @staticmethod
    def _is_subdomain(candidate: str, domain: str) -> bool:
        """True when ``candidate`` is a strict subdomain of ``domain``."""
        if not candidate or "*" in candidate or " " in candidate or ".." in candidate:
            return False
        return candidate != domain and candidate.endswith("." + domain)

    @staticmethod
    def _normalize_domain(target: str) -> str:
        """Strip scheme, path, credentials and port from a user supplied target."""
        value = target.strip().lower()
        value = re.sub(r"^[a-z][a-z0-9+.\-]*://", "", value)
        value = value.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
        if "@" in value:
            value = value.rsplit("@", 1)[-1]
        if value.count(":") == 1:
            host, _, port = value.partition(":")
            if port.isdigit():
                value = host
        value = value.strip().strip(".")
        if not value or "." not in value:
            return ""
        if not re.fullmatch(r"[a-z0-9.\-]+", value):
            return ""
        return value
