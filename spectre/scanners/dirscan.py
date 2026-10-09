"""Directory and endpoint discovery scanner: brute-forces common web paths."""

from __future__ import annotations

import asyncio
import uuid
from pathlib import Path
from urllib.parse import urljoin, urlparse

import httpx

from .base import BaseScanner
from ..models import Finding, Severity

USER_AGENT = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
TIMEOUT = httpx.Timeout(4.0, connect=3.0)   # Keeps the sweep inside the 30s engine budget
INTERESTING = {200, 201, 204, 301, 302, 401, 403, 500}
HTML_MIN_BYTES = 100          # Smaller 200s on directory paths are junk
MAX_FINDINGS = 200            # Cap output so one run cannot flood the report


class DirScanner(BaseScanner):
    """Discover reachable directories, files and endpoints on a web server."""

    name = "dirscan"
    description = "Directory and endpoint discovery"
    version = "1.0.0"

    # Built-in wordlist (~150 common paths, stored without a leading slash).
    WORDLIST: list[str] = [
        # admin / auth surfaces
        "admin", "administrator", "login", "signin", "signup", "register", "logout", "dashboard",
        "console", "panel", "manage", "manager/html", "backend", "user", "users", "account",
        "accounts", "profile", "settings", "auth",
        # WordPress / CMS
        "wp-admin", "wp-login.php", "wp-signup.php", "wp-content", "wp-includes", "wp-json", "xmlrpc.php",
        # api / documentation / interactive consoles
        "api", "api/v1", "api/v2", "api/v3", "api/docs", "swagger", "swagger-ui", "swagger.json",
        "openapi.json", "graphql", "graphiql", "playground", "redoc", "docs", "documentation",
        "actuator", "actuator/health", "actuator/env", "actuator/metrics", "metrics", "health",
        "status", "info", "version", "prometheus", "grafana", "kibana", "solr", "jmx-console",
        "host-manager", "server-status", "server-info",
        # backups / configuration / source metadata
        "backup", "backups", "backup.sql", "dump.sql", "database.sql", "db.sql", "dump", "export",
        "old", "tmp", "temp", "test", "config", "config.json", "config.yml", "config.php",
        "settings.php", "application.yml", "application.properties", "web.config", "crossdomain.xml",
        "composer.json", "composer.lock", "package.json", "package-lock.json", "yarn.lock",
        "README.md", "LICENSE", "CHANGELOG.md", ".env", ".env.local", ".env.production", ".env.bak",
        "env", ".git/HEAD", ".git/config", ".gitignore", ".hg", ".svn/entries", ".svn/wc.db",
        ".DS_Store", ".htaccess", ".htpasswd", ".ssh/id_rsa", "id_rsa", ".aws/credentials",
        ".idea/workspace.xml", ".vscode/settings.json",
        # content / static assets
        "robots.txt", "sitemap.xml", "favicon.ico", "security.txt", ".well-known/security.txt",
        "upload", "uploads", "files", "file", "static", "assets", "js", "css", "images", "img",
        "media", "fonts", "download", "downloads", "public", "private", "data", "src", "source",
        "db", "sql",
        # tooling / admin apps / mail
        "phpinfo.php", "phpmyadmin", "phpmyadmin/index.php", "adminer.php", "adminer", "elmah.axd",
        "trace.axd", "debug", "trace", "shell", "cgi-bin", "vendor", "node_modules", "jenkins",
        "git", "mail", "webmail", "roundcube", "squirrelmail", "imp", "redis", "test.php",
    ]

    # Path (no leading slash) -> severity when it returns 200/201/204.
    SENSITIVE_PATHS: dict[str, Severity] = {
        # Credential / key material: immediate compromise risk
        ".env": Severity.CRITICAL, ".env.local": Severity.CRITICAL, ".env.production": Severity.CRITICAL,
        ".env.bak": Severity.CRITICAL, ".git/HEAD": Severity.CRITICAL, ".git/config": Severity.CRITICAL,
        ".htpasswd": Severity.CRITICAL, "id_rsa": Severity.CRITICAL, ".ssh/id_rsa": Severity.CRITICAL,
        ".aws/credentials": Severity.CRITICAL,
        # Database dumps, config and debug endpoints
        "backup.sql": Severity.HIGH, "dump.sql": Severity.HIGH, "database.sql": Severity.HIGH,
        "db.sql": Severity.HIGH, "backup": Severity.HIGH, "backups": Severity.HIGH,
        "config": Severity.HIGH, "config.php": Severity.HIGH, "config.yml": Severity.HIGH,
        "settings.php": Severity.HIGH, "application.yml": Severity.HIGH,
        "application.properties": Severity.HIGH, "web.config": Severity.HIGH,
        "phpinfo.php": Severity.HIGH, "phpmyadmin": Severity.HIGH, "phpmyadmin/index.php": Severity.HIGH,
        "adminer.php": Severity.HIGH, "adminer": Severity.HIGH, "server-status": Severity.HIGH,
        "server-info": Severity.HIGH, "actuator": Severity.HIGH, "actuator/env": Severity.HIGH,
        "jmx-console": Severity.HIGH, "manager/html": Severity.HIGH, "host-manager": Severity.HIGH,
        "elmah.axd": Severity.HIGH, "trace.axd": Severity.HIGH, "shell": Severity.HIGH,
        ".svn/entries": Severity.HIGH, ".svn/wc.db": Severity.HIGH, "env": Severity.HIGH,
        ".htaccess": Severity.MEDIUM, ".DS_Store": Severity.MEDIUM,
        # Exposed interactive consoles / debug surfaces (spec -> MEDIUM)
        "swagger": Severity.MEDIUM, "swagger-ui": Severity.MEDIUM, "api/docs": Severity.MEDIUM,
        "graphql": Severity.MEDIUM, "graphiql": Severity.MEDIUM, "playground": Severity.MEDIUM,
        "redoc": Severity.MEDIUM, "console": Severity.MEDIUM, "actuator/health": Severity.MEDIUM,
        "actuator/metrics": Severity.MEDIUM, "debug": Severity.MEDIUM, "trace": Severity.MEDIUM,
        "metrics": Severity.MEDIUM, "solr": Severity.MEDIUM, "kibana": Severity.MEDIUM,
        "grafana": Severity.MEDIUM, "prometheus": Severity.MEDIUM, "webmail": Severity.MEDIUM,
        "roundcube": Severity.MEDIUM,
    }

    #: 200 on these is expected housekeeping (INFO); LOW_PATHS leaks only metadata.
    NORMAL_PATHS = {"robots.txt", "sitemap.xml", "favicon.ico", "security.txt", ".well-known/security.txt", "crossdomain.xml"}
    LOW_PATHS = {"README.md", "LICENSE", "CHANGELOG.md", "composer.json", "composer.lock", "package.json",
                 "package-lock.json", "yarn.lock", ".gitignore", ".hg"}
    FILE_NAMES = {"head", "id_rsa", "env"}   # Extensionless names that are still files
    ADMIN_MARKERS = ("admin", "login", "signin", "dashboard", "manager", "panel", "backend", "manage",
                     "console", "phpmyadmin", "adminer", "wp-login", "wp-admin", "auth")
    INTERACTIVE_MARKERS = ("swagger", "graphql", "graphiql", "playground", "redoc", "api/docs", "console")
    REMEDIATIONS: dict[Severity, str] = {
        Severity.CRITICAL: ("Remove the exposed file from the web root immediately, rotate every credential it "
                            "contains, and deny access to VCS/metadata directories at the web server."),
        Severity.HIGH: ("Block this path with a web-server deny rule and move backups, configuration and debug "
                        "endpoints outside the document root."),
        Severity.MEDIUM: ("Restrict this endpoint to authenticated admin networks and disable interactive "
                          "consoles/debug tooling in production."),
        Severity.LOW: "Limit exposure of this resource to trusted networks and confirm it must be publicly reachable.",
        Severity.INFO: "Expected content; keep the file current and ensure it does not reference internal or sensitive resources.",
    }

    def __init__(self, wordlist: list[str] | None = None, concurrency: int = 30, wordlist_file: str | None = None):
        if wordlist_file:  # Optional external wordlist (one path per line)
            lines = Path(wordlist_file).read_text(encoding="utf-8", errors="replace").splitlines()
            self.wordlist = [w.strip().lstrip("/") for w in lines
                             if w.strip() and not w.strip().startswith("#")]
        elif wordlist is not None:
            self.wordlist = list(wordlist)
        else:
            self.wordlist = list(self.WORDLIST)
        self.concurrency = max(1, concurrency)

    # -------------------------------------------------------------- scanning
    async def scan(self, target: str) -> list[Finding]:
        """Probe every wordlist path under ``target`` and report what exists."""
        base = self._base_url(target)
        if not base:
            return []
        semaphore = asyncio.Semaphore(self.concurrency)
        headers = {"User-Agent": USER_AGENT, "Accept": "*/*"}

        async with httpx.AsyncClient(timeout=TIMEOUT, follow_redirects=False,
                                     verify=False, headers=headers) as client:
            # Random-path baseline used to recognise soft-404 catch-alls.
            baseline = await self._baseline(client, base)
            results = await asyncio.gather(
                *(self._probe(client, semaphore, base, path) for path in self.wordlist),
                return_exceptions=True)

        findings = [f for path, resp in (r for r in results if isinstance(r, tuple))
                    if resp is not None and (f := self._evaluate(base, path, resp, baseline))]
        return findings[:MAX_FINDINGS]

    async def _probe(self, client: httpx.AsyncClient, semaphore: asyncio.Semaphore, base: str, path: str) -> tuple[str, httpx.Response | None]:
        """GET one candidate path; transport errors yield (path, None)."""
        url = urljoin(f"{base}/", path.lstrip("/"))
        try:
            async with semaphore:
                resp = await client.get(url)
        except (httpx.HTTPError, OSError, ValueError):
            return path, None
        return path, resp

    async def _baseline(self, client: httpx.AsyncClient, base: str) -> tuple[int, int, str] | None:
        """Fetch a nonexistent path to learn the site's catch-all response."""
        junk = urljoin(f"{base}/", f"spectre-no-such-path-{uuid.uuid4().hex[:10]}")
        try:
            resp = await client.get(junk)
            return resp.status_code, len(resp.content), resp.headers.get("location", "")
        except (httpx.HTTPError, OSError, ValueError):
            return None

    # --------------------------------------------------------------- scoring
    def _evaluate(self, base: str, path: str, resp: httpx.Response,
                  baseline: tuple[int, int, str] | None) -> Finding | None:
        """Turn one response into a Finding, or None when it is not interesting."""
        status = resp.status_code
        if status not in INTERESTING:
            return None
        try:
            length = len(resp.content)
        except Exception:
            length = 0
        server = (resp.headers.get("server") or "").strip()
        location = (resp.headers.get("location") or "").strip()
        path = path.lstrip("/")

        if self._is_soft_404(status, length, location, baseline):
            return None
        # Tiny bodies on directory (HTML) paths are generic stubs, not content.
        if status in (200, 201, 204) and not self._is_file(path) and length < HTML_MIN_BYTES:
            return None

        evidence = f"HTTP {status}, {length} bytes"
        if server:
            evidence += f", Server: {server}"
        if location:
            evidence += f", Location: {location}"
        severity = self._severity(path, status)
        return Finding(
            title=self._title(path, status, location),
            severity=severity,
            target=f"{base}/{path}",
            evidence=evidence,
            remediation=self.REMEDIATIONS[severity],
            scanner=self.name,
            metadata={"type": "path", "path": "/" + path, "status": status,
                      "length": length, "server": server, "location": location},
        )

    @staticmethod
    def _is_soft_404(status: int, length: int, location: str, baseline: tuple[int, int, str] | None) -> bool:
        """True when the response matches the random-path catch-all (soft 404)."""
        if baseline is None:
            return False
        base_status, base_length, base_location = baseline
        if status != base_status or base_status not in INTERESTING:
            return False
        if status in (301, 302):  # Catch-all redirect: same destination
            return bool(base_location) and location == base_location
        if status in (200, 201, 204):
            return abs(length - base_length) <= max(HTML_MIN_BYTES, int(0.05 * base_length))
        # Catch-all 401/403/500: identical body for every unknown path
        return abs(length - base_length) <= max(HTML_MIN_BYTES, int(0.10 * base_length))

    @classmethod
    def _severity(cls, path: str, status: int) -> Severity:
        sensitive = cls.SENSITIVE_PATHS.get(path.lstrip("/"))
        if sensitive is None and path.startswith("actuator/"):
            sensitive = Severity.HIGH  # Any other actuator endpoint leaks config
        if status == 500:
            return Severity.LOW                    # Error/stack trace leak
        if status in (301, 302):
            return Severity.INFO                   # Redirect target recorded
        if status == 403:
            return Severity.MEDIUM if sensitive else Severity.LOW  # Exists but blocked
        if status == 401:
            if any(marker in path for marker in cls.ADMIN_MARKERS):
                return Severity.INFO               # Admin surface present, gated
            return Severity.MEDIUM if sensitive else Severity.LOW
        if sensitive:                              # 200/201/204 on sensitive path
            return sensitive
        if any(marker in path for marker in cls.INTERACTIVE_MARKERS):
            return Severity.MEDIUM                 # Exposed API docs / console
        if any(marker in path for marker in cls.ADMIN_MARKERS):
            return Severity.MEDIUM                 # Exposed admin panel
        if path.lstrip("/") in cls.NORMAL_PATHS:
            return Severity.INFO                   # robots.txt / sitemap.xml / favicon
        if path.lstrip("/") in cls.LOW_PATHS:
            return Severity.LOW
        return Severity.INFO                       # Plain directory/file discovery

    @classmethod
    def _title(cls, path: str, status: int, location: str) -> str:
        shown = "/" + path
        if status in (301, 302):
            return f"Redirect found: {shown} -> {location or '(unknown)'}"
        if status == 500:
            return f"Server error (possible info leak): {shown}"
        if status == 403:
            return f"Access denied but path exists: {shown}"
        if status == 401:
            return f"Authentication required: {shown}"
        if status in (201, 204):
            return f"Endpoint found: {shown}"
        if path in cls.SENSITIVE_PATHS or path.startswith("actuator/"):
            kind = "file" if cls._is_file(path) else "directory"
            return f"Sensitive {kind} exposed: {shown}"
        if cls._is_file(path):
            return f"File found: {shown}"
        return f"Directory found: {shown}"

    @classmethod
    def _is_file(cls, path: str) -> bool:
        """Heuristic: last segment has an extension, or is a known file name."""
        last = path.rstrip("/").rsplit("/", 1)[-1]
        return "." in last or last.lower() in cls.FILE_NAMES

    @staticmethod
    def _base_url(target: str) -> str:
        """Normalise the target into a scheme://host[/dir] base without a slash."""
        target = (target or "").strip()
        if not target:
            return ""
        if "://" not in target:
            target = "https://" + target
        parsed = urlparse(target)
        if not parsed.hostname:
            return ""
        return f"{parsed.scheme}://{parsed.netloc}{parsed.path or '/'}".rstrip("/")
