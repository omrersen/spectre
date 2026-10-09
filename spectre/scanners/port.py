"""Port scanner with asynchronous service and version detection.

The scan is performed in three phases:

1. **Connect sweep** - every port in ``COMMON_PORTS`` (the full privileged
   range 1-1023 plus ~100 common registered/high ports, i.e. a superset of
   the classic "top 1000" set) is probed concurrently with a bounded
   semaphore and a short connect timeout.
2. **Service detection** - open ports are fingerprinted using a raw banner
   read, protocol specific probes (Redis ``INFO``, Memcached ``STATS``) and
   HTTP(S) requests that parse ``Server`` headers, JSON version fields and
   HTML titles.
3. **Reporting** - one Finding per open port with a severity derived from
   how dangerous the service is when exposed.
"""

from __future__ import annotations

import asyncio
import re
from typing import Any

import httpx

from ..models import Finding, Severity
from .base import BaseScanner


class PortScanner(BaseScanner):
    """Scan the most common TCP ports and fingerprint running services."""

    name = "port"
    description = "Port scanner with service detection"
    version = "1.0.0"

    USER_AGENT = "Spectre/1.0.0 (security scanner)"

    # ------------------------------------------------------------------ #
    # Port -> default service name map (used when fingerprinting fails)
    # ------------------------------------------------------------------ #
    SERVICES: dict[int, str] = {
        # --- privileged / well-known ---
        1: "tcpmux", 4: "echo", 7: "echo", 9: "discard", 11: "systat",
        13: "daytime", 15: "netstat", 17: "qotd", 19: "chargen",
        20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
        37: "time", 42: "nameserver", 43: "whois", 49: "tacacs", 53: "domain",
        67: "dhcps", 68: "dhcpc", 69: "tftp", 70: "gopher", 79: "finger",
        80: "http", 81: "hosts2-ns", 82: "xfer", 85: "mit-ml-dev",
        88: "kerberos", 89: "su-mit-tg", 90: "dnsix", 91: "mit-dov", 92: "npp",
        93: "dcp", 95: "supdup", 97: "swift-rvf", 98: "linuxconf",
        99: "metagram", 101: "hostname", 102: "iso-tsap", 103: "x400",
        104: "dicom", 106: "pop3pw", 107: "rtelnet", 108: "sna-gw",
        109: "pop2", 110: "pop3", 111: "sunrpc", 113: "ident", 119: "nntp",
        123: "ntp", 135: "msrpc", 137: "netbios-ns", 138: "netbios-dgm",
        139: "netbios-ssn", 143: "imap", 161: "snmp", 179: "bgp", 194: "irc",
        389: "ldap", 427: "svrloc", 443: "https", 445: "microsoft-ds",
        465: "smtps", 500: "isakmp", 512: "rexec", 513: "rlogin", 514: "rsh",
        515: "lpd", 526: "tempo", 530: "courier", 543: "klogin", 544: "kshell",
        548: "afp", 554: "rtsp", 563: "nntps", 587: "submission",
        591: "filemaker", 593: "msrpc-http", 631: "ipp", 636: "ldaps",
        646: "ldp", 873: "rsync", 989: "ftps-data", 990: "ftps",
        993: "imaps", 995: "pop3s",
        # --- common registered ports ---
        1080: "socks", 1099: "rmiregistry", 1194: "openvpn",
        1433: "ms-sql-s", 1434: "ms-sql-m", 1521: "oracle", 1720: "h323",
        1723: "pptp", 1755: "mms", 1883: "mqtt", 1900: "ssdp", 2000: "skinny",
        2049: "nfs", 2082: "cpanel", 2083: "cpanel-ssl", 2086: "whm",
        2087: "whm-ssl", 2095: "webmail", 2096: "webmail-ssl",
        2121: "ccproxy", 2181: "zookeeper", 2222: "ipmi-alt",
        2375: "docker", 2376: "docker-tls", 2379: "etcd", 2380: "etcd-peer",
        2483: "oracle-tns", 2484: "oracle-tns-ssl", 3000: "dev-http",
        3128: "squid-http", 3268: "gcldap", 3269: "gcldaps", 3306: "mysql",
        3389: "ms-wbt-server", 3493: "nut", 3690: "svn", 4190: "managesieve",
        4369: "epmd", 4443: "https-alt", 4899: "radmin", 5000: "http-alt",
        5060: "sip", 5061: "sips", 5190: "aim", 5222: "xmpp-client",
        5269: "xmpp-server", 5357: "wsdapi", 5432: "postgresql",
        5631: "pcanywhere", 5800: "vnc-http", 5900: "vnc", 5901: "vnc-1",
        5984: "couchdb", 5985: "winrm", 5986: "winrm-ssl", 6000: "x11",
        6379: "redis", 6443: "k8s-apiserver", 6666: "irc", 6667: "irc",
        7001: "http-alt", 7443: "https-alt", 7777: "http-alt",
        8000: "http-alt", 8008: "http", 8009: "ajp13", 8080: "http-proxy",
        8081: "http-alt", 8088: "http-alt", 8090: "http-alt",
        8180: "http-alt", 8443: "https-alt", 8500: "consul", 8888: "http-alt",
        9000: "http-alt", 9001: "http-alt", 9090: "http-alt",
        9092: "kafka", 9100: "jetdirect", 9200: "elasticsearch",
        9300: "elasticsearch-transport", 9418: "git", 9999: "http-alt",
        10000: "webmin", 10250: "kubelet", 10255: "kubelet-read-only",
        10443: "https-alt", 11211: "memcached", 15672: "rabbitmq-mgmt",
        16379: "redis", 27017: "mongodb", 27018: "mongodb", 28017: "mongodb-http",
        31337: "backorifice", 50000: "db2",
    }

    # Ports probed with an HTTP(S) request before anything else (they are
    # silent on connect). TLS ports get the HTTPS probe first.
    HTTP_PORTS: set[int] = {
        80, 81, 3000, 5000, 5985, 5986, 8000, 8008, 8080, 8081, 8088, 8090,
        8180, 8443, 8500, 8888, 9000, 9001, 9090, 9200, 9999, 10000, 15672,
        10443, 443, 465, 636, 989, 990, 993, 995, 2083, 2087, 2096, 2376,
        4443, 5061, 5984, 6443, 7443,
    }

    # Ports wrapped with TLS before probing.
    TLS_PORTS: set[int] = {
        443, 465, 636, 989, 990, 993, 995, 2083, 2087, 2096, 2376, 4443,
        5061, 5986, 6443, 7443, 8443, 9443, 10443,
    }

    # Request paths that reveal product/version information.
    HTTP_PATHS: dict[int, str] = {
        2375: "/version",
        2376: "/version",
        6443: "/version",
        8500: "/v1/status/leader",
        9200: "/",
        5984: "/",
    }

    # Payloads sent to otherwise silent services.
    RAW_PROBES: dict[int, bytes] = {
        6379: b"INFO server\r\n",
        6380: b"INFO server\r\n",
        16379: b"INFO server\r\n",
        11211: b"stats\r\n",
    }

    # Ports probed even though they have no well-known service name.
    EXTRA_SCAN_PORTS: set[int] = {
        4444, 5555, 6001, 6002, 7778, 8082, 8083, 12345, 65535,
    }

    # ------------------------------------------------------------------ #
    # Severity guidance per port class
    # ------------------------------------------------------------------ #
    CRITICAL_PORTS: set[int] = {
        2375, 6379, 6380, 9200, 11211, 16379, 27017, 27018, 28017,
    }
    HIGH_PORTS: set[int] = {
        23, 69, 79, 111, 135, 139, 445, 512, 513, 514, 1433, 1521, 2049,
        2181, 2376, 3306, 3389, 3690, 4899, 5432, 5631, 5800, 5900, 5901,
        5985, 5986, 6443, 8500, 9092, 9300, 10000, 10250, 10255, 15672,
        31337,
    }
    MEDIUM_PORTS: set[int] = {
        21, 110, 119, 143, 389, 631, 873, 1080, 1900, 3128, 5060, 5601,
        6666, 6667, 7777, 9100, 12345,
    }
    INFO_PORTS: set[int] = {80, 443, 3000, 5000, 8000, 8080, 8443}

    # ------------------------------------------------------------------ #
    # Scan target list: every privileged port + common registered ports.
    # ------------------------------------------------------------------ #
    COMMON_PORTS: list[int] = list(range(1, 1024)) + sorted(
        {port for port in SERVICES if port >= 1024} | EXTRA_SCAN_PORTS
    )

    def __init__(
        self,
        timeout: float = 1.0,
        banner_timeout: float = 0.6,
        http_timeout: float = 2.0,
        concurrency: int = 100,
        ports: list[int] | None = None,
    ):
        self.timeout = timeout
        self.banner_timeout = banner_timeout
        self.http_timeout = http_timeout
        self.concurrency = max(1, concurrency)
        self.ports = list(ports) if ports else list(self.COMMON_PORTS)

    # ------------------------------------------------------------------ #
    # Main entry point
    # ------------------------------------------------------------------ #
    async def scan(self, target: str) -> list[Finding]:
        """Scan ``target`` (host or URL) and return a Finding per open port."""
        host = self._normalize_host(target)
        if not host:
            return []

        open_ports = await self._scan_ports(host, self.ports)
        if not open_ports:
            return []

        semaphore = asyncio.Semaphore(min(self.concurrency, 50))

        async def detect(port: int) -> dict[str, Any]:
            async with semaphore:
                return await self._detect_service(host, port)

        detections = await asyncio.gather(
            *(detect(port) for port in open_ports), return_exceptions=True
        )

        findings: list[Finding] = []
        for port, info in zip(open_ports, detections):
            if isinstance(info, BaseException) or not isinstance(info, dict):
                info = {
                    "service": self.SERVICES.get(port, "unknown"),
                    "version": "",
                    "evidence": "",
                    "method": "connect",
                }

            service = info.get("service") or self.SERVICES.get(port) or "unknown"
            version = str(info.get("version") or "")
            severity = self._severity_for(port, service)

            title = f"Open port {port}/tcp ({service})"
            if version:
                title += f" {version}"

            evidence = info.get("evidence") or (
                f"TCP connect to {host}:{port} succeeded (no service fingerprint)."
            )

            findings.append(
                Finding(
                    title=title,
                    severity=severity,
                    target=f"{host}:{port}",
                    evidence=str(evidence),
                    remediation=self._remediation_for(severity, service, port),
                    scanner=self.name,
                    metadata={
                        "host": host,
                        "port": port,
                        "protocol": "tcp",
                        "service": service,
                        "version": version,
                        "detection": info.get("method", "connect"),
                    },
                )
            )
        return findings

    # ------------------------------------------------------------------ #
    # Phase 1: connect sweep
    # ------------------------------------------------------------------ #
    async def _scan_ports(self, host: str, ports: list[int]) -> list[int]:
        """Probe every port concurrently and return the open ones (sorted)."""
        semaphore = asyncio.Semaphore(self.concurrency)

        async def check(port: int) -> int | None:
            async with semaphore:
                return port if await self._is_open(host, port) else None

        results = await asyncio.gather(
            *(check(port) for port in ports), return_exceptions=True
        )
        return sorted({r for r in results if isinstance(r, int)})

    async def _is_open(self, host: str, port: int) -> bool:
        """Attempt a TCP handshake; treat anything but success as closed."""
        try:
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=self.timeout
            )
        except Exception:
            return False
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass
        return True

    # ------------------------------------------------------------------ #
    # Phase 2: service / version detection
    # ------------------------------------------------------------------ #
    async def _detect_service(self, host: str, port: int) -> dict[str, Any]:
        """Fingerprint the service listening on ``host:port``."""
        known = self.SERVICES.get(port)
        tls = port in self.TLS_PORTS
        banner: str | None = None
        http_info: dict[str, Any] | None = None

        if port in self.HTTP_PORTS:
            # Web-ish ports are silent on connect: ask HTTP(S) directly.
            http_info = await self._http_probe(host, port, tls=tls)
            if http_info is None and not tls:
                http_info = await self._http_probe(host, port, tls=True)
            if http_info is None and tls:
                # Non-HTTP TLS service (IMAPS/SMTPS/LDAPS...): grab its banner.
                banner = await self._read_banner(host, port, tls=True)
        else:
            banner = await self._read_banner(host, port, tls=tls)
            if banner is None and port in self.RAW_PROBES:
                banner = await self._read_banner(
                    host, port, tls=False, probe=self.RAW_PROBES[port]
                )
            if banner is None:
                http_info = await self._http_probe(host, port, tls=False)

        service = known or "unknown"
        version = ""
        evidence = ""
        method = "connect"

        if http_info is not None:
            method = "http-probe"
            service = known or ("https" if tls else "http")
            version = str(http_info.get("version") or "")
            evidence = str(http_info.get("evidence") or "")
        elif banner:
            method = "raw-probe"
            service, version = self._classify_banner(banner, known)
            evidence = banner

        if not evidence:
            evidence = (
                f"TCP connect to {host}:{port} succeeded"
                + (f" ({service} port)" if known else " (no service fingerprint)")
                + "."
            )

        return {
            "service": service,
            "version": version,
            "evidence": evidence[:512],
            "method": method,
        }

    async def _read_banner(
        self, host: str, port: int, tls: bool = False, probe: bytes | None = None
    ) -> str | None:
        """Connect, optionally send ``probe``, and read the server banner."""
        context = self._ssl_context() if tls else None
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(
                    host,
                    port,
                    ssl=context,
                    server_hostname=host if tls else None,
                ),
                timeout=self.timeout,
            )
        except Exception:
            return None

        try:
            if probe:
                writer.write(probe)
                await writer.drain()
            try:
                data = await asyncio.wait_for(
                    reader.read(2048), timeout=self.banner_timeout
                )
            except Exception:
                data = b""
            if not data:
                return None
            return self._clean(data)
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    async def _http_probe(
        self, host: str, port: int, tls: bool = False, path: str | None = None
    ) -> dict[str, Any] | None:
        """Send an HTTP(S) request and extract status, Server header and version."""
        request_path = path or self.HTTP_PATHS.get(port, "/")
        scheme = "https" if tls else "http"
        url = f"{scheme}://{host}:{port}{request_path}"
        timeout = httpx.Timeout(self.http_timeout, connect=min(self.http_timeout, 1.5))

        try:
            async with httpx.AsyncClient(
                verify=False,
                follow_redirects=True,
                timeout=timeout,
                headers={"User-Agent": self.USER_AGENT},
            ) as client:
                response = await client.get(url)
        except Exception:
            return None

        server = (response.headers.get("server") or "").strip()
        content_type = (response.headers.get("content-type") or "").lower()
        body = ""
        try:
            if any(t in content_type for t in ("html", "json", "xml", "text")) or not content_type:
                body = response.text[:4096]
        except Exception:
            body = response.content[:4096].decode("utf-8", "replace")

        version = ""
        if server and re.search(r"\d", server):
            version = server
        if not version and body:
            match = (
                re.search(r'"number"\s*:\s*"([^"]+)"', body, re.I)
                or re.search(r'"version"\s*:\s*"([^"]+)"', body, re.I)
                or re.search(r"\bversion[\"'\s:=]+([0-9][\w.\-+]*)", body, re.I)
            )
            if match:
                version = match.group(1)

        title = ""
        match = re.search(r"<title[^>]*>(.*?)</title>", body, re.I | re.S)
        if match:
            title = " ".join(match.group(1).split())[:80]

        parts = [f"HTTP {response.status_code} from {url}"]
        if server:
            parts.append(f"Server: {server}")
        if title:
            parts.append(f"Title: {title}")
        if version and version != server:
            parts.append(f"Version: {version}")

        return {
            "status": response.status_code,
            "server": server,
            "title": title,
            "version": version,
            "evidence": "; ".join(parts),
        }

    # ------------------------------------------------------------------ #
    # Fingerprint helpers
    # ------------------------------------------------------------------ #
    def _classify_banner(self, banner: str, known: str | None) -> tuple[str, str]:
        """Derive ``(service, version)`` from a raw protocol banner."""
        text = banner.strip()

        match = re.match(r"SSH-(\d\.\d)-(\S+)", text)
        if match:
            return "ssh", match.group(2)

        if re.match(r"^\d{3}", text):
            if re.search(r"vsftpd|proftpd|pure-ftpd|wu-ftpd|filezilla|\bftp\b", text, re.I):
                found = re.search(
                    r"(vsftpd|ProFTPD|Pure-FTPd|wu-ftpd|FileZilla)[\s/]?[\d.]*",
                    text,
                    re.I,
                )
                return "ftp", found.group(0).strip() if found else ""
            if re.search(r"esmtp|\bsmtp\b|postfix|exim|sendmail|haraka|exchange", text, re.I):
                found = re.search(
                    r"(Postfix[^\r\n]*|Exim[^\r\n]*|Sendmail[^\r\n]*|Haraka[^\r\n]*|"
                    r"Microsoft ESMTP[^\r\n]*|Exchange[^\r\n]*)",
                    text,
                    re.I,
                )
                return "smtp", found.group(0).strip()[:60] if found else ""
            if "mysql" in text.lower():
                return "mysql", self._numeric_version(text) or ""
            return (known or "text"), self._numeric_version(text) or ""

        if text.startswith("+OK"):
            found = re.search(r"(Dovecot|Courier|qpopper|CommuniGate)[^\r\n]*", text, re.I)
            return "pop3", found.group(0).strip()[:60] if found else ""

        if text.startswith("* OK"):
            found = re.search(r"(Dovecot|Courier|UW[\s-]imapd|Zimbra)[^\r\n]*", text, re.I)
            return "imap", found.group(0).strip()[:60] if found else ""

        if text.startswith("HTTP/"):
            found = re.match(r"HTTP/([\d.]+)", text)
            return "http", found.group(1) if found else ""

        if "MongoDB" in text or "access MongoDB over HTTP" in text:
            return "mongodb", ""

        if "redis_version" in text:
            found = re.search(r"redis_version[:=]\s*([\d.]+)", text)
            return "redis", found.group(1) if found else ""

        if "STAT version" in text:
            found = re.search(r"STAT version\s+(\S+)", text)
            return "memcached", found.group(1) if found else ""

        # Generic: a full x.y.z version is trusted even in binary banners
        # (e.g. MySQL handshake); a shorter x.y form only when the banner
        # looks textual, to avoid version strings fabricated from junk bytes.
        three_part = re.search(r"\b(\d+\.\d+\.\d+[\w.\-+]*)\b", text)
        if three_part:
            return known or "unknown", three_part.group(1)
        if re.search(r"[A-Za-z]{3,}", text):
            return known or "unknown", self._numeric_version(text) or ""
        return known or "unknown", ""

    @staticmethod
    def _numeric_version(text: str) -> str | None:
        match = re.search(r"\b(\d+\.\d+(?:\.\d+)?[\w.\-+]*)\b", text)
        return match.group(1) if match else None

    @staticmethod
    def _clean(data: bytes) -> str:
        """Make arbitrary banner bytes safe for logs/evidence fields."""
        text = data.decode("utf-8", "replace")
        text = "".join(
            ch if (32 <= ord(ch) < 127 or ch in "\r\n\t") else "." for ch in text
        )
        return text.strip()[:512]

    @staticmethod
    def _ssl_context() -> Any:
        import ssl

        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        return context

    # ------------------------------------------------------------------ #
    # Reporting helpers
    # ------------------------------------------------------------------ #
    def _severity_for(self, port: int, service: str) -> Severity:
        if port in self.CRITICAL_PORTS or service in {"docker", "redis", "memcached"}:
            return Severity.CRITICAL
        if port in self.HIGH_PORTS or service in {"telnet", "rexec", "rsh", "rlogin"}:
            return Severity.HIGH
        if port in self.MEDIUM_PORTS:
            return Severity.MEDIUM
        if port in self.INFO_PORTS:
            return Severity.INFO
        return Severity.LOW

    @staticmethod
    def _remediation_for(severity: Severity, service: str, port: int) -> str:
        guidance = {
            Severity.CRITICAL: (
                f"The exposed '{service}' service on port {port} typically allows "
                "unauthenticated access to sensitive data. Restrict it to trusted "
                "hosts with firewall rules, require authentication, and patch "
                "immediately."
            ),
            Severity.HIGH: (
                f"Restrict port {port} ({service}) to trusted source IPs via "
                "firewall or ACLs, disable it if not required, and enforce strong "
                "authentication and current patching."
            ),
            Severity.MEDIUM: (
                f"The '{service}' service on port {port} may leak credentials or "
                "expose sensitive functionality; prefer encrypted alternatives and "
                "limit access to authorized networks."
            ),
            Severity.LOW: (
                f"Confirm that '{service}' on port {port} is intentionally exposed, "
                "keep it patched, and restrict access to trusted networks."
            ),
            Severity.INFO: (
                "Expected service; verify it is kept up to date and does not expose "
                "administrative interfaces publicly."
            ),
        }
        return guidance[severity]

    @staticmethod
    def _normalize_host(target: str) -> str:
        """Strip scheme, path, credentials and port from a user supplied target."""
        value = target.strip()
        value = re.sub(r"^[a-zA-Z][a-zA-Z0-9+.\-]*://", "", value)
        value = value.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
        if "@" in value:
            value = value.rsplit("@", 1)[-1]
        if value.count(":") == 1:
            host, _, port = value.partition(":")
            if port.isdigit():
                value = host
        return value.strip().strip(".").lower()
