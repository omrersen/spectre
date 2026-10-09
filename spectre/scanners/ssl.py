"""SSL/TLS configuration analyzer: certificate validity, protocol versions and ciphers."""

import asyncio
import os
import re
import socket
import ssl
import tempfile
import time
from urllib.parse import urlparse

import httpx

from .base import BaseScanner
from ..models import Finding, Severity

TIMEOUT = 8.0                    # Per-socket / per-request timeout (seconds)
EXPIRY_WARNING_DAYS = 30         # Certificates expiring within this window get a finding
HSTS_MIN_MAX_AGE = 15_552_000    # 180 days, the HSTS duration recommended by OWASP
VERSION_TESTS = (
    ("TLS 1.0", ssl.TLSVersion.TLSv1),
    ("TLS 1.1", ssl.TLSVersion.TLSv1_1),
    ("TLS 1.2", ssl.TLSVersion.TLSv1_2),
    ("TLS 1.3", ssl.TLSVersion.TLSv1_3),
)
OP_NO_FLAGS = {
    ssl.TLSVersion.TLSv1: "OP_NO_TLSv1",
    ssl.TLSVersion.TLSv1_1: "OP_NO_TLSv1_1",
    ssl.TLSVersion.TLSv1_2: "OP_NO_TLSv1_2",
    ssl.TLSVersion.TLSv1_3: "OP_NO_TLSv1_3",
}
# "DES" also matches 3DES/DES-CBC3 suites
WEAK_CIPHER_MARKERS = ("NULL", "EXPORT", "RC4", "DES", "MD5")


class SSLScanner(BaseScanner):
    name = "ssl"
    description = "SSL/TLS configuration analyzer"
    version = "1.0.0"

    # -------------------------------------------------------------- scanning
    async def scan(self, target: str) -> list[Finding]:
        """Probe the TLS service behind ``target`` and report weaknesses."""
        hostname, port = self._host_port(target)
        if not hostname:
            return []
        try:  # Unresolvable hostnames are not a TLS finding
            await asyncio.to_thread(socket.getaddrinfo, hostname, port, proto=socket.IPPROTO_TCP)
        except socket.gaierror:
            return []

        probes = await asyncio.gather(
            *(self._test_version(hostname, port, label, version) for label, version in VERSION_TESTS),
            asyncio.to_thread(self._fetch_certificate, hostname, port),
            self._hsts_findings(hostname, port), return_exceptions=True)
        enabled = {label for (label, _), ok in zip(VERSION_TESTS, probes[:4]) if ok is True}
        if not enabled:  # Host resolves but no handshake completed at all
            return [self._finding(
                title="TLS negotiation failed", severity=Severity.MEDIUM, target=hostname,
                evidence=f"no TLS version completed a handshake on {hostname}:{port}",
                remediation="Confirm the service is reachable and terminates TLS on this port.")]

        findings: list[Finding] = []
        for label in ("TLS 1.0", "TLS 1.1"):
            if label in enabled:
                findings.append(self._finding(
                    title=f"Weak TLS version enabled: {label}", severity=Severity.HIGH, target=hostname,
                    evidence=f"handshake negotiated down to {label} on {hostname}:{port}",
                    remediation=f"Disable {label} (deprecated by RFC 8996); require TLS 1.2+."))
        if not (enabled & {"TLS 1.2", "TLS 1.3"}):
            findings.append(self._finding(
                title="No modern TLS version supported", severity=Severity.HIGH, target=hostname,
                evidence=f"only {', '.join(sorted(enabled))} negotiated on {hostname}:{port}",
                remediation="Enable TLS 1.2 and TLS 1.3; older protocols are deprecated."))
        findings.append(self._finding(
            title=f"TLS 1.3 {'supported' if 'TLS 1.3' in enabled else 'not supported'}",
            severity=Severity.INFO, target=hostname,
            evidence=f"enabled protocols: {', '.join(sorted(enabled))}",
            remediation="Enable TLS 1.3 for the strongest protocol support."))
        cert_result = probes[4]
        if isinstance(cert_result, ssl.SSLError):
            findings.append(self._finding(
                title="TLS handshake error", severity=Severity.MEDIUM, target=hostname,
                evidence=f"{hostname}:{port} rejected the handshake: {cert_result}",
                remediation="Inspect server TLS configuration and protocol/cipher settings."))
        elif isinstance(cert_result, tuple):  # OSError/timeout exceptions are skipped
            cert, cipher = cert_result
            if cert:
                findings.extend(self._certificate_findings(cert, hostname, port))
            findings.extend(self._cipher_findings(cipher, hostname, port))
        if isinstance(probes[5], list):
            findings.extend(probes[5])  # HSTS results
        return findings

    async def _test_version(self, hostname: str, port: int, label: str,
                            version: ssl.TLSVersion) -> bool:
        """True when a handshake succeeds with only ``version`` allowed."""
        try:
            return await asyncio.wait_for(
                asyncio.to_thread(self._handshake, hostname, port, version), TIMEOUT + 2)
        except (asyncio.TimeoutError, ssl.SSLError, OSError, ValueError):
            return False

    @staticmethod
    def _handshake(hostname: str, port: int, version: ssl.TLSVersion) -> bool:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.options &= ~getattr(ssl, OP_NO_FLAGS[version], 0)  # Don't inherit interpreter defaults
        try:
            ctx.minimum_version = version
            ctx.maximum_version = version
        except (ValueError, ssl.SSLError):  # OpenSSL build without this protocol
            return False
        with socket.create_connection((hostname, port), timeout=TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname):
                return True  # min == max, so success implies exactly this version

    # ----------------------------------------------------------- certificates
    @staticmethod
    def _fetch_certificate(hostname: str, port: int) -> tuple[dict | None, tuple | None]:
        """TLS session without validation; returns (decoded certificate dict, cipher)."""
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((hostname, port), timeout=TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as tls:
                der = tls.getpeercert(binary_form=True)
                cipher = tls.cipher()
        if not der:
            raise ssl.SSLError(f"{hostname}:{port} did not present a certificate")
        return SSLScanner._decode_certificate(der), cipher

    @staticmethod
    def _decode_certificate(der: bytes) -> dict | None:
        """Decode DER via the stdlib certificate parser (cert dict as in ssl docs)."""
        fd, path = tempfile.mkstemp(suffix=".pem")
        try:
            with os.fdopen(fd, "w", encoding="ascii") as handle:
                handle.write(ssl.DER_cert_to_PEM_cert(der))
            return ssl._ssl._test_decode_cert(path)
        except (OSError, ValueError, ssl.SSLError):
            return None
        finally:
            if os.path.exists(path):
                os.unlink(path)

    def _certificate_findings(self, cert: dict, hostname: str, port: int) -> list[Finding]:
        findings: list[Finding] = []
        not_after = cert.get("notAfter")
        try:
            expires = ssl.cert_time_to_seconds(not_after) if not_after else None
        except (ValueError, TypeError):
            expires = None
        if expires is not None:
            days_left = int((expires - time.time()) / 86_400)
            if days_left <= EXPIRY_WARNING_DAYS:
                expired = days_left < 0
                findings.append(self._finding(
                    title="Certificate expired" if expired else "Certificate expires soon",
                    severity=Severity.CRITICAL if expired else Severity.MEDIUM, target=hostname,
                    evidence=f"notAfter={not_after} ({abs(days_left)} day(s) "
                             f"{'ago' if expired else 'remaining'}) on {hostname}:{port}",
                    remediation=("Reissue and deploy a valid certificate immediately."
                                 if expired else "Automate certificate renewal before expiry.")))
        subject, issuer = cert.get("subject") or (), cert.get("issuer") or ()
        if subject and subject == issuer:
            findings.append(self._finding(
                title="Self-signed certificate", severity=Severity.MEDIUM, target=hostname,
                evidence=f"subject==issuer: CN={self._common_name(subject) or '<none>'} (notAfter={not_after})",
                remediation="Use a certificate issued by a trusted CA, or distribute your CA certificate to clients."))
        matches, names = self._hostname_matches(hostname, cert)
        if not matches:
            findings.append(self._finding(
                title="Certificate hostname mismatch", severity=Severity.HIGH, target=hostname,
                evidence=f"certificate is for {names or ['<no names>']} but was used for {hostname}",
                remediation="Reissue the certificate covering this hostname; SAN/CN mismatches fail client validation."))
        return findings

    def _cipher_findings(self, cipher: tuple | None, hostname: str, port: int) -> list[Finding]:
        if not cipher:
            return []
        name, protocol, bits = cipher[0], cipher[1], cipher[2]
        marker = next((m for m in WEAK_CIPHER_MARKERS if m in name.upper()), None)
        if not marker:
            return []
        return [self._finding(
            title=f"Weak cipher suite negotiated: {name}", severity=Severity.HIGH, target=hostname,
            evidence=f"{name} over {protocol} ({bits}-bit strength) on {hostname}:{port}; matched '{marker}'",
            remediation="Disable NULL/EXPORT/RC4/DES/3DES/MD5 suites; prefer AEAD (AES-GCM, ChaCha20-Poly1305).")]

    @classmethod
    def _hostname_matches(cls, hostname: str, cert: dict) -> tuple[bool, list[str]]:
        """Manual SAN check (ssl.match_hostname was removed in Python 3.12)."""
        names = [v for k, v in cert.get("subjectAltName") or () if k in ("DNS", "IP Address")]
        if not names and cert.get("subject"):
            common = cls._common_name(cert["subject"])
            names = [common] if common else []
        for pattern in names:
            if pattern == hostname:
                return True, names
            if pattern.startswith("*."):  # Wildcard covers exactly one label
                suffix = pattern[1:]
                if (len(hostname) > len(suffix) and hostname.endswith(suffix)
                        and "." not in hostname[: -len(suffix)]):
                    return True, names
        return False, names

    @staticmethod
    def _common_name(subject: tuple) -> str:
        return next((str(v) for rel in subject for k, v in rel if k == "commonName"), "")

    # ------------------------------------------------------------------ HSTS
    async def _hsts_findings(self, hostname: str, port: int) -> list[Finding]:
        url = f"https://{hostname}" + (f":{port}" if port != 443 else "") + "/"
        try:
            async with httpx.AsyncClient(follow_redirects=True, timeout=TIMEOUT, verify=False) as client:
                resp = await client.get(url, headers={"User-Agent": "SpectreScanner/1.0"})
        except httpx.HTTPError:
            return []  # HTTPS unreachable: the version probes already report that
        header = resp.headers.get("strict-transport-security", "")
        if not header:
            return [self._finding(
                title="HSTS header missing", severity=Severity.LOW, target=hostname,
                evidence=f"no Strict-Transport-Security header in the response from {resp.url}",
                remediation='Add "Strict-Transport-Security: max-age=31536000; includeSubDomains" to HTTPS responses.')]
        match = re.search(r"max-age=(\d+)", header, re.I)
        if match and int(match.group(1)) < HSTS_MIN_MAX_AGE:
            return [self._finding(
                title="HSTS max-age too short", severity=Severity.LOW, target=hostname,
                evidence=f"Strict-Transport-Security: {header} on {resp.url} (< {HSTS_MIN_MAX_AGE}s / 180 days)",
                remediation="Increase max-age to at least 15552000 (180 days) and consider the preload list.")]
        return []

    # --------------------------------------------------------------- helpers
    @staticmethod
    def _host_port(target: str) -> tuple[str, int]:
        raw = (target or "").strip()
        if not raw:
            return "", 443
        try:
            parsed = urlparse(raw if "://" in raw else f"//{raw}")
            return (parsed.hostname or ""), (parsed.port or 443)
        except ValueError:  # Malformed host/port in the target
            return "", 443

    @staticmethod
    def _finding(*, title: str, severity: Severity, target: str, evidence: str, remediation: str) -> Finding:
        return Finding(title=title, severity=severity, target=target, evidence=evidence,
                       remediation=remediation, scanner=SSLScanner.name,
                       metadata={"type": "tls", "protocol": "ssl/tls"})
