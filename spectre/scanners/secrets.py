"""Secret and credential scanner: detects hardcoded secrets in files and directories."""

import math
import re
from collections import Counter
from pathlib import Path

from .base import BaseScanner
from ..models import Finding, Severity

MAX_FILE_SIZE = 1_048_576  # Skip files larger than 1MB
ENTROPY_THRESHOLD = 4.5
MIN_ENTROPY_TOKEN = 20


class SecretsScanner(BaseScanner):
    name = "secrets"
    description = "Secret and credential scanner"
    version = "1.0.0"

    PATTERNS: list[tuple[str, str, Severity]] = [
        # Provider API keys / tokens
        ("aws_access_key", r"AKIA[0-9A-Z]{16}", Severity.CRITICAL),
        ("google_api_key", r"AIza[0-9A-Za-z_\-]{35}", Severity.CRITICAL),
        ("github_token", r"gh[pousr]_[A-Za-z0-9]{36}", Severity.CRITICAL),
        ("github_pat", r"github_pat_[A-Za-z0-9_]{50,}", Severity.CRITICAL),
        ("openai_api_key", r"sk-(?:proj-)?[A-Za-z0-9_\-]{20,}", Severity.CRITICAL),
        ("anthropic_api_key", r"sk-ant-[A-Za-z0-9_\-]{20,}", Severity.CRITICAL),
        ("stripe_secret_key", r"sk_live_[0-9a-zA-Z]{24,}", Severity.CRITICAL),
        ("slack_token", r"xox[baprs]-[A-Za-z0-9\-]{10,}", Severity.CRITICAL),
        ("slack_webhook", r"hooks\.slack\.com/services/[A-Za-z0-9/_\-]+", Severity.HIGH),
        ("gitlab_token", r"glpat-[A-Za-z0-9_\-]{20,}", Severity.HIGH),
        ("sendgrid_api_key", r"SG\.[A-Za-z0-9_\-]{16,}\.[A-Za-z0-9_\-]{16,}", Severity.HIGH),
        ("twilio_api_key", r"\bSK[0-9a-fA-F]{32}\b", Severity.HIGH),
        ("mailgun_api_key", r"\bkey-[0-9a-fA-F]{32}\b", Severity.HIGH),
        ("huggingface_token", r"\bhf_[A-Za-z0-9]{30,}\b", Severity.HIGH),
        ("npm_token", r"\bnpm_[A-Za-z0-9]{36}\b", Severity.HIGH),
        # Private key material
        ("private_key", r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----", Severity.CRITICAL),
        # Credential assignments in source code
        ("password_assignment", r"(?i)\b(?:password|passwd|pwd)\s*[:=]\s*[\"']([^\"'\n]{4,})[\"']", Severity.HIGH),
        ("password_bare", r"(?i)\b(?:password|passwd|pwd)\s*[:=]\s*(?![\"'])(?!(?:None|True|False|null|nil|os\.|env|getenv|settings\.|self\.|\w+\())([A-Za-z0-9_\-!@#$%^&*.]{6,})\b", Severity.HIGH),
        ("secret_assignment", r"(?i)\b(?:secret|client_secret|api_key|apikey|access_token|auth_token|private_key|credential)\s*[:=]\s*[\"']([^\"'\n]{8,})[\"']", Severity.HIGH),
        ("authorization_header", r"(?i)\bauthorization\s*[:=]\s*[\"']?(?:basic|bearer)\s+[A-Za-z0-9_\-.=/+]{16,}", Severity.HIGH),
        # Structured tokens / URLs
        ("jwt_token", r"eyJ[A-Za-z0-9_\-]{5,}\.eyJ[A-Za-z0-9_\-]{5,}\.[A-Za-z0-9_\-]+", Severity.MEDIUM),
        ("basic_auth_url", r"\b[a-z][a-z0-9+.\-]*://[^/\s:@]+:[^/\s@]+@[^\s\"'<>]+", Severity.HIGH),
        ("mysql_connection", r"(?i)\bmysql://[^\s/:@]+:[^\s/@]+@[^\s\"'<>]+", Severity.HIGH),
        ("postgres_connection", r"(?i)\bpost(?:gres|gresql)://[^\s/:@]+:[^\s/@]+@[^\s\"'<>]+", Severity.HIGH),
        ("mongodb_connection", r"(?i)\bmongodb(?:\+srv)?://[^\s/:@]+:[^\s/@]+@[^\s\"'<>]+", Severity.HIGH),
        ("redis_connection", r"(?i)\brediss?://[^\s/:@]+:[^\s/@]+@[^\s\"'<>]+", Severity.HIGH),
        ("database_url_env", r"(?i)\b(?:DATABASE_URL|DB_URL|MONGO_URL|REDIS_URL|AMQP_URL)\s*[:=]\s*[\"']?\S+", Severity.MEDIUM),
    ]

    PLACEHOLDERS = ("example", "your-", "your_", "changeme", "change-me", "placeholder",
                    "dummy", "redacted", "xxxx", "<%", "${", "%(")
    PLACEHOLDER_VALUES = {"password", "passwd", "secret", "token", "api_key", "apikey",
                          "key", "pass", "redacted", "null", "none", "undefined"}
    BINARY_MARKERS = (".png", ".jpg", ".jpeg", ".gif", ".ico", ".woff", ".woff2", ".ttf",
                      ".eot", ".pdf", ".zip", ".gz", ".tar", ".jar", ".exe", ".dll",
                      ".so", ".dylib", ".class", ".pyc", ".min.")
    EXCLUDED_DIRS = {".git", "node_modules", "vendor", "dist", "build", ".venv", "venv",
                     "__pycache__", ".tox", ".next", ".cache", "coverage"}
    ENTROPY_TOKEN = re.compile(rf"[A-Za-z0-9+/=_\-]{{{MIN_ENTROPY_TOKEN},}}")
    REMEDIATION = ("Remove the secret from source control, rotate it immediately, and load "
                   "it at runtime from an environment variable or secret manager.")
    _COMPILED: dict[str, tuple[re.Pattern[str], Severity]] | None = None

    # -------------------------------------------------------------- scanning
    async def scan(self, target: str) -> list[Finding]:
        """Scan a file, or a directory recursively, for hardcoded secrets."""
        path = Path(target).expanduser()
        if not path.exists():
            raise FileNotFoundError(f"Secret scan target does not exist: {target}")

        findings: list[Finding] = []
        if path.is_dir():
            for candidate in sorted(path.rglob("*")):
                try:
                    if not candidate.is_file() or not self._is_scannable(candidate):
                        continue
                    findings.extend(self._scan_file(candidate))
                except OSError:
                    continue
        elif path.is_file():
            findings.extend(self._scan_file(path))

        seen: set[tuple[str, str, str]] = set()
        unique = [f for f in findings
                  if (f.title, f.target, f.evidence) not in seen
                  and not seen.add((f.title, f.target, f.evidence))]
        return unique[:500]  # Cap output so one run cannot flood the report

    @classmethod
    def compiled_patterns(cls) -> dict[str, tuple[re.Pattern[str], Severity]]:
        """Compile the regex patterns once per class."""
        if cls.__dict__.get("_COMPILED") is None:
            cls._COMPILED = {n: (re.compile(e), s) for n, e, s in cls.PATTERNS}
        return cls._COMPILED

    def _scan_file(self, path: Path) -> list[Finding]:
        findings: list[Finding] = []
        if not self._is_scannable(path):
            return findings
        try:
            raw = path.read_bytes()
        except OSError:
            return findings
        if b"\x00" in raw[:8192]:  # Binary content heuristic
            return findings

        text = raw.decode("utf-8", errors="replace")
        patterns = self.compiled_patterns()
        for lineno, line in enumerate(text.splitlines(), 1):
            line = line[:8192]
            spans: list[tuple[int, int]] = []
            for pattern_name, (regex, severity) in patterns.items():
                for match in regex.finditer(line):
                    if self._is_placeholder(match.group(0)):
                        continue
                    spans.append(match.span())
                    findings.append(self._finding(
                        title=f"{self._label(pattern_name)} detected",
                        severity=severity,
                        target=str(path),
                        evidence=f"{path}:{lineno}: {self._redact(match.group(0))}",
                        pattern=pattern_name, line=lineno))
            findings.extend(self._entropy_findings(line, path, lineno, spans))
            if len(findings) >= 50:  # Per-file cap keeps large files bounded
                break
        return findings

    def _entropy_findings(self, line: str, path: Path, lineno: int,
                          covered: list[tuple[int, int]]) -> list[Finding]:
        """Flag high-entropy tokens that no explicit pattern already matched."""
        out: list[Finding] = []
        for match in self.ENTROPY_TOKEN.finditer(line):
            token = match.group(0)
            start, end = match.span()
            if any(start < e and end > s for s, e in covered):
                continue
            if self._is_placeholder(token):
                continue
            # Require mixed digits + letters: drops words, paths and plain hashes.
            if not (any(c.isdigit() for c in token) and any(c.isalpha() for c in token)):
                continue
            if re.fullmatch(r"[0-9a-fA-F]+", token):
                continue
            entropy = self.shannon_entropy(token)
            if entropy <= ENTROPY_THRESHOLD:
                continue
            out.append(self._finding(
                title=f"High entropy string (entropy={entropy:.2f})",
                severity=Severity.MEDIUM, target=str(path),
                evidence=f"{path}:{lineno}: {self._redact(token)}",
                pattern="high_entropy", line=lineno,
                extra={"entropy": round(entropy, 3), "length": len(token)}))
        return out

    # --------------------------------------------------------------- helpers
    @staticmethod
    def shannon_entropy(data: str) -> float:
        """Shannon entropy of ``data`` in bits per character."""
        if not data:
            return 0.0
        length = len(data)
        counts = Counter(data)
        return -sum((n / length) * math.log2(n / length) for n in counts.values())

    @classmethod
    def _is_scannable(cls, path: Path) -> bool:
        """Filter out binary-looking extensions, vendored dirs and oversized files."""
        try:
            if path.stat().st_size >= MAX_FILE_SIZE:
                return False
        except OSError:
            return False
        if any(part in cls.EXCLUDED_DIRS for part in path.parts):
            return False
        name = path.name.lower()
        return not any(name.endswith(ext) for ext in cls.BINARY_MARKERS)

    @classmethod
    def _is_placeholder(cls, value: str) -> bool:
        """Skip obvious placeholder/example values to limit false positives."""
        lowered = value.lower().strip("\"'")
        if lowered in cls.PLACEHOLDER_VALUES:
            return True
        return any(marker in lowered for marker in cls.PLACEHOLDERS)

    @staticmethod
    def _redact(value: str) -> str:
        value = value.strip()
        if len(value) <= 8:
            return "*" * len(value)
        return f"{value[:4]}...{value[-4:]} (len={len(value)})"

    @staticmethod
    def _label(name: str) -> str:
        acronyms = {"aws": "AWS", "api": "API", "openai": "OpenAI", "github": "GitHub",
                    "gitlab": "GitLab", "jwt": "JWT", "db": "DB", "url": "URL",
                    "anthropic": "Anthropic", "npm": "NPM", "uri": "URI"}
        return " ".join(acronyms.get(w, w.capitalize()) for w in name.split("_"))

    def _finding(self, *, title: str, severity: Severity, target: str, evidence: str,
                 pattern: str, line: int, extra: dict | None = None) -> Finding:
        metadata = {"type": "secret", "pattern": pattern, "line": line}
        if extra:
            metadata.update(extra)
        return Finding(title=title, severity=severity, target=target, evidence=evidence,
                       remediation=self.REMEDIATION, scanner=self.name, metadata=metadata)
