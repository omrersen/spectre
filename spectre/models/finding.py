from enum import Enum
from datetime import datetime
from pydantic import BaseModel, Field


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Finding(BaseModel):
    title: str
    severity: Severity
    target: str
    evidence: str = ""
    remediation: str = ""
    scanner: str = ""
    cvss: float | None = None
    cve: list[str] = []
    metadata: dict = {}
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    verified: bool = False
    false_positive: bool = False

    class Config:
        use_enum_values = True


class ScanResult(BaseModel):
    target: str
    findings: list[Finding] = []
    scanners_used: list[str] = []
    duration: float = 0.0
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    
    @property
    def summary(self) -> dict[str, int]:
        counts = {s.value: 0 for s in Severity}
        for f in self.findings:
            counts[f.severity] += 1
        return counts
    
    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.CRITICAL)
    
    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.HIGH)
