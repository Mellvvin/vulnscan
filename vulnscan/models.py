from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum
from typing import Dict, List, Optional, Tuple

from .owasp import DEFAULT_EDITION, lookup


class Severity(IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def parse(cls, value: str) -> "Severity":
        return cls[value.strip().upper()]


@dataclass
class Finding:
    host: str
    port: Optional[int]
    check_id: str
    title: str
    severity: Severity
    category: str  # edition-independent OWASP category key, see owasp.py
    cwe: str
    description: str
    remediation: str
    evidence: str = ""
    # Edition-specific (id, name) that bypasses the category-key lookup. Used by the
    # package audit, where the category comes from the CVE's CWE via OWASP's own data.
    owasp_override: Optional[Tuple[str, str]] = None
    extra: Dict[str, object] = field(default_factory=dict)

    def key(self) -> tuple:
        return (self.host, self.port, self.check_id)

    def to_dict(self, edition: str = DEFAULT_EDITION) -> Dict[str, object]:
        if self.owasp_override:
            owasp_id, owasp_name = self.owasp_override
        else:
            owasp_id, owasp_name = lookup(self.category, edition)
        out = {
            "host": self.host,
            "port": self.port,
            "check_id": self.check_id,
            "title": self.title,
            "severity": self.severity.name,
            "owasp": owasp_id,
            "owasp_name": owasp_name,
            "cwe": self.cwe,
            "description": self.description,
            "remediation": self.remediation,
            "evidence": self.evidence,
        }
        if self.extra:
            out["details"] = self.extra
        return out


@dataclass
class PortInfo:
    port: int
    service: str = "unknown"
    banner: str = ""
    tls: bool = False
    http: bool = False

    def to_dict(self) -> Dict[str, object]:
        return {
            "port": self.port,
            "service": self.service,
            "banner": self.banner,
            "tls": self.tls,
            "http": self.http,
        }


@dataclass
class HostResult:
    host: str  # label shown in reports (hostname or IP)
    address: str  # IP actually scanned
    ports: List[PortInfo] = field(default_factory=list)
    findings: List[Finding] = field(default_factory=list)

    def add(self, finding: Finding) -> None:
        if all(f.key() != finding.key() for f in self.findings):
            self.findings.append(finding)

    def extend(self, findings) -> None:
        for f in findings:
            self.add(f)
