"""Banner-based detection of end-of-life / known-bad software versions.

This is deliberately a *small, explainable* table rather than a CVE database.
Banner matching cannot see distro backports, so every finding says "verify".
The thresholds reflect upstream support status as of late 2026 and should be
reviewed periodically.
"""

from __future__ import annotations

import re
from typing import List, Tuple

from .models import Finding, Severity

# (regex, product, minimum supported version tuple, note)
MIN_VERSION_RULES: List[Tuple[re.Pattern, str, Tuple[int, ...], str]] = [
    (re.compile(r"OpenSSH[_ ](\d+)\.(\d+)", re.I), "OpenSSH", (8, 0),
     "Releases older than 8.0 no longer receive upstream fixes."),
    (re.compile(r"Apache/(\d+)\.(\d+)\.(\d+)", re.I), "Apache httpd", (2, 4, 50),
     "2.4.49 is vulnerable to path traversal/RCE (CVE-2021-41773); older 2.4.x lacks many fixes."),
    (re.compile(r"nginx/(\d+)\.(\d+)\.(\d+)", re.I), "nginx", (1, 20, 0),
     "Versions older than 1.20 are outside upstream support."),
    (re.compile(r"PHP/(\d+)\.(\d+)\.(\d+)", re.I), "PHP", (8, 2, 0),
     "PHP releases older than 8.2 are end-of-life."),
    (re.compile(r"Microsoft-IIS/(\d+)\.(\d+)", re.I), "Microsoft IIS", (8, 5),
     "IIS older than 8.5 runs on unsupported Windows Server releases."),
    (re.compile(r"ProFTPD (\d+)\.(\d+)\.(\d+)", re.I), "ProFTPD", (1, 3, 6),
     "Older ProFTPD releases have multiple published vulnerabilities."),
]

# Specific known-bad builds: (regex, product, severity, note)
KNOWN_BAD = [
    (re.compile(r"vsftpd 2\.3\.4", re.I), "vsftpd 2.3.4", Severity.CRITICAL,
     "This release shipped with a backdoor (CVE-2011-2523). Common in intentionally "
     "vulnerable lab VMs; should never appear on a real host."),
]


def _version_str(groups) -> str:
    return ".".join(groups)


def version_findings(host: str, port: int, text: str) -> List[Finding]:
    """Inspect a banner / Server header string and return component findings."""
    findings: List[Finding] = []
    if not text:
        return findings

    for rx, product, severity, note in KNOWN_BAD:
        if rx.search(text):
            findings.append(Finding(
                host=host, port=port, check_id="COMP-KNOWN-BAD-VERSION",
                title=f"Known-compromised software version: {product}",
                severity=severity, category="supply_chain", cwe="CWE-1104",
                description=note,
                remediation="Remove or upgrade the affected package immediately and "
                            "treat the host as potentially compromised.",
                evidence=text.strip()[:120],
            ))

    for rx, product, minimum, note in MIN_VERSION_RULES:
        m = rx.search(text)
        if not m:
            continue
        found = tuple(int(g) for g in m.groups())
        # Compare only as many components as the rule specifies.
        if found[: len(minimum)] < minimum:
            wanted = ".".join(str(x) for x in minimum)
            findings.append(Finding(
                host=host, port=port, check_id="COMP-OUTDATED",
                title=f"Outdated {product} ({_version_str(m.groups())})",
                severity=Severity.MEDIUM, category="supply_chain", cwe="CWE-1104",
                description=f"{note} Detected from the service banner; distributions "
                            "sometimes backport fixes without changing the version string, "
                            "so verify against the package changelog.",
                remediation=f"Upgrade {product} to {wanted} or later (or a supported "
                            "distribution build) and re-scan.",
                evidence=m.group(0),
            ))
    return findings
