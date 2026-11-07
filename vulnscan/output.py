"""Machine-readable output: results.json (full detail) and findings.tsv (for Bash tooling)."""

from __future__ import annotations

import json
import os
from collections import Counter
from typing import Dict, List, Optional

from . import __version__
from .models import Finding, HostResult, Severity

TSV_COLUMNS = ["severity", "host", "port", "check_id", "owasp", "owasp_name", "cwe",
               "title", "remediation", "evidence"]


def sort_findings(findings: List[Finding]) -> List[Finding]:
    return sorted(findings, key=lambda f: (-int(f.severity), f.host, f.port or 0, f.check_id))


def _clean(value: object) -> str:
    """Make a value safe for a single TSV cell."""
    return str(value if value is not None else "").replace("\t", " ").replace("\r", " ").replace("\n", " ")


def write_tsv(path: str, findings: List[Finding], edition: str) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\t".join(TSV_COLUMNS) + "\n")
        for f in sort_findings(findings):
            d = f.to_dict(edition)
            d["port"] = d["port"] if d["port"] is not None else "-"
            fh.write("\t".join(_clean(d[c]) for c in TSV_COLUMNS) + "\n")


def write_json(path: str, meta: Dict[str, object], hosts: List[HostResult],
               findings: List[Finding], edition: str, extra: Optional[Dict[str, object]] = None) -> None:
    counts = Counter(f.severity.name for f in findings)
    doc = {
        "meta": {"tool": "vulnscan", "version": __version__, "owasp_edition": edition, **meta},
        "summary": {s.name: counts.get(s.name, 0) for s in sorted(Severity, reverse=True)},
        "hosts": [
            {"host": h.host, "address": h.address, "open_ports": [p.to_dict() for p in h.ports]}
            for h in hosts
        ],
        "findings": [f.to_dict(edition) for f in sort_findings(findings)],
    }
    if extra:
        doc.update(extra)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(doc, fh, indent=2)
        fh.write("\n")


def ensure_dir(path: str) -> str:
    os.makedirs(path, exist_ok=True)
    return path
