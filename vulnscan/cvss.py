"""CVSS v3.x base score calculation (FIRST specification) and severity bands."""

from __future__ import annotations

import math
from typing import Dict, Optional

_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_AC = {"L": 0.77, "H": 0.44}
_UI = {"N": 0.85, "R": 0.62}
_CIA = {"H": 0.56, "L": 0.22, "N": 0.0}
_PR_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.5}


def _roundup(x: float) -> float:
    i = int(round(x * 100000))
    if i % 10000 == 0:
        return i / 100000.0
    return (math.floor(i / 10000) + 1) / 10.0


def parse_vector(vector: str) -> Optional[Dict[str, str]]:
    parts = vector.strip().split("/")
    if not parts or not parts[0].startswith("CVSS:3"):
        return None
    metrics: Dict[str, str] = {}
    for p in parts[1:]:
        if ":" in p:
            k, v = p.split(":", 1)
            metrics[k] = v
    return metrics


def base_score_v3(vector: str) -> Optional[float]:
    """Return the CVSS v3.x base score for a vector string, or None if unsupported/invalid."""
    m = parse_vector(vector)
    if not m:
        return None
    try:
        changed = m["S"] == "C"
        pr = (_PR_CHANGED if changed else _PR_UNCHANGED)[m["PR"]]
        iss = 1 - (1 - _CIA[m["C"]]) * (1 - _CIA[m["I"]]) * (1 - _CIA[m["A"]])
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15 if changed else 6.42 * iss
        exploit = 8.22 * _AV[m["AV"]] * _AC[m["AC"]] * pr * _UI[m["UI"]]
    except KeyError:
        return None
    if impact <= 0:
        return 0.0
    raw = 1.08 * (impact + exploit) if changed else impact + exploit
    return _roundup(min(raw, 10.0))


def severity_label(score: Optional[float]) -> Optional[str]:
    if score is None:
        return None
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    if score > 0.0:
        return "LOW"
    return "NONE"
