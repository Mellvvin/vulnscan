"""OWASP Top 10 data: static category names plus a *self-refreshing* CWE mapping.

Two layers:

1. ``EDITIONS`` - a small static table used by the network/web checks, which are
   tagged with an edition-independent category key ("injection", "crypto"...).
2. ``OwaspData`` - the official CWE-to-category mapping, downloaded from OWASP's
   own source repository, cached for a week, and shipped as an offline snapshot.
   This is what maps real CVEs (via their CWE) to Top 10 categories, so the
   mapping follows OWASP's published data instead of being hand-written.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Dict, List, Optional, Tuple

from .cache import Cache
from .http import Http, HttpError

EDITIONS = {
    "2025": {
        "access_control": ("A01:2025", "Broken Access Control"),
        "misconfig": ("A02:2025", "Security Misconfiguration"),
        "supply_chain": ("A03:2025", "Software Supply Chain Failures"),
        "crypto": ("A04:2025", "Cryptographic Failures"),
        "injection": ("A05:2025", "Injection"),
        "insecure_design": ("A06:2025", "Insecure Design"),
        "auth": ("A07:2025", "Authentication Failures"),
        "integrity": ("A08:2025", "Software or Data Integrity Failures"),
        "logging": ("A09:2025", "Security Logging & Alerting Failures"),
        "exceptions": ("A10:2025", "Mishandling of Exceptional Conditions"),
    },
    "2021": {
        "access_control": ("A01:2021", "Broken Access Control"),
        "crypto": ("A02:2021", "Cryptographic Failures"),
        "injection": ("A03:2021", "Injection"),
        "insecure_design": ("A04:2021", "Insecure Design"),
        "misconfig": ("A05:2021", "Security Misconfiguration"),
        "supply_chain": ("A06:2021", "Vulnerable and Outdated Components"),
        "auth": ("A07:2021", "Identification and Authentication Failures"),
        "integrity": ("A08:2021", "Software and Data Integrity Failures"),
        "logging": ("A09:2021", "Security Logging and Monitoring Failures"),
        # 2021 has no dedicated category for exception handling; CWE-209
        # (error message information leak) was filed under Insecure Design.
        "exceptions": ("A04:2021", "Insecure Design"),
    },
}

DEFAULT_EDITION = "2025"

# Categories that are about design/process and cannot be tested from outside a system.
NOT_TESTABLE_KEYS = ("insecure_design", "logging")


def lookup(category: str, edition: str = DEFAULT_EDITION) -> Tuple[str, str]:
    """Return (owasp_id, owasp_name) for a category key."""
    return EDITIONS[edition][category]


def category_for_key(category: str, edition: str) -> str:
    return EDITIONS[edition][category][0]


def not_testable_ids(edition: str) -> List[str]:
    return sorted({EDITIONS[edition][k][0] for k in NOT_TESTABLE_KEYS})


# --------------------------------------------------------------------------- data

RAW_URL = "https://raw.githubusercontent.com/OWASP/Top10/master/{edition}/docs/en/{file}"
LIST_URL = "https://api.github.com/repos/OWASP/Top10/contents/{edition}/docs/en"
SNAPSHOT_DIR = Path(__file__).parent / "data"
CACHE_TTL = 7 * 24 * 3600

# Fallback file names, used only if the GitHub directory listing is unavailable.
KNOWN_FILES = {
    "2025": [
        "A01_2025-Broken_Access_Control.md", "A02_2025-Security_Misconfiguration.md",
        "A03_2025-Software_Supply_Chain_Failures.md", "A04_2025-Cryptographic_Failures.md",
        "A05_2025-Injection.md", "A06_2025-Insecure_Design.md",
        "A07_2025-Authentication_Failures.md", "A08_2025-Software_or_Data_Integrity_Failures.md",
        "A09_2025-Security_Logging_and_Alerting_Failures.md",
        "A10_2025-Mishandling_of_Exceptional_Conditions.md",
    ],
    "2021": [
        "A01_2021-Broken_Access_Control.md", "A02_2021-Cryptographic_Failures.md",
        "A03_2021-Injection.md", "A04_2021-Insecure_Design.md",
        "A05_2021-Security_Misconfiguration.md", "A06_2021-Vulnerable_and_Outdated_Components.md",
        "A07_2021-Identification_and_Authentication_Failures.md",
        "A08_2021-Software_and_Data_Integrity_Failures.md",
        "A09_2021-Security_Logging_and_Monitoring_Failures.md",
        "A10_2021-Server-Side_Request_Forgery_%28SSRF%29.md",
    ],
}


class OwaspError(Exception):
    pass


@dataclass
class OwaspData:
    edition: str
    categories: Dict[str, str]  # "A05:2025" -> "Injection"
    cwe_map: Dict[int, List[str]]  # 79 -> ["A05:2025"]
    fetched_at: str = ""
    origin: str = "snapshot"  # live | cache | snapshot
    source: str = "github.com/OWASP/Top10"

    def categories_for(self, cwe: int) -> List[str]:
        return self.cwe_map.get(cwe, [])

    def name(self, cat_id: str) -> str:
        return self.categories.get(cat_id, "")

    def to_json(self) -> dict:
        return {"edition": self.edition, "categories": self.categories,
                "cwe_map": {str(k): v for k, v in sorted(self.cwe_map.items())},
                "fetched_at": self.fetched_at, "source": self.source}

    @classmethod
    def from_json(cls, d: dict, origin: str) -> "OwaspData":
        return cls(edition=d["edition"], categories=dict(d["categories"]),
                   cwe_map={int(k): list(v) for k, v in d["cwe_map"].items()},
                   fetched_at=d.get("fetched_at", ""), origin=origin,
                   source=d.get("source", "github.com/OWASP/Top10"))


TITLE_RE = re.compile(r"^#\s+(A\d{2}):(\d{4})\s*(?:[\u2013\u2014-]\s*)?(.+?)\s*(?:!\[.*)?$")
CWE_RE = re.compile(r"\[CWE-(\d+)\b")


def parse_category(markdown: str) -> Tuple[str, str, List[int]]:
    """Parse one OWASP category page into (id, name, [cwe numbers])."""
    cat_id = name = ""
    cwes: List[int] = []
    in_list = False
    for line in markdown.splitlines():
        stripped = line.strip()
        if not cat_id:
            m = TITLE_RE.match(stripped)
            if m:
                cat_id, name = f"{m.group(1)}:{m.group(2)}", m.group(3).strip()
                continue
        if stripped.startswith("## "):
            in_list = stripped.lower().startswith("## list of mapped cwes")
            continue
        if in_list:
            for m in CWE_RE.finditer(line):
                n = int(m.group(1))
                if n not in cwes:
                    cwes.append(n)
    if not cat_id:
        raise OwaspError("no 'A0X:YYYY Name' title found in category page")
    return cat_id, name, cwes


def discover_files(http: Http, edition: str) -> List[str]:
    try:
        listing = http.get_json(LIST_URL.format(edition=edition))
        names = sorted(e["name"] for e in listing
                       if re.fullmatch(rf"A\d{{2}}_{edition}-.+\.md", e.get("name", "")))
        if len(names) == 10:
            return names
    except (HttpError, TypeError, KeyError):
        pass
    return list(KNOWN_FILES.get(edition, []))


def fetch_edition(http: Http, edition: str) -> OwaspData:
    files = discover_files(http, edition)
    if not files:
        raise OwaspError(f"unknown OWASP edition {edition}")
    categories: Dict[str, str] = {}
    cwe_map: Dict[int, List[str]] = {}
    for fname in files:
        try:
            md = http.get_text(RAW_URL.format(edition=edition, file=fname))
        except HttpError as exc:
            raise OwaspError(f"cannot download {fname}: {exc}") from exc
        cat_id, name, cwes = parse_category(md)
        if not cat_id.endswith(f":{edition}"):
            raise OwaspError(f"{fname} is not an {edition} page ({cat_id})")
        categories[cat_id] = name
        for n in cwes:
            cwe_map.setdefault(n, []).append(cat_id)
    expected = {f"A{i:02d}:{edition}" for i in range(1, 11)}
    if set(categories) != expected or not all(cwe_map.values()):
        raise OwaspError(f"incomplete OWASP data: got {sorted(categories)}")
    for ids in cwe_map.values():
        ids.sort()
    return OwaspData(edition=edition, categories=categories, cwe_map=cwe_map,
                     fetched_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
                     origin="live")


def load_snapshot(edition: str) -> Optional[OwaspData]:
    path = SNAPSHOT_DIR / f"owasp_{edition}.json"
    try:
        return OwaspData.from_json(json.loads(path.read_text(encoding="utf-8")), "snapshot")
    except (OSError, ValueError, KeyError):
        return None


def get_owasp(edition: str, cache: Cache, http: Http, mode: str = "auto",
              log: Callable[[str], None] = lambda m: None) -> Tuple[OwaspData, List[str]]:
    """Load OWASP data. mode: 'auto' (refresh when older than 7 days), 'force', 'offline'.

    Always returns usable data (live > cache > bundled snapshot) plus warnings.
    """
    warnings: List[str] = []
    key = f"owasp:{edition}"

    if mode != "force":
        fresh = cache.get(key, max_age=None if mode == "offline" else CACHE_TTL)
        if fresh:
            return OwaspData.from_json(fresh, "cache"), warnings

    if mode != "offline":
        try:
            log(f"refreshing OWASP Top 10:{edition} mapping from OWASP source ...")
            data = fetch_edition(http, edition)
            cache.set(key, data.to_json())
            return data, warnings
        except OwaspError as exc:
            warnings.append(f"could not refresh OWASP {edition} data ({exc})")

    stale = cache.get(key)
    if stale:
        if mode != "offline":
            warnings.append("using the previously downloaded OWASP data instead")
        return OwaspData.from_json(stale, "cache"), warnings
    snap = load_snapshot(edition)
    if snap:
        if mode != "offline":
            warnings.append(f"using the OWASP {edition} snapshot bundled with vulnscan (from {snap.fetched_at[:10]})")
        return snap, warnings
    raise OwaspError(f"no OWASP {edition} data available (offline and no snapshot)")
