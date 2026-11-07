"""Version comparison, used to pick the right 'fixed in' version for a finding.

Debian/Ubuntu versions use the dpkg algorithm; everything else uses a generic
dotted-version comparison.  Comparison only chooses which fix to display; which
vulnerabilities apply is decided by OSV, not by us.
"""

from __future__ import annotations

import re
from typing import List, Tuple


def _order(c: str) -> int:
    if c.isdigit():
        return 0
    if c.isalpha():
        return ord(c)
    if c == "~":
        return -1
    return ord(c) + 256


def _dpkg_part(a: str, b: str) -> int:
    i = j = 0
    while i < len(a) or j < len(b):
        while (i < len(a) and not a[i].isdigit()) or (j < len(b) and not b[j].isdigit()):
            ac = _order(a[i]) if i < len(a) else 0
            bc = _order(b[j]) if j < len(b) else 0
            if ac != bc:
                return -1 if ac < bc else 1
            i += 1
            j += 1
        while i < len(a) and a[i] == "0":
            i += 1
        while j < len(b) and b[j] == "0":
            j += 1
        diff = 0
        while i < len(a) and a[i].isdigit() and j < len(b) and b[j].isdigit():
            if not diff:
                diff = ord(a[i]) - ord(b[j])
            i += 1
            j += 1
        if i < len(a) and a[i].isdigit():
            return 1
        if j < len(b) and b[j].isdigit():
            return -1
        if diff:
            return -1 if diff < 0 else 1
    return 0


def _split_dpkg(v: str) -> Tuple[int, str, str]:
    epoch = 0
    if ":" in v:
        e, v = v.split(":", 1)
        epoch = int(e) if e.isdigit() else 0
    if "-" in v:
        upstream, revision = v.rsplit("-", 1)
    else:
        upstream, revision = v, ""
    return epoch, upstream, revision


def dpkg_compare(a: str, b: str) -> int:
    ea, ua, ra = _split_dpkg(a)
    eb, ub, rb = _split_dpkg(b)
    if ea != eb:
        return -1 if ea < eb else 1
    return _dpkg_part(ua, ub) or _dpkg_part(ra, rb)


def _tokens(v: str) -> List[object]:
    v = re.sub(r"^\d+:", "", v)
    return [int(t) if t.isdigit() else t.lower() for t in re.findall(r"\d+|[A-Za-z]+", v)]


def generic_compare(a: str, b: str) -> int:
    ta, tb = _tokens(a), _tokens(b)
    for x, y in zip(ta, tb):
        if x == y:
            continue
        if isinstance(x, int) and isinstance(y, int):
            return -1 if x < y else 1
        if isinstance(x, int):  # number beats pre-release word
            return 1
        if isinstance(y, int):
            return -1
        return -1 if x < y else 1
    if len(ta) == len(tb):
        return 0
    longer_is_a = len(ta) > len(tb)
    extra = (ta if longer_is_a else tb)[min(len(ta), len(tb))]
    # "1.0rc1" < "1.0": a trailing word marks a pre-release; a trailing number is newer.
    newer = isinstance(extra, int) or extra in ("post", "p", "r")
    if longer_is_a:
        return 1 if newer else -1
    return -1 if newer else 1


def compare(a: str, b: str, ecosystem: str) -> int:
    if ecosystem.startswith(("Debian", "Ubuntu")):
        return dpkg_compare(a, b)
    return generic_compare(a, b)


def pick_fixed(installed: str, candidates: List[str], ecosystem: str) -> str:
    """Smallest candidate strictly greater than the installed version ('' if none)."""
    newer = [c for c in set(candidates) if c and compare(c, installed, ecosystem) > 0]
    if not newer:
        return ""
    best = newer[0]
    for c in newer[1:]:
        if compare(c, best, ecosystem) < 0:
            best = c
    return best
