"""CWE hierarchy, used to map specific weaknesses to OWASP categories.

OWASP lists a limited set of CWEs per category, but CVEs are often filed under
a more specific child (e.g. CWE-121 'Stack-based Buffer Overflow').  MITRE's
catalog records ChildOf relations; walking up them lets us find the OWASP
category of the nearest listed ancestor.
"""

from __future__ import annotations

import io
import zipfile
from typing import Callable, Dict, List, Optional, Tuple
from xml.etree import ElementTree as ET

from .cache import Cache
from .http import Http, HttpError
from .owasp import OwaspData

CWE_URL = "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip"
CACHE_KEY = "cwe:parents"
CACHE_TTL = 30 * 24 * 3600
RESEARCH_VIEW = "1000"


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def parse_cwe_xml(xml_bytes: bytes) -> Dict[int, List[int]]:
    """Return {cwe_id: [parent ids]} using ChildOf links in the Research Concepts view."""
    parents: Dict[int, List[int]] = {}
    for _event, elem in ET.iterparse(io.BytesIO(xml_bytes), events=("end",)):
        if _local(elem.tag) != "Weakness":
            continue
        try:
            cwe_id = int(elem.attrib["ID"])
        except (KeyError, ValueError):
            elem.clear()
            continue
        for rel in elem.iter():
            if _local(rel.tag) != "Related_Weakness":
                continue
            if rel.attrib.get("Nature") == "ChildOf" and rel.attrib.get("View_ID") == RESEARCH_VIEW:
                try:
                    parents.setdefault(cwe_id, []).append(int(rel.attrib["CWE_ID"]))
                except (KeyError, ValueError):
                    pass
        elem.clear()
    return parents


def fetch_cwe_parents(http: Http) -> Dict[int, List[int]]:
    raw = http.get_bytes(CWE_URL)
    with zipfile.ZipFile(io.BytesIO(raw)) as zf:
        name = next((n for n in zf.namelist() if n.lower().endswith(".xml")), None)
        if not name:
            raise HttpError("CWE archive contained no XML file")
        return parse_cwe_xml(zf.read(name))


def load_cwe_parents(cache: Cache, http: Http, mode: str = "auto",
                     log: Callable[[str], None] = lambda m: None) -> Tuple[Dict[int, List[int]], List[str]]:
    warnings: List[str] = []
    cached = cache.get(CACHE_KEY, max_age=None if mode == "offline" else CACHE_TTL)
    if cached:
        return {int(k): v for k, v in cached.items()}, warnings
    if mode != "offline":
        try:
            log("downloading MITRE CWE hierarchy ...")
            parents = fetch_cwe_parents(http)
            if parents:
                cache.set(CACHE_KEY, {str(k): v for k, v in parents.items()})
                return parents, warnings
            warnings.append("CWE catalog parsed but contained no hierarchy")
        except (HttpError, zipfile.BadZipFile, ET.ParseError) as exc:
            warnings.append(f"CWE hierarchy unavailable ({exc}); only direct CWE-to-OWASP matches used")
    stale = cache.get(CACHE_KEY)
    if stale:
        return {int(k): v for k, v in stale.items()}, warnings
    return {}, warnings


def resolve_owasp(cwe: int, owasp: OwaspData, parents: Dict[int, List[int]],
                  max_depth: int = 10) -> Optional[Tuple[str, int, bool]]:
    """Find the OWASP category for a CWE.

    Returns (category_id, matched_cwe, inherited) where `inherited` is True when the
    category was found on an ancestor rather than on the CWE itself.
    """
    direct = owasp.categories_for(cwe)
    if direct:
        return direct[0], cwe, False
    frontier = [cwe]
    seen = {cwe}
    for _ in range(max_depth):
        nxt: List[int] = []
        for node in frontier:
            for parent in parents.get(node, []):
                if parent in seen:
                    continue
                seen.add(parent)
                cats = owasp.categories_for(parent)
                if cats:
                    return cats[0], parent, True
                nxt.append(parent)
        if not nxt:
            break
        frontier = nxt
    return None
