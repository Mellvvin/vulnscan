"""OSV.dev client: batch-match packages to vulnerabilities, fetch full records.

OSV (https://osv.dev) aggregates advisories for Debian, Ubuntu, Alpine, PyPI, npm,
GitHub Security Advisories and many more.  The API needs no key.
"""

from __future__ import annotations

import re
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Set, Tuple

from .cache import Cache
from .cvss import base_score_v3, severity_label
from .http import Http, HttpError
from .vercmp import pick_fixed

BATCH_URL = "https://api.osv.dev/v1/querybatch"
VULN_URL = "https://api.osv.dev/v1/vulns/{}"
BATCH_SIZE = 500
RECORD_TTL = 7 * 24 * 3600

QueryKey = Tuple[str, str, str]  # (ecosystem, name, version)

_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}")
_LABELS = {"critical": "CRITICAL", "high": "HIGH", "important": "HIGH", "moderate": "MEDIUM",
           "medium": "MEDIUM", "low": "LOW", "minor": "LOW", "negligible": "LOW",
           "unimportant": "LOW"}


@dataclass
class VulnInfo:
    id: str
    aliases: List[str]
    cves: List[str]
    summary: str
    details: str
    cwes: List[int]
    cvss_score: Optional[float]
    cvss_vector: Optional[str]
    severity_text: Optional[str]  # CRITICAL/HIGH/MEDIUM/LOW if the source states one
    references: List[str]
    published: str
    withdrawn: bool
    raw_affected: list = field(default_factory=list, repr=False)

    @property
    def canonical_id(self) -> str:
        return self.cves[0] if self.cves else self.id


def parse_vuln(rec: dict) -> VulnInfo:
    vid = rec.get("id", "")
    aliases = [a for a in rec.get("aliases", []) if isinstance(a, str)]
    related = [a for a in rec.get("related", []) if isinstance(a, str)]
    cves = sorted({m for s in [vid, *aliases, *related] for m in _CVE_RE.findall(s)})

    score: Optional[float] = None
    vector: Optional[str] = None
    text: Optional[str] = None
    for sev in rec.get("severity", []) or []:
        raw = str(sev.get("score", ""))
        if raw.startswith("CVSS:3"):
            s = base_score_v3(raw)
            if s is not None and (score is None or s > score):
                score, vector = s, raw
        elif raw.lower() in _LABELS and text is None:
            text = _LABELS[raw.lower()]
    dbs = rec.get("database_specific") or {}
    if text is None and isinstance(dbs.get("severity"), str):
        text = _LABELS.get(dbs["severity"].lower())
    if score is not None:
        text = severity_label(score)

    cwes: List[int] = []
    for item in dbs.get("cwe_ids", []) or []:
        m = re.search(r"(\d+)", str(item))
        if m and int(m.group(1)) not in cwes:
            cwes.append(int(m.group(1)))

    refs = [r["url"] for r in rec.get("references", []) or []
            if isinstance(r, dict) and str(r.get("url", "")).startswith(("http://", "https://"))]
    return VulnInfo(
        id=vid, aliases=aliases, cves=cves, summary=(rec.get("summary") or "").strip(),
        details=(rec.get("details") or "").strip(), cwes=cwes, cvss_score=score, cvss_vector=vector,
        severity_text=text, references=refs, published=rec.get("published", ""),
        withdrawn=bool(rec.get("withdrawn")), raw_affected=rec.get("affected", []) or [])


def _norm(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def fixed_versions(vuln: VulnInfo, name: str) -> List[str]:
    """All 'fixed' events recorded for the named package in this record."""
    matched: List[str] = []
    everything: List[str] = []
    for aff in vuln.raw_affected:
        pkg = aff.get("package") or {}
        fixes = [ev["fixed"] for rng in aff.get("ranges", []) or []
                 for ev in rng.get("events", []) or [] if "fixed" in ev]
        everything += fixes
        if _norm(pkg.get("name", "")) == _norm(name):
            matched += fixes
    return matched or everything


def best_fix(vuln: VulnInfo, name: str, installed: str, ecosystem: str) -> str:
    return pick_fixed(installed, fixed_versions(vuln, name), ecosystem)


# ------------------------------------------------------------------ network

def query_batch(http: Http, keys: List[QueryKey],
                log: Callable[[str], None] = lambda m: None) -> Tuple[Dict[QueryKey, List[dict]], List[QueryKey]]:
    """Return ({key: [{'id','modified'}...]}, keys whose lookup failed)."""
    results: Dict[QueryKey, List[dict]] = {k: [] for k in keys}
    failed: List[QueryKey] = []

    def q(key: QueryKey, token: Optional[str] = None) -> dict:
        eco, name, ver = key
        item = {"package": {"name": name, "ecosystem": eco}, "version": ver}
        if token:
            item["page_token"] = token
        return item

    for start in range(0, len(keys), BATCH_SIZE):
        chunk = keys[start:start + BATCH_SIZE]
        try:
            resp = http.post_json(BATCH_URL, {"queries": [q(k) for k in chunk]})
        except HttpError as exc:
            log(f"OSV batch {start}-{start + len(chunk)} failed: {exc}")
            failed.extend(chunk)
            continue
        for key, res in zip(chunk, resp.get("results", [])):
            results[key].extend(res.get("vulns", []) or [])
            token = res.get("next_page_token")
            while token:
                try:
                    more = http.post_json(BATCH_URL, {"queries": [q(key, token)]})["results"][0]
                except (HttpError, KeyError, IndexError):
                    failed.append(key)
                    break
                results[key].extend(more.get("vulns", []) or [])
                token = more.get("next_page_token")
        log(f"OSV: matched {min(start + BATCH_SIZE, len(keys))}/{len(keys)} package versions")
    return results, failed


def fetch_records(http: Http, cache: Cache, refs: Dict[str, str], offline: bool = False,
                  log: Callable[[str], None] = lambda m: None,
                  workers: int = 16) -> Tuple[Dict[str, VulnInfo], List[str]]:
    """Download (or load from cache) full OSV records. `refs` maps id -> modified timestamp."""
    records: Dict[str, VulnInfo] = {}
    todo: List[str] = []
    for vid, modified in refs.items():
        cached = cache.get(f"osv:{vid}", max_age=None if offline else RECORD_TTL)
        if cached and (not modified or cached.get("modified") == modified or offline):
            records[vid] = parse_vuln(cached["record"])
        else:
            todo.append(vid)
    failed: List[str] = []
    if not todo or offline:
        return records, (todo if offline else failed)

    done = 0

    def fetch(vid: str) -> Tuple[str, Optional[dict]]:
        try:
            return vid, http.get_json(VULN_URL.format(vid))
        except HttpError:
            return vid, None

    log(f"downloading {len(todo)} vulnerability records (cached afterwards) ...")
    with ThreadPoolExecutor(max_workers=workers) as pool:
        for vid, rec in pool.map(fetch, todo):
            done += 1
            if rec is None:
                failed.append(vid)
            else:
                cache.set(f"osv:{vid}", {"modified": refs.get(vid) or rec.get("modified"), "record": rec})
                records[vid] = parse_vuln(rec)
            if done % 200 == 0:
                log(f"  {done}/{len(todo)} records")
    return records, failed
