"""Enrichment from public sources, all cached and all optional (the audit still works
if any of them is unreachable):

* CISA Known Exploited Vulnerabilities (KEV)  - "is this being exploited right now?"
* FIRST EPSS                                  - probability of exploitation in the next 30 days
* CVE.org records (cvelistV5)                 - CWE and CVSS for CVEs that OSV lacks them for
"""

from __future__ import annotations

import re
from concurrent.futures import ThreadPoolExecutor
from typing import Callable, Dict, Iterable, List, Optional, Tuple

from .cache import Cache
from .http import Http, HttpError

KEV_URLS = [
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
    "https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json",
]
EPSS_URL = "https://api.first.org/data/v1/epss?cve={}"
CVE_URL = "https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/{year}/{bucket}xxx/{cve}.json"

KEV_TTL = 24 * 3600
EPSS_TTL = 24 * 3600
CVE_TTL = 7 * 24 * 3600
_CVE_ID = re.compile(r"CVE-(\d{4})-(\d{4,})")


def load_kev(cache: Cache, http: Http, offline: bool = False,
             log: Callable[[str], None] = lambda m: None) -> Tuple[Dict[str, dict], dict, List[str]]:
    """Return ({cve: entry}, meta, warnings)."""
    warnings: List[str] = []
    cached = cache.get("kev", max_age=None if offline else KEV_TTL)
    if cached:
        return cached["entries"], dict(cached["meta"], origin="cache"), warnings
    if not offline:
        for url in KEV_URLS:
            try:
                log("downloading CISA Known Exploited Vulnerabilities catalog ...")
                doc = http.get_json(url)
                entries = {v["cveID"]: {
                    "added": v.get("dateAdded", ""), "due": v.get("dueDate", ""),
                    "name": v.get("vulnerabilityName", ""), "vendor": v.get("vendorProject", ""),
                    "product": v.get("product", ""), "ransomware": v.get("knownRansomwareCampaignUse", ""),
                    "cwes": v.get("cwes", []), "action": v.get("requiredAction", "")}
                    for v in doc["vulnerabilities"]}
                meta = {"version": doc.get("catalogVersion", ""), "released": doc.get("dateReleased", ""),
                        "count": len(entries)}
                cache.set("kev", {"entries": entries, "meta": meta})
                return entries, dict(meta, origin="live"), warnings
            except (HttpError, KeyError, TypeError):
                continue
        warnings.append("CISA KEV catalog could not be downloaded; exploited-in-the-wild flags unavailable")
    stale = cache.get("kev")
    if stale:
        return stale["entries"], dict(stale["meta"], origin="cache (stale)"), warnings
    return {}, {"origin": "unavailable"}, warnings


def load_epss(cves: Iterable[str], cache: Cache, http: Http, offline: bool = False,
              log: Callable[[str], None] = lambda m: None) -> Tuple[Dict[str, Tuple[float, float]], List[str]]:
    """Return ({cve: (epss, percentile)}, warnings)."""
    warnings: List[str] = []
    out: Dict[str, Tuple[float, float]] = {}
    missing: List[str] = []
    for cve in sorted(set(cves)):
        hit = cache.get(f"epss:{cve}", max_age=None if offline else EPSS_TTL)
        if hit is not None:
            if hit:
                out[cve] = (hit[0], hit[1])
        else:
            missing.append(cve)
    if offline or not missing:
        return out, warnings
    log(f"fetching EPSS scores for {len(missing)} CVEs ...")
    failed = False
    for i in range(0, len(missing), 100):
        chunk = missing[i:i + 100]
        try:
            doc = http.get_json(EPSS_URL.format(",".join(chunk)))
            seen = set()
            for row in doc.get("data", []):
                score, pct = float(row["epss"]), float(row["percentile"])
                out[row["cve"]] = (score, pct)
                cache.set(f"epss:{row['cve']}", [score, pct])
                seen.add(row["cve"])
            for cve in chunk:  # CVEs EPSS does not know: remember that for a day
                if cve not in seen:
                    cache.set(f"epss:{cve}", [])
        except (HttpError, KeyError, ValueError, TypeError):
            failed = True
    if failed:
        warnings.append("EPSS scores were not available for some CVEs")
    return out, warnings


def cve_record_url(cve: str) -> Optional[str]:
    m = _CVE_ID.fullmatch(cve)
    if not m:
        return None
    return CVE_URL.format(year=m.group(1), bucket=int(m.group(2)) // 1000, cve=cve)


def parse_cve_record(doc: dict) -> dict:
    """Extract CWE ids and the best CVSS v3 score from a CVE JSON 5 record."""
    containers = [doc.get("containers", {}).get("cna", {})] + list(doc.get("containers", {}).get("adp", []))
    cwes: List[int] = []
    for c in containers:
        for pt in c.get("problemTypes", []) or []:
            for d in pt.get("descriptions", []) or []:
                found = d.get("cweId") or ""
                m = re.search(r"CWE-(\d+)", found) or re.search(r"CWE-(\d+)", d.get("description", ""))
                if m and int(m.group(1)) not in cwes:
                    cwes.append(int(m.group(1)))
    score: Optional[float] = None
    vector: Optional[str] = None
    for key in ("cvssV3_1", "cvssV3_0"):
        for c in containers:
            for metric in c.get("metrics", []) or []:
                m = metric.get(key)
                if m and m.get("baseScore") is not None:
                    score, vector = float(m["baseScore"]), m.get("vectorString")
                    break
            if score is not None:
                break
        if score is not None:
            break
    rejected = doc.get("cveMetadata", {}).get("state") == "REJECTED"
    return {"cwes": cwes, "cvss": score, "vector": vector, "rejected": rejected}


def load_cve_records(cves: Iterable[str], cache: Cache, http: Http, offline: bool = False,
                     limit: int = 3000, log: Callable[[str], None] = lambda m: None,
                     workers: int = 12) -> Tuple[Dict[str, dict], List[str]]:
    """Return ({cve: {'cwes','cvss','vector'}}, warnings) for CVEs that need CWE/CVSS data."""
    warnings: List[str] = []
    out: Dict[str, dict] = {}
    todo: List[str] = []
    for cve in sorted(set(cves)):
        hit = cache.get(f"cve:{cve}", max_age=None if offline else CVE_TTL)
        if hit is not None:
            if hit:
                out[cve] = hit
        else:
            todo.append(cve)
    if offline or not todo:
        return out, warnings
    if len(todo) > limit:
        warnings.append(f"CWE/CVSS enrichment limited to {limit} of {len(todo)} CVEs "
                        "(re-run to continue; results are cached)")
        todo = todo[:limit]
    log(f"looking up {len(todo)} CVE records on CVE.org (cached afterwards) ...")

    def fetch(cve: str) -> Tuple[str, Optional[dict], bool]:
        url = cve_record_url(cve)
        if not url:
            return cve, {}, True
        try:
            return cve, parse_cve_record(http.get_json(url)), True
        except HttpError as exc:
            return cve, None, exc.status == 404  # 404: not published there; anything else: retry later

    failures = 0
    done = 0
    with ThreadPoolExecutor(max_workers=workers) as pool:
        for cve, rec, definitive in pool.map(fetch, todo):
            done += 1
            if rec is None:
                if definitive:
                    cache.set(f"cve:{cve}", {})
                else:
                    failures += 1
                continue
            cache.set(f"cve:{cve}", rec)
            if rec and not rec.get("rejected"):
                out[cve] = rec
            if done % 200 == 0:
                log(f"  {done}/{len(todo)} CVE records")
    if failures:
        warnings.append(f"{failures} CVE records could not be fetched from CVE.org")
    return out, warnings
