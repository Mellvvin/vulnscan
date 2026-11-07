"""Software vulnerability audit: inventory -> OSV match -> enrich -> OWASP-mapped findings."""

from __future__ import annotations

import importlib.util
import re
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Set, Tuple

from . import cwe as cwe_mod
from . import enrich, inventory, osv
from .cache import Cache
from .http import Http
from .inventory import InventoryError, Package, Runner, SystemInfo
from .models import Finding, Severity
from .owasp import DEFAULT_EDITION, EDITIONS, OwaspData, get_owasp
from .vercmp import pick_fixed

QUERY_TTL = 6 * 3600
SEV_BY_TEXT = {"CRITICAL": Severity.CRITICAL, "HIGH": Severity.HIGH,
               "MEDIUM": Severity.MEDIUM, "LOW": Severity.LOW}
EPSS_HIGH = 0.5


@dataclass
class AuditOptions:
    edition: str = DEFAULT_EDITION
    ecosystem: Optional[str] = None
    host: bool = True
    pip: bool = True
    npm: bool = True
    projects: List[str] = field(default_factory=list)
    docker: List[str] = field(default_factory=list)
    offline: bool = False
    refresh: str = "auto"  # auto | force
    max_cve_lookups: int = 3000


@dataclass
class TargetResult:
    info: SystemInfo
    packages: List[Package]
    findings: List[Finding] = field(default_factory=list)
    source_files: List[str] = field(default_factory=list)
    vulnerable_components: int = 0

    def to_dict(self) -> dict:
        managers: Dict[str, int] = {}
        for p in self.packages:
            managers[p.manager] = managers.get(p.manager, 0) + 1
        d = self.info.to_dict()
        d.update({"packages": len(self.packages), "by_manager": managers,
                  "vulnerable_components": self.vulnerable_components,
                  "source_files": self.source_files})
        return d


@dataclass
class AuditResult:
    targets: List[TargetResult]
    owasp: OwaspData
    warnings: List[str]
    sources: Dict[str, object]

    @property
    def findings(self) -> List[Finding]:
        return [f for t in self.targets for f in t.findings]


@dataclass
class _Group:
    target: TargetResult
    key: Tuple[str, str, str]  # ecosystem, osv name, osv version
    manager: str
    binaries: List[str]
    vulns: List[osv.VulnInfo] = field(default_factory=list)
    canonical: str = ""


def _gather_targets(opts: AuditOptions, runner: Runner, warnings: List[str],
                    log: Callable[[str], None]) -> List[TargetResult]:
    targets: List[TargetResult] = []
    if opts.host:
        info = inventory.local_system_info(opts.ecosystem)
        pkgs: List[Package] = []
        if info.kind == "host" and info.os_ecosystem:
            log(f"inventory: reading installed OS packages ({info.os_pretty or info.os_id}) ...")
            pkgs += inventory.collect_os_packages(info, runner)
        if opts.pip:
            if importlib.util.find_spec("pip") is None:
                info.notes.append("pip is not available for this interpreter; Python packages were not inventoried")
            else:
                pkgs += inventory.collect_pip(runner)
        if opts.npm:
            if not inventory.shutil.which("npm"):
                info.notes.append("npm not found; global npm packages were not inventoried")
            else:
                pkgs += inventory.collect_npm_global(runner)
        targets.append(TargetResult(info, pkgs))
    for image in opts.docker:
        log(f"inventory: inspecting container image {image} ...")
        try:
            info, pkgs = inventory.collect_docker_image(image, opts.ecosystem, runner)
            targets.append(TargetResult(info, pkgs))
        except InventoryError as exc:
            warnings.append(f"{image}: {exc}")
    for path in opts.projects:
        try:
            pkgs, files = inventory.collect_project(path)
        except InventoryError as exc:
            warnings.append(str(exc))
            continue
        info = SystemInfo(label=f"project:{path}", kind="project", os_pretty="dependency files")
        if not files:
            info.notes.append("no requirements*.txt, package-lock.json or Pipfile.lock found")
        targets.append(TargetResult(info, pkgs, source_files=files))
    return targets


def _short(text: str, limit: int) -> str:
    text = re.sub(r"\s+", " ", text).strip()
    return text if len(text) <= limit else text[: limit - 1].rstrip() + "…"


def _upgrade_command(manager: str, binaries: List[str], component: str, fixed: str, kind: str) -> str:
    names = " ".join(sorted(set(binaries)))
    if kind == "docker":
        return "docker build --pull --no-cache ...   # rebuild on an updated base image, then re-scan"
    if kind == "project":
        return f"update the pinned version of {component}" + (f" to >= {fixed}" if fixed else "") + \
               " in the dependency file, then reinstall"
    if manager == "dpkg":
        return f"sudo apt-get update && sudo apt-get install --only-upgrade {names}"
    if manager == "apk":
        return f"apk upgrade {names}"
    if manager == "rpm":
        return f"sudo dnf upgrade {names}"
    if manager == "pip":
        return f"python -m pip install --upgrade \"{component}" + (f">={fixed}" if fixed else "") + "\""
    if manager == "npm":
        return f"npm install -g {component}" + (f"@{fixed}" if fixed else "@latest")
    return ""


def _owasp_for(cwes: List[int], owasp: OwaspData, parents: Dict[int, List[int]],
               edition: str) -> Tuple[Tuple[str, str], str, str]:
    """Return ((id, name), basis, component_category_id)."""
    comp_id, comp_name = EDITIONS[edition]["supply_chain"]
    for n in cwes:
        hit = cwe_mod.resolve_owasp(n, owasp, parents)
        if hit:
            cat_id, matched, inherited = hit
            basis = f"CWE-{n}" + (f" (via parent CWE-{matched})" if inherited else "")
            return (cat_id, owasp.name(cat_id) or cat_id), basis, comp_id
    why = "no CWE published for this CVE" if not cwes else \
        "weakness class (" + ", ".join(f"CWE-{n}" for n in cwes[:3]) + ") is not on OWASP's CWE list"
    return (comp_id, comp_name), f"known-vulnerable component; {why}", comp_id


def run_audit(opts: AuditOptions, http: Http, cache: Cache, runner: Runner = inventory.default_runner,
              log: Callable[[str], None] = lambda m: None) -> AuditResult:
    warnings: List[str] = []
    mode = "offline" if opts.offline else ("force" if opts.refresh == "force" else "auto")

    owasp, w = get_owasp(opts.edition, cache, http, mode, log)
    warnings += w
    parents, w = cwe_mod.load_cwe_parents(cache, http, "offline" if opts.offline else "auto", log)
    warnings += w

    targets = _gather_targets(opts, runner, warnings, log)
    for t in targets:
        warnings += [f"{t.info.label}: {n}" for n in t.info.notes]

    # ---- 1. match every unique (ecosystem, name, version) against OSV ----------------------
    keys: List[Tuple[str, str, str]] = sorted({(p.ecosystem, p.osv_name, p.osv_version)
                                               for t in targets for p in t.packages})
    matches: Dict[Tuple[str, str, str], List[dict]] = {}
    to_query: List[Tuple[str, str, str]] = []
    for k in keys:
        hit = cache.get("osvq:" + "|".join(k), max_age=None if opts.offline else QUERY_TTL) \
            if opts.refresh != "force" else None
        if hit is not None:
            matches[k] = hit
        else:
            to_query.append(k)
    unchecked = 0
    if to_query and opts.offline:
        unchecked = len(to_query)
        warnings.append(f"offline mode: {unchecked} package versions had no cached OSV result and were not checked")
    elif to_query:
        log(f"matching {len(to_query)} package versions against OSV.dev ...")
        fresh, failed = osv.query_batch(http, to_query, log)
        failed_set = set(failed)
        for k, vulns in fresh.items():
            if k not in failed_set:
                matches[k] = vulns
                cache.set("osvq:" + "|".join(k), vulns)
        unchecked = len(failed_set)
        if unchecked:
            warnings.append(f"OSV.dev could not be queried for {unchecked} package versions; "
                            "results are INCOMPLETE (check connectivity and re-run)")

    # Canary: every supported release has advisories for openssl. If OSV answers with nothing, it has
    # no data for that release (typically end-of-life) and an empty result would be a false "clean".
    unsupported: List[str] = []
    canaries = sorted({(t.info.os_ecosystem, "openssl", "0") for t in targets if t.info.os_ecosystem
                       and any(p.manager in ("dpkg", "apk", "rpm") for p in t.packages)})
    for key in canaries:
        eco = key[0]
        covered = cache.get(f"osvcanary:{eco}", max_age=QUERY_TTL) if opts.refresh != "force" else None
        if covered is None and not opts.offline:
            canary_res, canary_failed = osv.query_batch(http, [key], log)
            if key in canary_failed:
                continue  # network trouble is already reported as incomplete elsewhere
            covered = bool(canary_res.get(key))
            cache.set(f"osvcanary:{eco}", covered)
        if covered is False:
            unsupported.append(eco)
            warnings.append(f"OSV.dev has no advisory data for {eco} (a canary lookup returned nothing), so "
                            "OS-package results for it are NOT reliable. This usually means the release is "
                            "end-of-life: upgrade the OS, or treat it as unpatched.")

    refs = {v["id"]: v.get("modified", "") for vs in matches.values() for v in vs if v.get("id")}
    records, failed_ids = osv.fetch_records(http, cache, refs, opts.offline, log)
    if failed_ids:
        warnings.append(f"{len(failed_ids)} vulnerability records could not be downloaded and were skipped")

    # ---- 2. group by (target, component, installed version) --------------------------------
    groups: List[_Group] = []
    for t in targets:
        by_key: Dict[Tuple[str, str, str], _Group] = {}
        for p in t.packages:
            k = (p.ecosystem, p.osv_name, p.osv_version)
            g = by_key.setdefault(k, _Group(t, k, p.manager, []))
            if p.name not in g.binaries:
                g.binaries.append(p.name)
        for k, g in by_key.items():
            vulns = [records[v["id"]] for v in matches.get(k, []) if v.get("id") in records]
            g.vulns = [v for v in vulns if not v.withdrawn]
            if g.vulns:
                groups.append(g)

    # merge records describing the same CVE (e.g. DEBIAN-CVE-x and CVE-x) per component
    merged: List[Tuple[_Group, str, List[osv.VulnInfo]]] = []
    for g in groups:
        buckets: Dict[str, List[osv.VulnInfo]] = {}
        for v in g.vulns:
            buckets.setdefault(v.canonical_id, []).append(v)
        for cid, vs in buckets.items():
            merged.append((g, cid, vs))

    # ---- 3. enrich -------------------------------------------------------------------------
    all_cves: Set[str] = {c for _g, _cid, vs in merged for v in vs for c in v.cves}
    need_record: Set[str] = set()
    for _g, _cid, vs in merged:
        if not any(v.cwes for v in vs) or all(v.cvss_score is None for v in vs):
            need_record.update(c for v in vs for c in v.cves)
    kev, kev_meta, w = enrich.load_kev(cache, http, opts.offline, log)
    warnings += w
    epss, w = enrich.load_epss(all_cves, cache, http, opts.offline, log)
    warnings += w
    cve_recs, w = enrich.load_cve_records(need_record, cache, http, opts.offline,
                                          opts.max_cve_lookups, log)
    warnings += w

    # ---- 4. build findings -----------------------------------------------------------------
    for g, cid, vs in merged:
        eco, comp, installed = g.key
        info = g.target.info
        cves = sorted({c for v in vs for c in v.cves})
        cwes: List[int] = []
        for n in [n for v in vs for n in v.cwes] + [n for c in cves for n in cve_recs.get(c, {}).get("cwes", [])]:
            if n not in cwes:
                cwes.append(n)

        score, vector = None, None
        for v in vs:
            if v.cvss_score is not None and (score is None or v.cvss_score > score):
                score, vector = v.cvss_score, v.cvss_vector
        for c in cves:
            rec = cve_recs.get(c, {})
            if rec.get("cvss") is not None and (score is None or rec["cvss"] > score):
                score, vector = rec["cvss"], rec.get("vector")

        sev: Optional[Severity] = None
        sev_source = "cvss"
        if score is not None:
            sev = Severity.CRITICAL if score >= 9 else Severity.HIGH if score >= 7 else \
                Severity.MEDIUM if score >= 4 else Severity.LOW
        else:
            texts = [SEV_BY_TEXT[v.severity_text] for v in vs if v.severity_text in SEV_BY_TEXT]
            if texts:
                sev, sev_source = max(texts), "advisory"
        unrated = sev is None
        if unrated:
            sev, sev_source = Severity.MEDIUM, "unrated (defaulted to Medium)"

        kev_hit = next((kev[c] | {"cve": c} for c in cves if c in kev), None)
        if kev_hit and sev < Severity.HIGH:
            sev, sev_source = Severity.HIGH, sev_source + "; raised: actively exploited (CISA KEV)"
        epss_score, epss_pct = max((epss[c] for c in cves if c in epss), default=(None, None))

        fixed = pick_fixed(installed, [f for v in vs for f in osv.fixed_versions(v, comp)], eco)
        (owasp_id, owasp_name), basis, comp_cat = _owasp_for(cwes, owasp, parents, opts.edition)

        summary = next((v.summary for v in vs if v.summary), "") or \
            _short(next((v.details for v in vs if v.details), ""), 140) or "vulnerability reported"
        details = _short(next((v.details for v in vs if v.details), ""), 600)
        refs_out: List[str] = []
        for c in cves[:3]:
            refs_out.append(f"https://nvd.nist.gov/vuln/detail/{c}")
        refs_out.append(f"https://osv.dev/vulnerability/{vs[0].id}")
        for u in [u for v in vs for u in v.references]:
            if u not in refs_out and len(refs_out) < 8:
                refs_out.append(u)

        cmd = _upgrade_command(g.manager, g.binaries, comp, fixed, info.kind)
        if fixed:
            remediation = f"Upgrade {comp} from {installed} to {fixed} or later."
        elif info.kind in ("docker", "project"):
            remediation = ("No fixed version is listed in the advisory data for this release. Check the "
                           "vendor tracker; consider a newer base image / dependency version.")
        else:
            remediation = ("No fixed version is published for this release in the advisory data (the "
                           "vendor may have deferred or declined it). Check the distribution security "
                           "tracker, apply vendor mitigations, or move to a supported release.")

        g.target.findings.append(Finding(
            host=info.label, port=None, check_id=f"{cid}:{comp}",
            title=f"{comp} {installed}: {cid} - {_short(summary, 110)}",
            severity=sev, category="supply_chain", cwe=f"CWE-{cwes[0]}" if cwes else "",
            description=_short(summary + (" " + details if details and details != summary else ""), 700),
            remediation=remediation + (f"  Run: {cmd}" if cmd else ""),
            evidence=f"installed {installed}; fixed in {fixed or 'n/a'}; advisory {vs[0].id}",
            owasp_override=(owasp_id, owasp_name),
            extra={
                "kind": "package", "source": info.kind, "component": comp, "installed": installed,
                "summary": _short(summary, 200),
                "fixed": fixed, "packages": sorted(g.binaries), "ecosystem": eco, "manager": g.manager,
                "cves": cves, "advisories": [v.id for v in vs], "cwes": [f"CWE-{n}" for n in cwes],
                "cvss": score, "cvss_vector": vector, "severity_basis": sev_source,
                "epss": epss_score, "epss_percentile": epss_pct,
                "kev": ({"added": kev_hit["added"], "due": kev_hit["due"], "ransomware": kev_hit["ransomware"],
                         "name": kev_hit["name"]} if kev_hit else None),
                "owasp_basis": basis, "owasp_component_category": comp_cat,
                "upgrade_command": cmd, "references": refs_out,
            }))

    for t in targets:
        t.vulnerable_components = len({f.extra["component"] for f in t.findings})

    sources = {
        "owasp": {"edition": opts.edition, "origin": owasp.origin, "fetched_at": owasp.fetched_at,
                  "source": owasp.source, "cwes_mapped": len(owasp.cwe_map)},
        "osv": {"package_versions": len(keys), "unchecked": unchecked, "records": len(records),
                "unavailable_records": len(failed_ids),
                "incomplete": bool(unchecked or failed_ids or unsupported),
                "unsupported_ecosystems": unsupported},
        "kev": kev_meta,
        "epss": {"cves_scored": len(epss)},
        "cve_org": {"records_used": len(cve_recs)},
        "cwe_hierarchy": {"entries": len(parents)},
    }
    return AuditResult(targets, owasp, warnings, sources)
