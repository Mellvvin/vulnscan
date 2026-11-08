from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
import tempfile
import time
from datetime import datetime, timezone
from typing import List, Optional

from . import __version__
from .cache import Cache
from .http import Http, HttpError
from .models import Finding, HostResult, Severity
from .output import ensure_dir, sort_findings, write_json, write_tsv
from .owasp import DEFAULT_EDITION, EDITIONS, OwaspError, get_owasp, fetch_edition, SNAPSHOT_DIR, lookup
from .portscan import parse_ports
from .scanner import ScanConfig, scan_host
from .scope import ScopeError, check_authorization, expand_targets

SEVERITIES = [s.name.lower() for s in sorted(Severity)]
COMMANDS = ("scan", "audit", "update", "report", "doctor", "engage")

COLORS = {"CRITICAL": "\033[1;97;41m", "HIGH": "\033[1;31m", "MEDIUM": "\033[33m",
          "LOW": "\033[36m", "INFO": "\033[2m"}
RESET = "\033[0m"


def _log(quiet: bool):
    def log(msg: str) -> None:
        if not quiet:
            print(f"[*] {msg}", file=sys.stderr, flush=True)
    return log


# ------------------------------------------------------------------ parsers

def _common(p: argparse.ArgumentParser) -> None:
    p.add_argument("-o", "--out-dir", help="output directory (default: reports/<timestamp>)")
    p.add_argument("--owasp-edition", choices=sorted(EDITIONS), default=DEFAULT_EDITION,
                   help=f"OWASP Top 10 edition used in reports (default {DEFAULT_EDITION})")
    p.add_argument("--min-severity", choices=SEVERITIES, default="info",
                   help="drop findings below this severity")
    p.add_argument("--fail-on", choices=SEVERITIES[1:],
                   help="exit with status 2 if any finding at or above this severity exists (CI use)")
    p.add_argument("--include-data", action="store_true",
                   help="also save results.json and findings.tsv (default: report files only)")
    p.add_argument("--no-report", action="store_true", help="write results.json/findings.tsv only")
    p.add_argument("-q", "--quiet", action="store_true", help="suppress progress output")


def _net_args(p: argparse.ArgumentParser) -> None:
    p.add_argument("-p", "--ports", default="top",
                   help="'top' (default), 'all', or a list/range such as 22,80,8000-8100")
    p.add_argument("--timeout", type=float, default=1.0, help="per-connection timeout in seconds")
    p.add_argument("--threads", type=int, default=200, help="concurrent connections per host")
    p.add_argument("--no-web", action="store_true", help="skip HTTP(S) application checks")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="vulnscan",
        description="Finds known vulnerabilities in what is installed (audit) and risky exposure on the "
                    "network (scan), and maps them to the OWASP Top 10. "
                    "For systems you own or are explicitly authorized to test.")
    p.add_argument("--version", action="version", version=f"vulnscan {__version__}")
    sub = p.add_subparsers(dest="command", required=True, metavar="{audit,scan,update,report,doctor,engage}")

    a = sub.add_parser("audit", help="find known vulnerabilities in installed software (this machine, "
                                     "Docker images, project dependency files)")
    _common(a)
    _net_args(a)
    a.add_argument("--docker", action="append", default=[], metavar="IMAGE",
                   help="also audit a container image (repeatable), e.g. --docker nginx:1.18")
    a.add_argument("--project", action="append", default=[], metavar="DIR",
                   help="also audit dependency files under DIR (requirements.txt, package-lock.json, "
                        "Pipfile.lock); repeatable")
    a.add_argument("--no-host", action="store_true", help="do not audit this machine's own packages")
    a.add_argument("--no-pip", action="store_true", help="skip Python packages of this interpreter")
    a.add_argument("--no-npm", action="store_true", help="skip global npm packages")
    a.add_argument("--no-network", action="store_true",
                   help="skip the exposure scan of this machine's own listening services (127.0.0.1)")
    a.add_argument("--ecosystem", metavar="NAME",
                   help="override OSV ecosystem for OS packages, e.g. Debian:12 or Ubuntu:22.04:LTS "
                        "(needed for derivatives such as Kali or Mint)")
    a.add_argument("--offline", action="store_true", help="use cached data only; no network access")
    a.add_argument("--refresh", action="store_true",
                   help="force re-download of OWASP data and re-query every package")
    a.add_argument("--max-cve-lookups", type=int, default=3000,
                   help="cap on CVE.org lookups per run for missing CWE/CVSS data (default 3000)")
    a.set_defaults(func=cmd_audit)

    s = sub.add_parser("scan", help="scan hosts for exposed services, TLS and web misconfigurations")
    s.add_argument("targets", nargs="+", help="IP, hostname, CIDR range, or a file with one target per line")
    _net_args(s)
    _common(s)
    s.add_argument("--allow-public", action="store_true",
                   help="permit publicly routable targets (requires written authorization)")
    s.set_defaults(func=cmd_scan)

    u = sub.add_parser("update", help="refresh OWASP, exploited-vulnerability and CWE data")
    u.add_argument("--write-snapshot", action="store_true",
                   help="(maintainers) also rewrite the bundled offline OWASP snapshot")
    u.set_defaults(func=cmd_update)

    r = sub.add_parser("report", help="(re)build report.html / report.md from one or more result folders")
    r.add_argument("results", nargs="+", help="results.json files or the folders containing them")
    r.add_argument("-o", "--out-dir", help="where to write the merged report (default: first folder)")
    r.set_defaults(func=cmd_report)

    d = sub.add_parser("doctor", help="check connectivity to every data source and tool availability")
    d.set_defaults(func=cmd_doctor)

    from . import engage_cli
    engage_cli.add_parser(sub)
    return p


# ------------------------------------------------------------------ shared output

def _print_summary(findings: List[Finding], edition: str, out_dir: str, duration: float,
                   quiet: bool, limit: int = 15) -> None:
    use_color = sys.stdout.isatty()
    ordered = sort_findings(findings)
    shown = [f for f in ordered if f.severity > Severity.INFO]
    print()
    for f in shown[:limit]:
        sev = f.severity.name
        tag = f"{COLORS[sev]}{sev:<8}{RESET}" if use_color else f"{sev:<8}"
        where = f"{f.host}:{f.port}" if f.port else f.host
        oid = f.to_dict(edition)["owasp"]
        kev = " [EXPLOITED]" if f.extra.get("kev") else ""
        print(f"{tag} {oid}  {where[:24]:<24} {f.title[:70]}{kev}")
    if len(shown) > limit:
        print(f"... and {len(shown) - limit} more (see the report)")
    counts = {s.name: sum(1 for f in findings if f.severity == s) for s in sorted(Severity, reverse=True)}
    print()
    print("Summary: " + "  ".join(f"{k}={v}" for k, v in counts.items()))
    print(f"Done in {duration:.1f}s -> {out_dir}")


def _finish(args, out_dir: str, started: datetime, t0: float, hosts: List[HostResult],
            findings: List[Finding], meta: dict, extra: Optional[dict] = None) -> int:
    ensure_dir(out_dir)
    if args.no_report or args.include_data:
        write_json(os.path.join(out_dir, "results.json"), meta, hosts, findings, args.owasp_edition, extra)
        write_tsv(os.path.join(out_dir, "findings.tsv"), findings, args.owasp_edition)

    if not args.no_report:
        from .report import load_results, write_reports
        if args.include_data:
            report_source = out_dir
            write_reports(out_dir, [load_results(report_source)])
        else:
            # Keep the normal output folder focused on the reports. JSON is an
            # intermediate for rendering and is discarded after the report is built.
            for name in ("results.json", "findings.tsv"):
                try:
                    os.remove(os.path.join(out_dir, name))
                except FileNotFoundError:
                    pass
            with tempfile.TemporaryDirectory(prefix="vulnscan-") as work_dir:
                result_path = os.path.join(work_dir, "results.json")
                write_json(result_path, meta, hosts, findings, args.owasp_edition, extra)
                write_reports(out_dir, [load_results(result_path)])

    _print_summary(findings, args.owasp_edition, out_dir, time.monotonic() - t0, args.quiet)
    if not args.no_report:
        print(f"Open: {os.path.join(out_dir, 'report.html')}")
    if args.fail_on:
        threshold = Severity.parse(args.fail_on)
        if any(f.severity >= threshold for f in findings):
            return 2
    return 0


def _out_dir(args, started: datetime) -> str:
    return args.out_dir or os.path.join("reports", started.strftime("%Y%m%d-%H%M%S"))


# ------------------------------------------------------------------ scan

def _network_scan(targets, args, quiet: bool):
    cfg = ScanConfig(ports=parse_ports(args.ports), timeout=args.timeout, threads=args.threads,
                     web=not args.no_web)
    hosts = []
    for target in targets:
        if not quiet:
            print(f"[*] scanning {target.label} ({len(cfg.ports)} ports)", file=sys.stderr)
        hosts.append(scan_host(target, cfg, quiet=quiet))
    return hosts, cfg


def cmd_scan(args) -> int:
    try:
        parse_ports(args.ports)
        targets = expand_targets(args.targets)
        public = check_authorization(targets, args.allow_public)
    except (ScopeError, ValueError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    if public and not args.quiet:
        print("[!] --allow-public set: ensure you hold written authorization for these targets.",
              file=sys.stderr)

    started = datetime.now(timezone.utc)
    t0 = time.monotonic()
    hosts, cfg = _network_scan(targets, args, args.quiet)
    min_sev = Severity.parse(args.min_severity)
    findings = [f for h in hosts for f in h.findings if f.severity >= min_sev]
    meta = {"started": started.isoformat(timespec="seconds"),
            "duration_seconds": round(time.monotonic() - t0, 2),
            "targets": [t.label for t in targets], "ports_per_host": len(cfg.ports),
            "hosts_with_open_ports": sum(1 for h in hosts if h.ports), "mode": "scan"}
    skipped = ["UDP services are not tested", "TCP ports outside the selected port set are not tested"]
    if not cfg.web:
        skipped.append("HTTP(S) application checks disabled by --no-web")
    coverage = {"network": {
        "status": "completed", "scanner_vantage": "this machine", "method": "TCP connect",
        "requested_ports": args.ports, "selected_tcp_ports_per_host": len(cfg.ports),
        "open_tcp_ports": sum(len(h.ports) for h in hosts),
        "web_checks": "enabled" if cfg.web else "disabled", "skipped_checks": skipped,
        "limitations": ["Reachability is confirmed only from this scanner's vantage point.",
                        "Connectivity from another LAN client was not tested.",
                        "A public-routable target does not prove access from the public internet."]}}
    return _finish(args, _out_dir(args, started), started, t0, hosts, findings, meta,
                   {"coverage": coverage})


# ------------------------------------------------------------------ audit

def cmd_audit(args) -> int:
    from .audit import AuditOptions, run_audit
    from .owasp import OwaspError

    started = datetime.now(timezone.utc)
    t0 = time.monotonic()
    log = _log(args.quiet)
    http, cache = Http(), Cache()
    opts = AuditOptions(edition=args.owasp_edition, ecosystem=args.ecosystem, host=not args.no_host,
                        pip=not args.no_pip, npm=not args.no_npm, projects=args.project,
                        docker=args.docker, offline=args.offline,
                        refresh="force" if args.refresh else "auto",
                        max_cve_lookups=args.max_cve_lookups)
    if args.offline and not cache.persistent:
        print("error: --offline needs a writable cache from an earlier online run", file=sys.stderr)
        return 1
    try:
        result = run_audit(opts, http, cache, log=log)
    except OwaspError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    findings: List[Finding] = list(result.findings)
    hosts: List[HostResult] = []
    warnings = list(result.warnings)
    host_target = next((t for t in result.targets if t.info.kind == "host"), None)
    network_coverage = {"status": "not_run", "target": None, "scope": None,
                        "method": "TCP connect", "selected_tcp_ports": 0, "open_tcp_ports": 0,
                        "web_checks": "not_run", "skipped_checks": []}
    if host_target is None:
        network_coverage["status"] = "not_applicable"
        network_coverage["skipped_checks"].extend([
            "local service exposure scan: no host target was included (project/image-only or --no-host)",
            "LAN/public reachability from other vantage points is not tested by this audit",
        ])
        if args.no_web:
            network_coverage["skipped_checks"].append("HTTP(S) application checks disabled by --no-web")
    elif args.no_network:
        network_coverage["skipped_checks"].extend([
            "local service exposure scan disabled by --no-network",
            "LAN/public reachability from other vantage points is not tested by this audit",
        ])
        if args.no_web:
            network_coverage["skipped_checks"].append("HTTP(S) application checks disabled by --no-web")
    else:
        try:
            targets = expand_targets(["127.0.0.1"])
            log("checking this machine's listening services on localhost (127.0.0.1) ...")
            hosts, cfg = _network_scan(targets, args, args.quiet)
            network_coverage.update({"status": "completed", "target": "127.0.0.1",
                                     "scope": "localhost", "scanner_vantage": "local host",
                                     "requested_ports": args.ports,
                                     "selected_tcp_ports": len(cfg.ports),
                                     "open_tcp_ports": sum(len(h.ports) for h in hosts),
                                     "web_checks": "enabled" if cfg.web else "disabled",
                                     "limitations": ["Only localhost was tested; service bind addresses and remote-client reachability were not inspected."]})
            network_coverage["skipped_checks"].extend([
                "LAN-interface reachability: not tested by the localhost-only audit scan",
                "Public reachability: not tested by the localhost-only audit scan",
                "UDP services are not tested",
                "TCP ports outside the selected port set are not tested",
            ])
            if not cfg.web:
                network_coverage["skipped_checks"].append("HTTP(S) application checks disabled by --no-web")
            warnings.append("local service scan tested 127.0.0.1 only; it does not establish LAN or public reachability")
            for h in hosts:
                for f in h.findings:
                    f.host = host_target.info.label  # report under the machine's own name
                    host_target.findings.append(f)
                    findings.append(f)
        except (ScopeError, ValueError, OSError) as exc:
            network_coverage["status"] = "failed"
            network_coverage["skipped_checks"].append(f"local service exposure scan failed: {exc}")
            warnings.append(f"local exposure scan skipped: {exc}")

    min_sev = Severity.parse(args.min_severity)
    findings = [f for f in findings if f.severity >= min_sev]
    meta = {"started": started.isoformat(timespec="seconds"),
            "duration_seconds": round(time.monotonic() - t0, 2),
            "targets": [t.info.label for t in result.targets], "mode": "audit"}
    package_skipped = []
    if args.no_host:
        package_skipped.append("local host software inventory disabled by --no-host")
    if args.no_pip:
        package_skipped.append("current-interpreter Python package inventory disabled by --no-pip")
    if args.no_npm:
        package_skipped.append("global npm package inventory disabled by --no-npm")
    package_targets = []
    for target in result.targets:
        managers = {}
        for package in target.packages:
            managers[package.manager] = managers.get(package.manager, 0) + 1
        package_targets.append({"label": target.info.label, "kind": target.info.kind,
                                "packages_discovered": len(target.packages), "by_manager": managers,
                                "skipped_checks": list(target.info.notes)})
    coverage = {
        "package_audit": {"targets": package_targets,
                           "package_versions": result.sources["osv"]["package_versions"],
                           "unchecked_package_versions": result.sources["osv"]["unchecked"],
                           "unavailable_advisory_records": result.sources["osv"]["unavailable_records"],
                           "unsupported_ecosystems": result.sources["osv"]["unsupported_ecosystems"],
                           "skipped_checks": package_skipped},
        "network": network_coverage,
    }
    extra = {"systems": [t.to_dict() for t in result.targets], "sources": result.sources,
             "warnings": warnings, "coverage": coverage}
    if not result.targets:
        print("error: nothing to audit (all targets disabled or unreadable)", file=sys.stderr)
        for w in warnings:
            print(f"  - {w}", file=sys.stderr)
        return 1
    rc = _finish(args, _out_dir(args, started), started, t0, hosts, findings, meta, extra)
    for w in dict.fromkeys(warnings):
        print(f"note: {w}", file=sys.stderr)
    if result.sources["osv"]["incomplete"]:
        print("WARNING: vulnerability data was incomplete; this result must not be treated as clean.",
              file=sys.stderr)
        return max(rc, 3)
    return rc


# ------------------------------------------------------------------ update / report / doctor

def cmd_update(args) -> int:
    from . import cwe as cwe_mod
    from . import enrich
    http, cache = Http(), Cache()
    ok = True
    for edition in sorted(EDITIONS):
        try:
            data = fetch_edition(http, edition)
            cache.set(f"owasp:{edition}", data.to_json())
            print(f"OWASP Top 10:{edition}: {len(data.categories)} categories, {len(data.cwe_map)} CWEs mapped")
            if args.write_snapshot:
                path = SNAPSHOT_DIR / f"owasp_{edition}.json"
                path.write_text(json.dumps(data.to_json(), indent=1) + "\n", encoding="utf-8")
                print(f"  snapshot written: {path}")
        except OwaspError as exc:
            ok = False
            print(f"OWASP Top 10:{edition}: FAILED ({exc})")
    kev, meta, warns = enrich.load_kev(cache, http, offline=False)
    print(f"CISA KEV: {meta.get('count', 0)} entries, catalog {meta.get('version', '?')} ({meta.get('origin')})")
    parents, warns2 = cwe_mod.load_cwe_parents(cache, http, "auto")
    print(f"CWE hierarchy: {len(parents)} weaknesses")
    for w in warns + warns2:
        ok = False
        print(f"  warning: {w}")
    print(f"Cache: {cache.root}")
    return 0 if ok else 1


def cmd_report(args) -> int:
    from .report import load_results, write_reports
    try:
        docs = [load_results(p) for p in args.results]
    except (OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    first = args.results[0]
    out_dir = args.out_dir or (first if os.path.isdir(first) else os.path.dirname(first) or ".")
    ensure_dir(out_dir)
    for path in write_reports(out_dir, docs):
        print(path)
    return 0


def cmd_doctor(args) -> int:
    from . import cwe as cwe_mod
    from . import enrich, inventory, osv
    from .owasp import parse_category, RAW_URL, KNOWN_FILES
    http = Http(timeout=25, retries=1)
    results: List[tuple] = []

    def check(name: str, required: bool, fn):
        try:
            detail = fn()
            results.append((name, True, required, detail))
        except Exception as exc:  # noqa: BLE001 - doctor must report, never crash
            results.append((name, False, required, str(exc)[:110]))

    def t_osv():
        res, failed = osv.query_batch(http, [("PyPI", "jinja2", "2.4.1")])
        if failed:
            raise RuntimeError("cannot reach api.osv.dev (offline, firewall or proxy blocking it). "
                               "Without it vulnerabilities cannot be matched")
        n = len(res[("PyPI", "jinja2", "2.4.1")])
        if n == 0:
            raise RuntimeError("api.osv.dev answered but returned nothing for a known-vulnerable package")
        return f"OK, jinja2 2.4.1 matched {n} advisories"

    def t_osv_rec():
        res, failed = osv.query_batch(http, [("PyPI", "jinja2", "2.4.1")])
        hits = res[("PyPI", "jinja2", "2.4.1")]
        if failed or not hits:
            raise RuntimeError("skipped: needs the OSV matching check above to pass first")
        vid = hits[0]["id"]
        rec = osv.parse_vuln(http.get_json(osv.VULN_URL.format(vid)))
        return f"OK, parsed {rec.id} (cvss={rec.cvss_score}, cwes={rec.cwes})"

    def t_owasp():
        md = http.get_text(RAW_URL.format(edition="2025", file=KNOWN_FILES["2025"][4]))
        cid, name, cwes = parse_category(md)
        if 79 not in cwes:
            raise RuntimeError("CWE-79 not found in Injection page")
        return f"OK, {cid} {name}: {len(cwes)} CWEs"

    def t_kev():
        _e, meta, _w = enrich.load_kev(Cache(os.path.join(os.environ.get("TEMP", "/tmp"), "vulnscan-doctor")),
                                      http)
        if not meta.get("count"):
            raise RuntimeError("catalog unavailable")
        return f"OK, {meta['count']} entries ({meta.get('origin')})"

    def t_epss():
        doc = http.get_json(enrich.EPSS_URL.format("CVE-2021-44228"))
        return f"OK, log4shell EPSS={doc['data'][0]['epss']}"

    def t_cve():
        rec = enrich.parse_cve_record(http.get_json(enrich.cve_record_url("CVE-2021-44228")))
        if not rec["cwes"]:
            raise RuntimeError("no CWEs parsed")
        return f"OK, CWEs {rec['cwes']}, CVSS {rec['cvss']}"

    def t_cwe():
        parents = cwe_mod.fetch_cwe_parents(http)
        return f"OK, {len(parents)} weaknesses with hierarchy"

    def t_os_known():
        info = inventory.local_system_info()
        if info.platform_name != "Linux":
            return f"{info.platform_name}: OS packages not applicable (Python/npm, --project and --docker still work)"
        if not info.os_ecosystem:
            raise RuntimeError(info.notes[0] if info.notes else "OS not recognised")
        return f"OK, {info.os_pretty} -> OSV ecosystem '{info.os_ecosystem}'"

    def t_os_cov():
        info = inventory.local_system_info()
        if not info.os_ecosystem:
            return "not applicable"
        res, failed = osv.query_batch(http, [(info.os_ecosystem, "openssl", "0")])
        if failed:
            raise RuntimeError("cannot reach api.osv.dev")
        n = len(res[(info.os_ecosystem, "openssl", "0")])
        if n == 0:
            raise RuntimeError(f"OSV returned nothing for '{info.os_ecosystem}': the release is probably "
                               "end-of-life or the name is wrong. Try --ecosystem with another value")
        return f"OK, OSV has advisories for '{info.os_ecosystem}' ({n} for openssl alone)"

    def t_docker():
        if not shutil.which("docker"):
            raise RuntimeError("docker not on PATH (only needed for --docker)")
        rc, out = inventory.default_runner(["docker", "version", "--format", "{{.Server.Version}}"], 20)
        if rc != 0:
            raise RuntimeError("docker is installed but the engine is not running")
        return f"OK, engine {out.strip()}"

    def t_inventory():
        info = inventory.local_system_info()
        pkgs = inventory.collect_os_packages(info) if info.os_ecosystem else []
        pip = inventory.collect_pip()
        return (f"{info.os_pretty or info.platform_name}; OSV ecosystem={info.os_ecosystem}; "
                f"{len(pkgs)} OS packages, {len(pip)} pip packages")

    check("OSV.dev vulnerability matching", True, t_osv)
    check("OSV.dev record download and parsing", True, t_osv_rec)
    check("OWASP Top 10 source (GitHub)", True, t_owasp)
    check("CISA KEV catalog", False, t_kev)
    check("EPSS scores (FIRST)", False, t_epss)
    check("CVE.org records (GitHub)", False, t_cve)
    check("MITRE CWE hierarchy", False, t_cwe)
    check("This system's OS is recognised", False, t_os_known)
    check("OSV has data for this system's OS release", True, t_os_cov)
    check("Docker engine", False, t_docker)
    check("Local inventory", True, t_inventory)

    print(f"vulnscan {__version__}  |  cache: {Cache().root}\n")
    bad_required = 0
    for name, ok, required, detail in results:
        mark = "PASS" if ok else ("FAIL" if required else "WARN")
        if not ok and required:
            bad_required += 1
        print(f"{mark}  {name}\n      {detail}")
    print("\n" + ("All required checks passed." if not bad_required else
                  f"{bad_required} required check(s) failed: results from audit would be incomplete."))
    return 0 if not bad_required else 1


# ------------------------------------------------------------------ entry point

def cmd_engage(args) -> int:
    from . import engage_cli
    return engage_cli.run(args)


def main(argv: Optional[List[str]] = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    # Backwards compatible: `vulnscan 127.0.0.1 -p 80` means `vulnscan scan 127.0.0.1 -p 80`.
    if argv and argv[0] not in COMMANDS and argv[0] not in ("-h", "--help", "--version"):
        argv.insert(0, "scan")
    args = build_parser().parse_args(argv)
    if args.command == "engage":
        return cmd_engage(args)
    return args.func(args)
