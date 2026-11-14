"""`vulnscan engage ...` command line: new, list, authorize, scan, dns, status, findings, note, check,
report and ui."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import List, Optional

from . import checklist
from .engage_report import write_report
from .engagement import Engagement, EngagementError, FINDING_STATUSES, list_engagements
from .report import SEV_RANK


def add_parser(sub) -> None:
    e = sub.add_parser("engage", help="client engagements: scope, signed authorization, checklist, your notes "
                                      "and fix offers, one combined report, local web UI")
    e.add_argument("--dir", help="engagements folder (default: ./engagements or $VULNSCAN_ENGAGEMENTS_DIR)")
    es = e.add_subparsers(dest="engage_command", required=True)

    n = es.add_parser("new", help="start an engagement for a client")
    n.add_argument("client", help="client name, e.g. 'Mama Njeri Fashions'")
    n.add_argument("--scope", action="append", required=True, metavar="TARGET",
                   help="domain, IP or CIDR the client agreed to have tested (repeatable)")
    n.add_argument("--email-domain", action="append", default=[], metavar="DOMAIN",
                   help="domain to check SPF/DKIM/DMARC for (default: the domains in the scope)")
    n.add_argument("--contact", default="", help="who at the client you deal with")
    n.add_argument("--currency", default="USD", help="currency for fix prices (default USD)")

    es.add_parser("list", help="list engagements")

    a = es.add_parser("authorize", help="record the signed authorization letter")
    a.add_argument("name")
    a.add_argument("--signer", required=True, help="who signed for the client")
    a.add_argument("--date", required=True, help="date signed, YYYY-MM-DD")
    a.add_argument("--reference", default="", help="file name or reference of the letter")
    a.add_argument("--expires", help="end of the testing window, YYYY-MM-DD")

    s = es.add_parser("scan", help="scan the scope (public targets need a recorded authorization)")
    s.add_argument("name")
    s.add_argument("-p", "--ports", default="top")
    s.add_argument("--timeout", type=float, default=1.0)
    s.add_argument("--threads", type=int, default=200)
    s.add_argument("--no-web", action="store_true")
    s.add_argument("--target", action="append", metavar="TARGET", help="only this part of the scope")

    d = es.add_parser("dns", help="check SPF, DMARC and DKIM from public DNS (no authorization needed)")
    d.add_argument("name")

    w = es.add_parser("winaudit", help="read-only check of this Windows PC's security settings "
                                       "(run it on the PC; use an Administrator PowerShell for a full check)")
    w.add_argument("name")

    cr = es.add_parser("crawl", help="crawl one site: find pages, forms and API routes and test them "
                                     "(GET only; public sites need a recorded authorization)")
    cr.add_argument("name")
    cr.add_argument("url", help="e.g. http://127.0.0.1:3000")
    cr.add_argument("--login", action="store_true",
                    help="also crawl logged in: you are asked to paste a Cookie header value (hidden, never saved). "
                         "Use a normal test account, not an admin.")
    cr.add_argument("--max-pages", type=int, default=40)

    ex = es.add_parser("nmap", help="identify service versions with Nmap (must be installed)")
    ex.add_argument("name")
    ex.add_argument("target", help="one host from the scope")
    ex.add_argument("-p", "--ports", default="top")
    nu = es.add_parser("nuclei", help="run Nuclei templates against a site (must be installed)")
    nu.add_argument("name")
    nu.add_argument("url")

    cs = es.add_parser("codescan", help="scan a project folder for leaked secrets and vulnerable dependencies")
    cs.add_argument("name")
    cs.add_argument("folder", help="path to the project, e.g. C:\\Users\\you\\shopzone")
    cs.add_argument("--no-history", action="store_true", help="skip the git history search")

    st = es.add_parser("status", help="show scope, authorization, findings and checklist")
    st.add_argument("name")

    f = es.add_parser("findings", help="list findings with their numbers")
    f.add_argument("name")

    no = es.add_parser("note", help="add your note / fix offer / status to a finding")
    no.add_argument("name")
    no.add_argument("finding", help="finding number from `engage findings`, or its full key")
    no.add_argument("--note", help="what it means, in your words")
    no.add_argument("--fix", help="what you can do about it")
    no.add_argument("--price", help="price for the fix (a number)")
    no.add_argument("--status", choices=FINDING_STATUSES)

    c = es.add_parser("check", help="answer a manual checklist item")
    c.add_argument("name")
    c.add_argument("item", help="checklist id, see `engage status`")
    c.add_argument("result", nargs="?", choices=checklist.STATUSES)
    c.add_argument("--note")
    c.add_argument("--fix")
    c.add_argument("--price")

    r = es.add_parser("report", help="write the combined report (report.html and report.md)")
    r.add_argument("name")
    r.add_argument("-o", "--out-dir")

    u = es.add_parser("ui", help="open the local web interface (127.0.0.1 only)")
    u.add_argument("--port", type=int, default=8765)
    u.add_argument("--no-browser", action="store_true")


def _log(msg: str) -> None:
    print(f"[*] {msg}", file=sys.stderr, flush=True)


def sorted_findings(eng: Engagement) -> List[dict]:
    return sorted(eng.findings(), key=lambda f: (-SEV_RANK[f["severity"]], f["host"], f.get("port") or 0,
                                                 f["check_id"]))


def _resolve_finding(eng: Engagement, ref: str) -> str:
    if ref.isdigit():
        items = sorted_findings(eng)
        idx = int(ref)
        if not 1 <= idx <= len(items):
            raise EngagementError(f"there is no finding number {idx}; run `engage findings {eng.slug}`")
        return items[idx - 1]["key"]
    return ref


def _price_args(args) -> dict:
    return {"price": args.price, "price_given": args.price is not None}


def run(args) -> int:
    root = Path(args.dir) if args.dir else None
    try:
        return _dispatch(args, root)
    except EngagementError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


def _dispatch(args, root: Optional[Path]) -> int:
    cmd = args.engage_command
    if cmd == "new":
        eng = Engagement.create(args.client, args.scope, root, args.contact, args.email_domain, args.currency)
        print(f"Created '{eng.slug}' in {eng.dir}")
        print("Scope: " + ", ".join(eng.data["scope"]))
        print(f"Next: get the signed authorization letter, then "
              f"`vulnscan engage authorize {eng.slug} --signer NAME --date YYYY-MM-DD`")
        return 0
    if cmd == "list":
        items = list_engagements(root)
        if not items:
            print("No engagements yet. Start one with: vulnscan engage new \"Client\" --scope example.com")
        for item in items:
            print(f"{item['slug']:<30} {item['client']}  ({', '.join(item['scope'])})")
        return 0
    if cmd == "ui":
        from .webui import serve
        return serve(root, args.port, not args.no_browser)

    eng = Engagement.load(args.name, root)
    if cmd == "authorize":
        eng.set_authorization(args.signer, args.date, args.reference, args.expires)
        print("Authorization recorded. Public targets in the scope can now be scanned.")
    elif cmd == "scan":
        run_info = eng.run_scan(args.ports, args.timeout, args.threads, not args.no_web, args.target, _log)
        print(f"Scan done: {run_info['findings']} finding(s) {run_info['by_severity']}")
        print(f"Next: `vulnscan engage findings {eng.slug}`, add your notes, then `engage report {eng.slug}`")
    elif cmd == "dns":
        run_info = eng.run_dns(log=_log)
        print(f"Email check done: {run_info['findings']} finding(s) {run_info['by_severity']}")
    elif cmd == "winaudit":
        run_info = eng.run_winaudit(log=_log)
        print(f"Windows check done: {run_info['findings']} finding(s) {run_info['by_severity']}")
    elif cmd == "crawl":
        headers = None
        if args.login:
            import getpass
            raw = getpass.getpass("Paste the Cookie header value of a logged-in test account (hidden): ").strip()
            headers = {"Cookie": raw} if raw else None
        run_info = eng.run_crawl(args.url, headers, args.max_pages, _log)
        print(f"Crawl done: {run_info['findings']} finding(s) {run_info['by_severity']}")
    elif cmd in ("nmap", "nuclei"):
        run_info = eng.run_external(cmd, args.target if cmd == "nmap" else args.url,
                                    getattr(args, "ports", "top"), log=_log)
        print(f"{cmd} done: {run_info['findings']} finding(s) {run_info['by_severity']}")
    elif cmd == "codescan":
        run_info = eng.run_codescan(args.folder, not args.no_history, log=_log)
        print(f"Code scan done: {run_info['findings']} finding(s) {run_info['by_severity']}")
    elif cmd == "status":
        _print_status(eng)
    elif cmd == "findings":
        items = sorted_findings(eng)
        if not items:
            print("No findings yet. Run `engage scan` and/or `engage dns` first.")
        for i, f in enumerate(items, 1):
            where = f"{f['host']}:{f['port']}" if f.get("port") else f["host"]
            marks = ("" if f["status"] == "open" else f" [{f['status']}]") + (" [note]" if f["note"] else "") + \
                (" [fix]" if f["fix"] else "")
            print(f"{i:>3}. {f['severity']:<8} {where[:32]:<32} {f['title'][:70]}{marks}")
    elif cmd == "note":
        key = _resolve_finding(eng, args.finding)
        eng.set_finding(key, note=args.note, fix=args.fix, status=args.status, **_price_args(args))
        print(f"Updated {key}")
    elif cmd == "check":
        if args.result is None and args.note is None and args.fix is None and args.price is None:
            raise EngagementError("give a result (pass/fail/na/todo) and/or --note/--fix/--price")
        eng.set_check(args.item, args.result, args.note, args.fix, **_price_args(args))
        print(f"Updated {args.item}")
    elif cmd == "report":
        for path in write_report(eng, args.out_dir):
            print(path)
    return 0


def _print_status(eng: Engagement) -> None:
    d = eng.data
    print(f"{eng.client}  ({eng.slug})")
    print("Scope:         " + ", ".join(d["scope"]))
    auth = d.get("authorization")
    print("Authorization: " + (f"signed by {auth['signer']} on {auth['signed_on']}"
                               + (f", expires {auth['expires']}" if auth.get("expires") else "") if auth else "NONE"))
    problem = eng.authorization_problem()
    if problem and auth:
        print(f"               WARNING: {problem}")
    print(f"Runs:          {len(d['runs'])}")
    counts = {}
    for f in eng.counted_findings():
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1
    print("Findings:      " + (", ".join(f"{k}={v}" for k, v in sorted(counts.items(), key=lambda kv: -SEV_RANK[kv[0]])) or "none"))
    print("\nChecklist (id, result, how it is checked):")
    for r in eng.checklist_rows():
        hint = f"  - {r['hint']}" if r["hint"] else ""
        print(f"  {r['id']:<18} {r['effective']:<5} {r['coverage']:<8} {r['title']}{hint}")
    total = eng.offer_total()
    if total:
        print(f"\nFixes you have priced: {d.get('currency', 'USD')} {total:,.2f}")
