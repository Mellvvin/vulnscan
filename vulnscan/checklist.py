"""The small-business audit checklist.

Each item says how it is answered:

* ``auto``    - the scanner fully answers it (a clean run really means pass);
* ``partial`` - the scanner finds some of the problems, a human still has to look;
* ``manual``  - only a person can check it (questions, screenshots, the client's accounts).

``checks`` lists check-id prefixes; a finding whose check_id starts with one of them belongs
to the item.  ``source`` says which run produces them ("scan", "dns", "win", "code" or "crawl").
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Tuple

from . import explain

STATUSES = ("todo", "pass", "fail", "na")
SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")


@dataclass(frozen=True)
class Item:
    id: str
    area: str
    title: str
    look_for: str
    severity: str  # severity if the check fails
    coverage: str  # auto | partial | manual
    checks: Tuple[str, ...] = ()
    source: Optional[str] = None  # scan | dns | None (manual)
    ask: str = ""  # what to ask or inspect when it is a manual check


ITEMS: List[Item] = [
    Item("web-tls", "Website", "HTTPS and certificate",
         "Expired or weak certificate, no redirect from HTTP to HTTPS, no HSTS.", "MEDIUM", "auto",
         ("TLS-", "WEB-NO-HSTS", "WEB-WEAK-HSTS", "WEB-NO-HTTPS-REDIRECT", "WEB-MIXED-CONTENT"), "scan"),
    Item("web-headers", "Website", "Security headers",
         "Missing CSP, clickjacking protection, nosniff or referrer policy.", "LOW", "auto",
         ("WEB-NO-CSP", "WEB-NO-CLICKJACK-PROTECTION", "WEB-NO-NOSNIFF", "WEB-NO-REFERRER-POLICY"), "scan"),
    Item("web-disclosure", "Website", "Server information and risky methods",
         "Version numbers in headers, TRACE/PUT/DELETE enabled, debug or stack-trace pages, loose CORS.",
         "MEDIUM", "auto",
         ("WEB-SERVER-VERSION", "WEB-X-POWERED-BY", "WEB-RISKY-METHODS", "WEB-TRACE-ENABLED",
          "WEB-VERBOSE-ERRORS", "WEB-CORS-"), "scan"),
    Item("web-cms", "Website", "CMS and plugin versions",
         "Outdated WordPress core, themes or plugins with known CVEs.", "HIGH", "partial",
         ("COMP-",), "scan",
         "Open /wp-admin (with permission), note the WordPress version, list plugins; run WPScan if you use it."),
    Item("web-exposed", "Website", "Exposed files and paths",
         "Open .git, .env, backups, phpinfo, directory listing, admin panels reachable by anyone.",
         "HIGH", "auto", ("WEB-EXPOSED-", "WEB-DIR-LISTING", "NUCLEI-"), "scan"),
    Item("web-login", "Website", "Login and session protection",
         "No rate limiting or MFA on admin, default usernames, cookies without Secure/HttpOnly/SameSite, "
         "login over HTTP.", "HIGH", "partial", ("WEB-COOKIE-", "WEB-LOGIN-OVER-HTTP", "WEB-FORM-INSECURE-ACTION"), "scan",
         "Try the admin login: is there a lockout after repeated failures? Is MFA offered? Is 'admin' a valid user?"),
    Item("web-inputs", "Website", "Forms and inputs",
         "Indicators of SQL injection or reflected XSS on contact, search and checkout forms.",
         "HIGH", "partial", ("WEB-SQL-ERROR", "WEB-REFLECTED-INPUT", "WEB-FORM-NO-CSRF"), "scan",
         "The scanner only flags indicators. Verify any hit by hand and test other forms it cannot reach."),
    Item("web-access", "Website", "Pages and data behind login",
         "Admin, account or API pages that open without logging in; login enforced only in the browser.",
         "HIGH", "partial", ("WEB-AUTH-NOT-ENFORCED", "WEB-API-", "WEB-PRIVATE-PAGE-OPEN"), "crawl",
         "Log in as an ordinary customer and try admin addresses; change an order or user number in the "
         "address and see whether you can open someone else's. The crawler only compares logged-in and "
         "logged-out, it cannot test two different users."),
    Item("pay-mpesa", "Payments", "M-Pesa / Daraja integration",
         "API keys in front-end code or public repos, callbacks accepted without verification.",
         "CRITICAL", "partial", ("CODE-SECRET", "CODE-ENV"), "code",
         "Read the page source and JS bundles for keys; check the callback URL validates the sender and amount."),
    Item("pay-checkout", "Payments", "Checkout flow",
         "Prices or amounts editable client-side, no server-side validation.", "CRITICAL", "manual", (), None,
         "Change the price or quantity in the browser request and see if the order still goes through."),
    Item("mail-auth", "Email", "SPF, DKIM and DMARC",
         "Missing records so anyone can spoof the business domain; DMARC left at p=none.",
         "HIGH", "partial", ("DNS-",), "dns",
         "DKIM selectors cannot be listed from DNS; confirm in the mail provider's admin console."),
    Item("mail-accounts", "Email", "Mailbox security",
         "No MFA on owner and finance mailboxes; forwarding rules to unknown addresses.", "HIGH", "manual",
         (), None, "Ask to see mailbox security settings and the forwarding/filter rules."),
    Item("acct-passwords", "Accounts", "Password hygiene",
         "Shared logins, reused passwords, no password manager.", "HIGH", "manual", (), None,
         "Ask how staff share logins and how passwords are stored."),
    Item("acct-mfa", "Accounts", "MFA coverage",
         "Missing on email, domain registrar, hosting, social pages and banking apps.", "HIGH", "manual",
         (), None, "Go through each critical account and check whether MFA is on."),
    Item("acct-exstaff", "Accounts", "Former staff access",
         "Ex-employees still have admin, hosting or social media access.", "MEDIUM", "manual", (), None,
         "Compare the list of people with admin access against current staff."),
    Item("dns-registrar", "DNS and domain", "Registrar security",
         "No registrar lock, owner email expired or personal, no MFA on the registrar account.", "HIGH",
         "manual", (), None, "Check WHOIS contact, the registrar lock and who controls the account."),
    Item("dns-subdomains", "DNS and domain", "Forgotten subdomains",
         "Dev, test or staging subdomains still live.", "MEDIUM", "manual", (), None,
         "Search certificate transparency (crt.sh) and DNS for subdomains, then check each one."),
    Item("net-wifi", "Network", "Wi-Fi and router",
         "Default router password, WPS on, guests on the same network as POS or CCTV.", "MEDIUM", "manual",
         (), None, "On site: router admin login, Wi-Fi security mode, guest network separation."),
    Item("net-exposed", "Network", "Exposed services",
         "RDP, SSH, databases, SMB or CCTV panels reachable from the internet.", "CRITICAL", "auto",
         ("PORT-",), "scan"),
    Item("code-deps", "Website", "Code dependencies",
         "Libraries in the project with published security advisories.", "HIGH", "auto",
         ("CODE-DEP-",), "code",
         "Run the code scan on the project folder."),
    Item("dev-updates", "Devices", "Updates and antivirus",
         "Unpatched Windows or Android POS devices, no endpoint protection, firewall or disk encryption off.",
         "MEDIUM", "partial", ("WIN-",), "win",
         "Run the Windows check on each Windows PC; spot-check phones and POS devices by hand; for Linux "
         "hosts run `vulnscan audit` on them."),
    Item("data-backups", "Data", "Backups",
         "No backup, backups never tested, or stored on the same machine.", "HIGH", "manual", (), None,
         "Ask when the last backup was and whether a restore was ever tested."),
    Item("people-phishing", "People", "Phishing readiness",
         "Staff cannot spot fake M-Pesa or bank messages; no habit of reporting them.", "MEDIUM", "manual",
         (), None, "Ask staff what they would do with a suspicious message."),
]

BY_ID: Dict[str, Item] = {i.id: i for i in ITEMS}


def blank_state() -> Dict[str, dict]:
    return {i.id: {"status": "todo", "note": "", "fix": "", "price": None} for i in ITEMS}


def finding_item(check_id: str) -> Optional[Item]:
    """The checklist item a finding belongs to, or None."""
    for item in ITEMS:
        if any(check_id.startswith(p) for p in item.checks):
            return item
    return None


def evaluate(state: Dict[str, dict], finding_ids: Iterable[str], ran: Iterable[str]) -> List[dict]:
    """Combine manual answers with scanner results into one row per item.

    ``effective`` is what to report: a manual answer always wins; otherwise findings make an item
    "fail", a clean run of a fully automated item makes it "pass", and anything the scanner cannot
    settle stays "todo" with an explanatory hint.
    """
    ids = list(finding_ids)
    ran_set = set(ran)
    rows: List[dict] = []
    for item in ITEMS:
        saved = state.get(item.id) or {}
        manual = saved.get("status", "todo")
        hits = [c for c in ids if any(c.startswith(p) for p in item.checks)] if item.checks else []
        if item.source is None:
            auto = "manual"
        elif hits:
            auto = "findings"
        elif item.source not in ran_set:
            auto = "not-run"
        else:
            auto = "clean"
        hint = ""
        if manual != "todo":
            effective = manual
        elif auto == "findings":
            effective = "fail"
        elif auto == "clean" and item.coverage == "auto":
            effective = "pass"
        elif auto == "clean":
            effective, hint = "todo", "scanner found nothing, but this needs a manual look"
        elif auto == "not-run":
            effective, hint = "todo", "run the " + {"scan": "scan", "dns": "email check", "win": "Windows check", "code": "code scan", "crawl": "site crawl"}.get(item.source, item.source)
        else:
            effective = "todo"
        sug_note, sug_fix = _suggest(item, effective, manual, hits)
        rows.append({"id": item.id, "area": item.area, "title": item.title, "look_for": item.look_for,
                     "severity": item.severity, "coverage": item.coverage, "ask": item.ask,
                     "manual": manual, "auto": auto, "effective": effective, "hint": hint,
                     "hits": hits, "note": saved.get("note", ""), "fix": saved.get("fix", ""),
                     "suggest_note": sug_note, "suggest_fix": sug_fix,
                     "price": saved.get("price")})
    return rows


def _suggest(item: Item, effective: str, manual: str, hits: List[str]) -> Tuple[str, str]:
    """Starting text for the note and fix boxes, depending on the result."""
    if effective == "pass":
        how = "by hand" if manual == "pass" else "by the scan"
        return (f"Checked {how} and no problems were found. What was checked: {item.look_for}",
                "Nothing to fix. Re-check after any change to the website, router or accounts.")
    if effective == "na":
        return "This does not apply to this business.", ""
    if effective == "fail":
        if hits:
            note, fix = explain.suggest({"check_id": hits[0]})
            return note, fix
        fix = "Fix this and re-check."
        if item.ask:
            fix += " How to check: " + item.ask
        return f"Problem found. What to look for: {item.look_for}", fix
    return "", ""
