"""A careful, read-only crawler: discovers pages, forms and API routes on one site, then runs
page-level checks on what it found.

Safety rules: GET requests only, same site only, capped number of requests, links that look
destructive (logout, delete ...) are never followed, forms are never submitted.  When a login
cookie or token is supplied the crawl is repeated logged-out to find pages that are not really
protected.  Credentials are used in memory only and are never written to results.
"""

from __future__ import annotations

import json
import re
import secrets
from dataclasses import dataclass, field
from html.parser import HTMLParser
from typing import Callable, Dict, List, Optional, Set, Tuple
from urllib.parse import parse_qsl, quote, urljoin, urlsplit, urlunsplit, urlencode

from .models import Finding, Severity
from .webchecks import (ERROR_SIGNATURES, SQL_ERROR_SIGNATURES, Response, WebTarget, fetch)

DESTRUCTIVE = re.compile(r"(?i)(log[-_ ]?out|sign[-_ ]?out|delete|remove|destroy|unsubscribe|cancel|reset|revoke)")
PRIVATE_HINT = re.compile(r"(?i)/(admin|dashboard|account|orders?|customers?|users?|invoices?|payments?|"
                          r"settings|manage|profile|reports?|internal)(/|$|\?)")
API_IN_JS = [re.compile(r"""["'`](/api/[A-Za-z0-9_\-/.]+)["'`]"""),
             re.compile(r"""fetch\(\s*["'`](/[A-Za-z0-9_\-/.]+)["'`]"""),
             re.compile(r"""axios\.(?:get|post|put|delete|patch)\(\s*["'`](/[A-Za-z0-9_\-/.]+)["'`]""")]
CSRF_NAME = re.compile(r"(?i)(csrf|xsrf|token|nonce|authenticity)")


@dataclass
class Form:
    page: str
    action: str
    method: str
    inputs: List[Tuple[str, str]]  # (name, type)


class _Parse(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: List[str] = []
        self.scripts: List[str] = []
        self.resources: List[str] = []
        self.forms: List[dict] = []
        self._form: Optional[dict] = None

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "a" and a.get("href"):
            self.links.append(a["href"])
        elif tag == "script" and a.get("src"):
            self.scripts.append(a["src"])
            self.resources.append(a["src"])
        elif tag in ("img", "iframe", "source") and a.get("src"):
            self.resources.append(a["src"])
        elif tag == "link" and a.get("href") and (a.get("rel") or "").lower() in ("stylesheet", "icon"):
            self.resources.append(a["href"])
        elif tag == "form":
            self._form = {"action": a.get("action") or "", "method": (a.get("method") or "get").lower(),
                          "inputs": []}
            self.forms.append(self._form)
        elif tag in ("input", "textarea", "select") and self._form is not None:
            self._form["inputs"].append((a.get("name") or "", (a.get("type") or tag).lower()))

    def handle_endtag(self, tag):
        if tag == "form":
            self._form = None


@dataclass
class CrawlResult:
    pages: Dict[str, Response] = field(default_factory=dict)       # url -> response
    forms: List[Form] = field(default_factory=list)
    api: Set[str] = field(default_factory=set)
    mixed: Dict[str, List[str]] = field(default_factory=dict)
    requests: int = 0
    truncated: bool = False


def _norm(url: str) -> str:
    p = urlsplit(url)
    return urlunsplit((p.scheme, p.netloc, p.path or "/", p.query, ""))


def crawl(t: WebTarget, start_path: str = "/", headers: Optional[Dict[str, str]] = None, max_pages: int = 40,
          max_depth: int = 3, max_requests: int = 150) -> CrawlResult:
    scheme = "https" if t.tls else "http"
    origin = f"{scheme}://{t.host}:{t.port}"
    res = CrawlResult()
    queue: List[Tuple[str, int]] = [(urljoin(origin + "/", start_path), 0)]
    seen: Set[str] = set()
    scripts: List[str] = []

    def same_site(url: str) -> bool:
        p = urlsplit(url)
        return p.hostname == t.host and (p.port or (443 if p.scheme == "https" else 80)) == t.port

    while queue and len(res.pages) < max_pages:
        url, depth = queue.pop(0)
        url = _norm(url)
        if url in seen or not same_site(url) or DESTRUCTIVE.search(urlsplit(url).path):
            continue
        seen.add(url)
        if res.requests >= max_requests:
            res.truncated = True
            break
        p = urlsplit(url)
        resp = fetch(t, p.path + (f"?{p.query}" if p.query else ""), headers=dict(headers or {}) or {"X-VS": "1"})
        res.requests += 1
        if resp is None:
            continue
        res.pages[url] = resp
        ctype = resp.headers.get("content-type", "").lower()
        if resp.status != 200 or "html" not in ctype:
            continue
        parser = _Parse()
        try:
            parser.feed(resp.text)
        except Exception:  # malformed HTML must not stop a crawl
            continue
        for form in parser.forms:
            res.forms.append(Form(url, urljoin(url, form["action"]), form["method"], form["inputs"]))
        for href in parser.links:
            if href.startswith(("mailto:", "tel:", "javascript:", "#")):
                continue
            full = urljoin(url, href)
            if depth < max_depth and full not in seen:
                queue.append((full, depth + 1))
        for src in parser.scripts:
            full = urljoin(url, src)
            if same_site(full) and full not in scripts and len(scripts) < 10:
                scripts.append(full)
        if scheme == "https":
            bad = [r for r in parser.resources if r.lower().startswith("http://")]
            if bad:
                res.mixed[url] = bad[:3]

    for src in scripts:
        if res.requests >= max_requests:
            res.truncated = True
            break
        p = urlsplit(src)
        js = fetch(t, p.path + (f"?{p.query}" if p.query else ""), headers=dict(headers or {}) or {"X-VS": "1"})
        res.requests += 1
        if js is not None and js.status == 200:
            for rx in API_IN_JS:
                for m in rx.findall(js.text):
                    if "${" not in m and ":" not in m and len(m) < 100:
                        res.api.add(m.rstrip("/") or "/")
    return res


def _f(t: WebTarget, cid: str, title: str, sev: Severity, cat: str, cwe: str, desc: str, fix: str,
       evidence: str = "") -> Finding:
    return Finding(t.host, t.port, cid, title, sev, cat, cwe, desc, fix, evidence)


def _looks_like_login(resp: Response) -> bool:
    return bool(re.search(r'(?i)<input[^>]+type=["\']?password', resp.text))


def _redirects_away(resp: Response) -> bool:
    return resp.status in (301, 302, 303, 307, 308, 401, 403)


def analyse(t: WebTarget, anon: CrawlResult, authed: Optional[CrawlResult] = None) -> List[Finding]:
    out: List[Finding] = []
    seen: Set[Tuple] = set()

    def add(f: Finding, key: Tuple) -> None:
        if key not in seen:
            seen.add(key)
            out.append(f)

    # attack-surface summary (INFO)
    where = f"{t.host}:{t.port}"
    out.append(_f(t, "WEB-SURFACE", f"Crawl found {len(anon.pages)} pages, {len(anon.forms)} forms and "
                  f"{len(anon.api)} API routes", Severity.INFO, "insecure_design", "CWE-200",
                  "This is the part of the site a visitor can reach and that the other checks covered.",
                  "Review the list for pages or API routes that should not be public.",
                  evidence="; ".join(sorted({urlsplit(u).path for u in anon.pages})[:15]) +
                  ("  | API: " + ", ".join(sorted(anon.api)[:10]) if anon.api else "")))

    for form in anon.forms:
        has_pw = any(ty == "password" for _, ty in form.inputs)
        if has_pw and form.action.startswith("http://") and t.host not in ("127.0.0.1", "localhost", "::1"):
            add(_f(t, "WEB-FORM-INSECURE-ACTION", "A password form submits over plain HTTP", Severity.HIGH,
                   "crypto", "CWE-319", "A form with a password field sends it without encryption, so anyone "
                   "on the network can read it.", "Serve the page and the form action over HTTPS only.",
                   evidence=f"{form.page} -> {form.action}"), ("insecure", form.action))
        if form.method == "post" and not any(CSRF_NAME.search(n) for n, ty in form.inputs if ty == "hidden" or n):
            add(_f(t, "WEB-FORM-NO-CSRF", "A form has no visible anti-forgery token (verify manually)",
                   Severity.LOW, "access_control", "CWE-352", "Without a token (or SameSite cookies) another "
                   "website may be able to make a logged-in visitor submit this form. Single-page apps often "
                   "send the token in a header instead, so this is only an indicator.",
                   "Add a CSRF token to state-changing forms, or use SameSite=Lax/Strict session cookies.",
                   evidence=f"POST form at {form.page} -> {form.action}"), ("csrf", form.page, form.action))

    for page, bad in anon.mixed.items():
        add(_f(t, "WEB-MIXED-CONTENT", "A secure page loads content over plain HTTP", Severity.MEDIUM, "crypto",
               "CWE-311", "Resources loaded over HTTP can be changed by anyone on the network, and scripts "
               "among them can take over the page.", "Load every resource over HTTPS.",
               evidence=f"{page}: {', '.join(bad)}"), ("mixed", page))

    # light probing of discovered pages that carry query parameters (GET only)
    probed = 0
    for url in list(anon.pages):
        p = urlsplit(url)
        params = parse_qsl(p.query, keep_blank_values=True)
        if not params or probed >= 10:
            continue
        probed += 1
        canary = f"vs{secrets.token_hex(3)}\"><vsx>"
        q = urlencode([(k, canary) for k, _ in params], quote_via=quote)
        r = fetch(t, p.path + "?" + q)
        if r and canary in r.text:
            add(_f(t, "WEB-REFLECTED-INPUT", "Unescaped input reflected (possible reflected XSS, verify manually)",
                   Severity.MEDIUM, "injection", "CWE-79", "A harmless marker with HTML characters was echoed "
                   "back unencoded.", "Encode all user-controlled output and add a strict CSP.",
                   evidence=f"{p.path}?{', '.join(k for k, _ in params)}"), ("xss", p.path))
        q2 = urlencode([(k, v + "'\"") for k, v in params], quote_via=quote)
        r2 = fetch(t, p.path + "?" + q2)
        if r2:
            for rx in SQL_ERROR_SIGNATURES:
                if re.search(rx, r2.text):
                    add(_f(t, "WEB-SQL-ERROR", "Possible SQL error disclosure (verify manually)", Severity.MEDIUM,
                           "injection", "CWE-89", "A quote in a parameter produced a database error, which can "
                           "mean queries are built unsafely. Indicator only.",
                           "Use parameterised queries and hide database errors.",
                           evidence=f"{p.path} matched {rx}"), ("sql", p.path))
                    break
            for rx, label in ERROR_SIGNATURES:
                if re.search(rx, r2.text):
                    add(_f(t, "WEB-VERBOSE-ERRORS", "Verbose error output / debug mode", Severity.MEDIUM,
                           "exceptions", "CWE-209", "Error pages expose internals.", "Turn off debug mode.",
                           evidence=label), ("verbose", p.path))
                    break

    # anonymous visitors reaching things that look private
    for url, resp in anon.pages.items():
        path = urlsplit(url).path
        if resp.status == 200 and PRIVATE_HINT.search(path + "/") and not _looks_like_login(resp) \
                and "html" in resp.headers.get("content-type", "").lower():
            add(_f(t, "WEB-PRIVATE-PAGE-OPEN", "A page that looks private opens without logging in "
                   "(verify manually)", Severity.MEDIUM, "access_control", "CWE-306",
                   f"{path} sounds like an account or admin area but returned content to an anonymous "
                   "visitor. It may be a public marketing page, so check it.",
                   "Require a login (and the right role) on the server for every private page.",
                   evidence=f"GET {path} -> 200 without credentials"), ("private", path))
    for route in sorted(anon.api):
        if PRIVATE_HINT.search(route + "/") and "{" not in route:
            r = fetch(t, route)
            if r and r.status == 200 and "json" in r.headers.get("content-type", "").lower():
                add(_f(t, "WEB-API-OPEN", "An API route that looks private answers without logging in",
                       Severity.HIGH, "access_control", "CWE-306", f"{route} returned data to an anonymous "
                       "request. If it lists customers, orders or users this is a data leak.",
                       "Require authentication and authorisation on the server for this route.",
                       evidence=f"GET {route} -> 200 JSON without credentials"), ("api", route))

    # logged-in differential: pages that only appear after login must not open without it
    if authed is not None:
        anon_paths = {urlsplit(u).path for u in anon.pages if anon.pages[u].status == 200}
        for url, resp in authed.pages.items():
            p = urlsplit(url)
            if resp.status != 200 or p.path in anon_paths or "html" not in resp.headers.get("content-type", ""):
                continue
            r = fetch(t, p.path + (f"?{p.query}" if p.query else ""))
            if r is None or _redirects_away(r) or r.status != 200 or _looks_like_login(r):
                continue
            a, b = len(resp.body), len(r.body)
            if max(a, b) and abs(a - b) / max(a, b) < 0.1:
                add(_f(t, "WEB-AUTH-NOT-ENFORCED", "A page that needs login is open without it", Severity.HIGH,
                       "access_control", "CWE-862", f"{p.path} was only found while logged in, yet an anonymous "
                       "request returns the same content. Login is checked in the front end but not on the "
                       "server.", "Enforce the login check on the server for this page and its data routes.",
                       evidence=f"GET {p.path}: logged-in {a} bytes, anonymous {b} bytes, both 200"),
                    ("authdiff", p.path))
        for route in sorted(authed.api - anon.api):
            if "{" in route:
                continue
            r = fetch(t, route)
            if r and r.status == 200 and "json" in r.headers.get("content-type", "").lower():
                add(_f(t, "WEB-API-NOT-ENFORCED", "A logged-in API route answers without login", Severity.HIGH,
                       "access_control", "CWE-862", f"{route} is used by the logged-in app but returns data to "
                       "an anonymous request.", "Check authentication and authorisation on the server for "
                       "every API route.", evidence=f"GET {route} -> 200 JSON without credentials"),
                    ("apidiff", route))
    return out


def run_crawl(host: str, address: str, port: int, tls: bool, start_path: str = "/",
              headers: Optional[Dict[str, str]] = None, max_pages: int = 40,
              log: Callable[[str], None] = lambda m: None) -> Tuple[List[Finding], dict]:
    t = WebTarget(host, address, port, tls, timeout=6.0)
    log(f"crawling {host}:{port} logged-out")
    anon = crawl(t, start_path, None, max_pages)
    authed = None
    if headers:
        log("crawling again with your login")
        authed = crawl(t, start_path, headers, max_pages)
    findings = analyse(t, anon, authed)
    coverage = {"status": "completed" if anon.pages else "incomplete", "pages_found": len(anon.pages),
                "forms_found": len(anon.forms), "api_routes_found": len(anon.api),
                "requests_made": anon.requests + (authed.requests if authed else 0),
                "authenticated_crawl": authed is not None,
                "skipped_checks": (["The crawl hit its request limit; some pages were not visited"]
                                   if anon.truncated else []) + ([] if anon.pages else ["no page could be loaded"]),
                "limitations": ["GET requests only; forms are never submitted.",
                                "Pages that need JavaScript to appear are not seen by this crawler.",
                                "Only one logged-in role is compared against anonymous, so privilege "
                                "escalation between two user roles is not tested."]}
    return findings, coverage
