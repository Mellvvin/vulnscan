"""Passive-to-light HTTP(S) checks mapped to the OWASP Top 10.

Design rules that keep the false-positive rate low:
  * header checks only run against HTML responses, where they matter;
  * exposed-file checks require a content *signature*, not just a 200 status;
  * injection-related checks are reported as "possible" indicators that need
    manual verification, and never attempt exploitation.
"""

from __future__ import annotations

import http.client
import re
import secrets
import ssl
from dataclasses import dataclass, field
from html.parser import HTMLParser
from typing import Callable, Dict, List, Optional, Tuple
from urllib.parse import quote, urlsplit

from .models import Finding, Severity
from .versions import version_findings

USER_AGENT = "vulnscan/1.0 (authorized security assessment)"
MAX_BODY = 65536


@dataclass
class Response:
    status: int
    headers: Dict[str, str]
    cookies: List[str]
    body: bytes

    @property
    def text(self) -> str:
        return self.body.decode("utf-8", "replace")

    @property
    def is_html(self) -> bool:
        return "html" in self.headers.get("content-type", "").lower() or not self.headers.get(
            "content-type"
        )


@dataclass
class WebTarget:
    host: str  # report label
    address: str  # where we connect
    port: int
    tls: bool
    timeout: float = 4.0
    https_available: bool = False  # does this host serve HTTPS anywhere?
    cache: Dict[Tuple[str, str], Optional[Response]] = field(default_factory=dict)

    @property
    def hostname_header(self) -> Optional[str]:
        return self.host if self.host != self.address else None


def fetch(t: WebTarget, path: str = "/", method: str = "GET",
          headers: Optional[Dict[str, str]] = None) -> Optional[Response]:
    cache_key = (method, path)
    if headers is None and cache_key in t.cache:
        return t.cache[cache_key]

    conn: Optional[http.client.HTTPConnection] = None
    result: Optional[Response] = None
    try:
        if t.tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            conn = http.client.HTTPSConnection(t.address, t.port, timeout=t.timeout, context=ctx)
        else:
            conn = http.client.HTTPConnection(t.address, t.port, timeout=t.timeout)
        hdrs = {"User-Agent": USER_AGENT, "Accept": "*/*", "Connection": "close"}
        if t.hostname_header:
            hdrs["Host"] = t.hostname_header
        hdrs.update(headers or {})
        conn.request(method, path, headers=hdrs)
        resp = conn.getresponse()
        body = b"" if method in ("HEAD", "OPTIONS") else resp.read(MAX_BODY)
        merged: Dict[str, str] = {}
        for k, v in resp.getheaders():
            lk = k.lower()
            merged[lk] = f"{merged[lk]}, {v}" if lk in merged and lk != "set-cookie" else v
        cookies = resp.msg.get_all("Set-Cookie") or []
        result = Response(resp.status, merged, cookies, body)
    except (OSError, http.client.HTTPException, ssl.SSLError, ValueError):
        result = None
    finally:
        if conn is not None:
            conn.close()
    if headers is None:
        t.cache[cache_key] = result
    return result


def _f(t: WebTarget, check_id: str, title: str, sev: Severity, category: str, cwe: str,
       desc: str, fix: str, evidence: str = "") -> Finding:
    return Finding(t.host, t.port, check_id, title, sev, category, cwe, desc, fix, evidence)


# --- A02/A05: transport and header hygiene -------------------------------------

def check_headers(t: WebTarget, root: Response) -> List[Finding]:
    out: List[Finding] = []
    h = root.headers
    csp = h.get("content-security-policy", "")
    if root.is_html:
        if not csp:
            out.append(_f(t, "WEB-NO-CSP", "Content-Security-Policy header missing",
                          Severity.MEDIUM, "misconfig", "CWE-693",
                          "Without a CSP the browser has no defence-in-depth against injected scripts (XSS).",
                          "Send a restrictive Content-Security-Policy, starting with default-src 'self'."))
        if "x-frame-options" not in h and "frame-ancestors" not in csp.lower():
            out.append(_f(t, "WEB-NO-CLICKJACK-PROTECTION", "No clickjacking protection",
                          Severity.LOW, "misconfig", "CWE-1021",
                          "The page can be embedded in a hostile frame.",
                          "Send X-Frame-Options: DENY or CSP frame-ancestors 'none'."))
    if h.get("x-content-type-options", "").lower() != "nosniff":
        out.append(_f(t, "WEB-NO-NOSNIFF", "X-Content-Type-Options header missing",
                      Severity.LOW, "misconfig", "CWE-693",
                      "Browsers may MIME-sniff responses into executable content types.",
                      "Send X-Content-Type-Options: nosniff."))
    if root.is_html and "referrer-policy" not in h:
        out.append(_f(t, "WEB-NO-REFERRER-POLICY", "Referrer-Policy header missing",
                      Severity.INFO, "misconfig", "CWE-200",
                      "Full URLs may leak to third parties via the Referer header.",
                      "Send Referrer-Policy: strict-origin-when-cross-origin (or stricter)."))
    if t.tls:
        hsts = h.get("strict-transport-security", "")
        if not hsts:
            out.append(_f(t, "WEB-NO-HSTS", "HTTP Strict-Transport-Security missing",
                          Severity.MEDIUM, "crypto", "CWE-319",
                          "Browsers are not told to insist on HTTPS, enabling downgrade/SSL-strip attacks.",
                          "Send Strict-Transport-Security: max-age=31536000; includeSubDomains."))
        else:
            m = re.search(r"max-age=(\d+)", hsts, re.I)
            if m and int(m.group(1)) < 15552000:
                out.append(_f(t, "WEB-WEAK-HSTS", "HSTS max-age is short",
                              Severity.LOW, "crypto", "CWE-319",
                              "A short max-age limits the protection window.",
                              "Use max-age of at least 15552000 (180 days), ideally 31536000.",
                              evidence=hsts[:100]))
    return out


def check_disclosure(t: WebTarget, root: Response) -> List[Finding]:
    out: List[Finding] = []
    server = root.headers.get("server", "")
    powered = root.headers.get("x-powered-by", "")
    if re.search(r"\d", server):
        out.append(_f(t, "WEB-SERVER-VERSION", "Server header discloses version",
                      Severity.LOW, "misconfig", "CWE-200",
                      "Exact versions help attackers choose exploits.",
                      "Suppress version detail (e.g. ServerTokens Prod, server_tokens off).",
                      evidence=f"Server: {server}"))
    if powered:
        out.append(_f(t, "WEB-X-POWERED-BY", "X-Powered-By header discloses technology",
                      Severity.LOW, "misconfig", "CWE-200",
                      "The header reveals the application stack and often its version.",
                      "Remove the X-Powered-By header.", evidence=f"X-Powered-By: {powered}"))
    for value in (server, powered):
        out.extend(version_findings(t.host, t.port, value))
    return out


SESSION_NAME = re.compile(r"(sess|sid|token|auth|jwt|login)", re.I)


def check_cookies(t: WebTarget, root: Response) -> List[Finding]:
    out: List[Finding] = []
    for raw in root.cookies:
        parts = [p.strip() for p in raw.split(";")]
        name = parts[0].split("=", 1)[0]
        attrs = {p.split("=", 1)[0].lower() for p in parts[1:]}
        samesite = next((p.split("=", 1)[1].lower() for p in parts[1:]
                         if p.lower().startswith("samesite=") and "=" in p), "")
        sensitive = bool(SESSION_NAME.search(name))
        sev = Severity.MEDIUM if sensitive else Severity.LOW
        if t.tls and "secure" not in attrs:
            out.append(_f(t, f"WEB-COOKIE-NO-SECURE:{name}", f"Cookie '{name}' missing Secure flag",
                          sev, "auth", "CWE-614",
                          "The cookie can be sent over unencrypted connections.",
                          "Set the Secure attribute on all cookies served over HTTPS.", evidence=raw[:100]))
        if "httponly" not in attrs:
            out.append(_f(t, f"WEB-COOKIE-NO-HTTPONLY:{name}", f"Cookie '{name}' missing HttpOnly flag",
                          sev, "auth", "CWE-1004",
                          "Client-side script can read the cookie, so XSS leads to session theft.",
                          "Set the HttpOnly attribute on cookies that scripts do not need.",
                          evidence=raw[:100]))
        if not samesite:
            out.append(_f(t, f"WEB-COOKIE-NO-SAMESITE:{name}", f"Cookie '{name}' missing SameSite attribute",
                          Severity.LOW, "auth", "CWE-1275",
                          "Without SameSite the cookie is sent on cross-site requests (CSRF exposure).",
                          "Set SameSite=Lax (or Strict) unless cross-site use is required.",
                          evidence=raw[:100]))
    return out


# --- A01: CORS ------------------------------------------------------------------

def check_cors(t: WebTarget) -> List[Finding]:
    probe_origin = "https://vulnscan-probe.invalid"
    r = fetch(t, "/", headers={"Origin": probe_origin})
    if not r:
        return []
    acao = r.headers.get("access-control-allow-origin", "")
    creds = r.headers.get("access-control-allow-credentials", "").lower() == "true"
    if acao == probe_origin and creds:
        return [_f(t, "WEB-CORS-REFLECT-CREDS", "CORS reflects arbitrary origin with credentials",
                   Severity.HIGH, "access_control", "CWE-942",
                   "Any website can make authenticated cross-origin requests and read the responses.",
                   "Validate Origin against a fixed allow-list and never reflect it blindly.",
                   evidence=f"ACAO: {acao}; ACAC: true")]
    if acao == probe_origin:
        return [_f(t, "WEB-CORS-REFLECT", "CORS reflects arbitrary origin",
                   Severity.MEDIUM, "access_control", "CWE-942",
                   "Any website can read responses cross-origin (unauthenticated data only).",
                   "Validate Origin against a fixed allow-list.", evidence=f"ACAO: {acao}")]
    if acao == "*":
        return [_f(t, "WEB-CORS-WILDCARD", "CORS allows any origin (*)",
                   Severity.LOW, "access_control", "CWE-942",
                   "Fine for fully public data, risky if anything sensitive is served here.",
                   "Restrict to specific origins unless the content is intentionally public.",
                   evidence="ACAO: *")]
    return []


# --- A02: cleartext login ---------------------------------------------------------

def check_cleartext_login(t: WebTarget, root: Response) -> List[Finding]:
    if t.tls or not re.search(r"""type\s*=\s*["']?password""", root.text, re.I):
        return []
    return [_f(t, "WEB-LOGIN-OVER-HTTP", "Login form served over plain HTTP",
               Severity.HIGH, "crypto", "CWE-319",
               "Credentials are sent in cleartext and can be captured on the network path.",
               "Serve all authenticated pages over HTTPS and redirect HTTP to HTTPS.",
               evidence="password input found on / over http")]


def check_https_redirect(t: WebTarget, root: Response) -> List[Finding]:
    if t.tls or not t.https_available:
        return []
    loc = root.headers.get("location", "")
    if root.status in (301, 302, 307, 308) and loc.lower().startswith("https://"):
        return []
    return [_f(t, "WEB-NO-HTTPS-REDIRECT", "HTTP does not redirect to HTTPS",
               Severity.LOW, "crypto", "CWE-319",
               "The host serves HTTPS but still answers plain HTTP without redirecting.",
               "Redirect all HTTP requests to HTTPS and enable HSTS.",
               evidence=f"HTTP {root.status}")]


# --- A05: methods, exposed files, directory listing --------------------------------

def check_methods(t: WebTarget) -> List[Finding]:
    out: List[Finding] = []
    opt = fetch(t, "/", method="OPTIONS")
    if opt:
        allowed = {m.strip().upper() for m in opt.headers.get("allow", "").split(",") if m.strip()}
        risky = sorted(allowed & {"PUT", "DELETE"})
        if risky:
            out.append(_f(t, "WEB-RISKY-METHODS", "State-changing HTTP methods advertised",
                          Severity.MEDIUM, "misconfig", "CWE-650",
                          "PUT/DELETE are advertised on the web root; verify they require authentication.",
                          "Disable unneeded HTTP methods at the server or reverse proxy.",
                          evidence=f"Allow: {', '.join(sorted(allowed))}"))
    tr = fetch(t, "/", method="TRACE")
    if tr and tr.status == 200 and b"TRACE /" in tr.body:
        out.append(_f(t, "WEB-TRACE-ENABLED", "HTTP TRACE method enabled",
                      Severity.MEDIUM, "misconfig", "CWE-693",
                      "TRACE echoes requests back and enables cross-site tracing in legacy scenarios.",
                      "Disable TRACE (TraceEnable off / equivalent).",
                      evidence="TRACE / returned 200 and echoed the request"))
    return out


# (path, check_id, title, severity, category, cwe, signature(response) -> bool, fix)
SENSITIVE_PATHS: List[tuple] = [
    ("/.git/HEAD", "WEB-EXPOSED-GIT", "Exposed .git repository", Severity.HIGH, "misconfig", "CWE-538",
     lambda r: r.status == 200 and r.text.startswith("ref:"),
     "Block access to dot-directories and never deploy the .git folder."),
    ("/.env", "WEB-EXPOSED-ENV", "Exposed .env configuration file", Severity.HIGH, "misconfig", "CWE-538",
     lambda r: r.status == 200 and "html" not in r.headers.get("content-type", "")
     and re.search(r"^[A-Z][A-Z0-9_]{2,}=", r.text, re.M) is not None,
     "Remove the file from the web root, rotate every secret it contained."),
    ("/phpinfo.php", "WEB-EXPOSED-PHPINFO", "phpinfo() page exposed", Severity.MEDIUM, "misconfig", "CWE-200",
     lambda r: r.status == 200 and ("phpinfo()" in r.text or "PHP Version" in r.text),
     "Delete diagnostic scripts from production."),
    ("/server-status", "WEB-EXPOSED-SERVER-STATUS", "Apache server-status exposed", Severity.MEDIUM,
     "misconfig", "CWE-200",
     lambda r: r.status == 200 and "Apache Server Status" in r.text,
     "Restrict mod_status to localhost or management networks."),
    ("/.DS_Store", "WEB-EXPOSED-DSSTORE", "macOS .DS_Store file exposed", Severity.LOW, "misconfig", "CWE-538",
     lambda r: r.status == 200 and b"Bud1" in r.body[:16],
     "Remove .DS_Store files from deployments."),
    ("/backup.sql", "WEB-EXPOSED-BACKUP", "Database backup exposed", Severity.HIGH, "misconfig", "CWE-530",
     lambda r: r.status == 200 and re.search(r"(CREATE TABLE|INSERT INTO)", r.text) is not None,
     "Remove backups from the web root and rotate affected credentials."),
    ("/actuator/env", "WEB-EXPOSED-ACTUATOR", "Spring Boot actuator /env exposed", Severity.HIGH,
     "misconfig", "CWE-200",
     lambda r: r.status == 200 and "propertySources" in r.text,
     "Secure or disable actuator endpoints."),
    ("/phpmyadmin/", "WEB-EXPOSED-PHPMYADMIN", "phpMyAdmin reachable", Severity.MEDIUM,
     "access_control", "CWE-284",
     lambda r: r.status == 200 and "phpMyAdmin" in r.text,
     "Restrict database admin tools to management networks."),
]

DIR_LISTING_PATHS = ["/", "/uploads/", "/backup/", "/files/", "/images/", "/static/", "/assets/"]
DIR_LISTING_SIGNATURES = ("Index of /", "Directory listing for", "<title>Directory Listing")


def check_sensitive_paths(t: WebTarget) -> List[Finding]:
    out: List[Finding] = []
    for path, cid, title, sev, cat, cwe, sig, fix in SENSITIVE_PATHS:
        r = fetch(t, path)
        if r and sig(r):
            out.append(_f(t, cid, title, sev, cat, cwe,
                          f"{path} returned content matching a known sensitive-file signature.",
                          fix, evidence=f"GET {path} -> {r.status}"))
    return out


def check_directory_listing(t: WebTarget) -> List[Finding]:
    out: List[Finding] = []
    for path in DIR_LISTING_PATHS:
        r = fetch(t, path)
        if r and r.status == 200 and any(s in r.text for s in DIR_LISTING_SIGNATURES):
            out.append(_f(t, "WEB-DIR-LISTING", "Directory listing enabled",
                          Severity.MEDIUM, "misconfig", "CWE-548",
                          "Automatic directory indexes reveal file names and may expose sensitive files.",
                          "Disable autoindex/Options -Indexes and add index files.",
                          evidence=f"GET {path} -> directory index"))
            break
    return out


# --- A10 / A05 (injection indicators): error handling and reflection -------------

ERROR_SIGNATURES = [
    (r"Traceback \(most recent call last\)", "Python stack trace"),
    (r"at (java|org|com)\.[\w.$]+\(", "Java stack trace"),
    (r"System\.\w+Exception", ".NET exception"),
    (r"Fatal error: Uncaught", "PHP fatal error"),
    (r"You're seeing this error because you have <code>DEBUG = True", "Django debug mode"),
    (r"Whoops, looks like something went wrong", "Laravel debug page"),
]
SQL_ERROR_SIGNATURES = [
    r"You have an error in your SQL syntax", r"SQLSTATE\[", r"ORA-\d{5}",
    r"unclosed quotation mark", r"pg_query\(\)", r"SQLite3::",
]


def check_error_handling(t: WebTarget) -> List[Finding]:
    out: List[Finding] = []
    not_found = fetch(t, f"/vulnscan-{secrets.token_hex(4)}")
    sqli = fetch(t, "/?vulnscan_id=1%27%22")
    for resp in (not_found, sqli):
        if not resp:
            continue
        for rx, label in ERROR_SIGNATURES:
            if re.search(rx, resp.text):
                out.append(_f(t, "WEB-VERBOSE-ERRORS", "Verbose error output / debug mode",
                              Severity.MEDIUM, "exceptions", "CWE-209",
                              "Error pages expose internals (paths, frameworks, code) useful for attack planning.",
                              "Disable debug mode and return generic error pages; log details server-side.",
                              evidence=label))
                break
        else:
            continue
        break
    if sqli:
        for rx in SQL_ERROR_SIGNATURES:
            if re.search(rx, sqli.text):
                out.append(_f(t, "WEB-SQL-ERROR", "Possible SQL error disclosure (verify manually)",
                              Severity.MEDIUM, "injection", "CWE-89",
                              "A single quote in a parameter produced a database error message, which "
                              "often indicates unparameterized queries. This is an indicator, not proof.",
                              "Use parameterized queries and suppress database errors in responses.",
                              evidence=f"GET /?vulnscan_id=1'\" -> matched {rx}"))
                break
    return out


def check_reflection(t: WebTarget) -> List[Finding]:
    canary = f"vs{secrets.token_hex(3)}\"><vsx>"
    q = quote(canary, safe="")
    path = "/?" + "&".join(f"{p}={q}" for p in ("q", "search", "s", "query", "name"))
    r = fetch(t, path)
    if r and canary in r.text:
        return [_f(t, "WEB-REFLECTED-INPUT", "Unescaped input reflected (possible reflected XSS, verify manually)",
                   Severity.MEDIUM, "injection", "CWE-79",
                   "A benign marker containing HTML metacharacters was echoed back unencoded.",
                   "Contextually encode all user-controlled output; add a strict CSP.",
                   evidence="marker with \"><tag> reflected unescaped")]
    return []


# --- A08: third-party scripts without SRI -------------------------------------------

class _ExternalAssets(HTMLParser):
    def __init__(self, own_host: str) -> None:
        super().__init__()
        self.own_host = own_host
        self.missing: List[str] = []

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        url = a.get("src") if tag == "script" else (
            a.get("href") if tag == "link" and "stylesheet" in (a.get("rel") or "").lower() else None)
        if not url:
            return
        if url.startswith("//"):
            url = "https:" + url
        parts = urlsplit(url)
        if parts.scheme in ("http", "https") and parts.hostname and parts.hostname != self.own_host \
                and "integrity" not in a:
            self.missing.append(url)


def check_sri(t: WebTarget, root: Response) -> List[Finding]:
    if not root.is_html:
        return []
    parser = _ExternalAssets(t.host)
    try:
        parser.feed(root.text)
    except Exception:  # malformed HTML must never abort a scan
        return []
    if not parser.missing:
        return []
    return [_f(t, "WEB-NO-SRI", "Third-party resources loaded without Subresource Integrity",
               Severity.LOW, "integrity", "CWE-829",
               "If the external host is compromised, malicious code runs in your origin.",
               "Add integrity= and crossorigin= attributes, or self-host the resources.",
               evidence=", ".join(parser.missing[:3]))]


# --- orchestration --------------------------------------------------------------------

def run_web_checks(host: str, address: str, port: int, tls: bool, timeout: float = 4.0,
                   https_available: bool = False) -> List[Finding]:
    t = WebTarget(host, address, port, tls, timeout, https_available)
    root = fetch(t, "/")
    if root is None:
        return []
    findings: List[Finding] = []
    for fn in (check_headers, check_disclosure, check_cookies, check_cleartext_login,
               check_https_redirect, check_sri):
        findings.extend(fn(t, root))
    for fn in (check_cors, check_methods, check_sensitive_paths, check_directory_listing,
               check_error_handling, check_reflection):
        findings.extend(fn(t))
    return findings
