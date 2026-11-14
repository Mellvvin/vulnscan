import json
import threading
import urllib.request
from urllib.error import HTTPError

import pytest

from vulnscan import checklist, dnschecks, cli
from vulnscan.engage_report import render_html, render_markdown, write_report
from vulnscan.engagement import Engagement, EngagementError, finding_key, normalize_scope_entry
from vulnscan.http import HttpError
from vulnscan.webui import make_server


from datetime import datetime, timezone
GEN = datetime(2026, 11, 8, tzinfo=timezone.utc)


def make(tmp_path, scope=("127.0.0.1",)):
    return Engagement.create("Mama Njeri Fashions", list(scope), tmp_path, currency="KES")


def test_scope_normalisation():
    assert normalize_scope_entry("https://Example.com:8443/path") == "example.com"
    assert normalize_scope_entry("10.0.0.0/24") == "10.0.0.0/24"


def test_create_and_reload(tmp_path):
    eng = make(tmp_path)
    again = Engagement.load("mama-njeri-fashions", tmp_path)
    assert again.client == "Mama Njeri Fashions" and again.data["currency"] == "KES"
    with pytest.raises(EngagementError):
        make(tmp_path)
    with pytest.raises(EngagementError):
        Engagement.create("X", [], tmp_path)


def test_public_target_needs_authorization(tmp_path):
    eng = make(tmp_path, ["8.8.8.8"])
    with pytest.raises(EngagementError, match="authoriz"):
        eng.plan_scan()
    with pytest.raises(EngagementError):
        eng.set_authorization("Mama", "2999-01-01")  # future / invalid
    eng.set_authorization("Mama Njeri", "2026-11-01", "letter.pdf", "2999-01-01")
    targets, public = eng.plan_scan()
    assert public and targets
    eng.set_authorization("Mama Njeri", "2020-01-01", "", "2020-02-01")
    with pytest.raises(EngagementError, match="expired"):
        eng.plan_scan()


def test_out_of_scope_target_refused(tmp_path):
    eng = make(tmp_path)
    with pytest.raises(EngagementError):
        eng.plan_scan(["127.0.0.2"])


def test_scan_notes_and_report(lab_port, tmp_path):
    eng = make(tmp_path)
    info = eng.run_scan(ports=str(lab_port), timeout=1.0, threads=20)
    assert info["findings"] > 0
    items = eng.findings()
    key = items[0]["key"]
    eng.set_finding(key, note="<script>alert(1)</script> hostile", fix="I will fix it", price="1,500",
                    price_given=True)
    eng.set_check("acct-mfa", "fail", note="no MFA on <b>mail</b>", fix="Turn it on", price="500",
                  price_given=True)
    assert eng.offer_total() == 2000
    rows = {r["id"]: r for r in eng.checklist_rows()}
    assert rows["acct-mfa"]["effective"] == "fail"
    html = render_html(eng, GEN)
    assert "<script>alert(1)" not in html and "&lt;script&gt;" in html
    assert "<b>mail</b>" not in html
    md = render_markdown(eng, GEN)
    assert "Mama Njeri Fashions" in md
    files = write_report(eng, tmp_path / "out")
    assert all(p for p in files)
    eng.set_finding(key, status="false-positive")
    assert all(f["key"] != key for f in eng.counted_findings())
    assert Engagement.load(eng.slug, tmp_path).data["finding_notes"][key]["status"] == "false-positive"


def test_checklist_mapping():
    assert checklist.finding_item("WEB-NO-HSTS").id == "web-tls"
    rows = checklist.evaluate({}, ["WEB-NO-CSP"], ["scan"])
    by = {r["id"]: r for r in rows}
    assert by["web-headers"]["effective"] == "fail"
    assert by["web-tls"]["effective"] == "pass"
    assert by["web-login"]["effective"] == "todo" and by["web-login"]["hint"]
    assert by["mail-auth"]["effective"] == "todo"
    assert by["acct-mfa"]["auto"] == "manual" and by["pay-mpesa"]["auto"] == "not-run"
    rows = checklist.evaluate({"web-tls": {"status": "na"}}, [], ["scan"])
    assert {r["id"]: r for r in rows}["web-tls"]["effective"] == "na"


class FakeHttp:
    def __init__(self, records, fail=False):
        self.records, self.fail = records, fail

    def request(self, method, url, data=None, headers=None):
        if self.fail:
            raise HttpError("down")
        from urllib.parse import urlparse, parse_qs
        q = parse_qs(urlparse(url).query)
        name, rtype = q["name"][0].lower(), q["type"][0]
        recs = self.records.get((name, rtype))
        if recs is None:
            return json.dumps({"Status": 3}).encode()
        code = {"TXT": 16, "MX": 15}[rtype]
        return json.dumps({"Status": 0, "Answer": [{"type": code, "data": r} for r in recs]}).encode()


def test_dns_findings_for_bare_domain():
    http = FakeHttp({("shop.co.ke", "MX"): ["10 mail.shop.co.ke."]})
    findings, cov = dnschecks.run_dns_checks(["shop.co.ke"], http)
    ids = {f.check_id for f in findings}
    assert {"DNS-NO-SPF", "DNS-NO-DMARC"} <= ids and cov["status"] == "completed"


def test_dns_good_domain_and_permissive_spf():
    good = FakeHttp({("a.com", "TXT"): ['"v=spf1 include:x -all"'], ("_dmarc.a.com", "TXT"): ['"v=DMARC1; p=reject"']})
    assert dnschecks.run_dns_checks(["a.com"], good)[0] == []
    bad = FakeHttp({("b.com", "TXT"): ['"v=spf1 +all"'], ("_dmarc.b.com", "TXT"): ['"v=DMARC1; p=none"']})
    ids = {f.check_id for f in dnschecks.run_dns_checks(["b.com"], bad)[0]}
    assert ids == {"DNS-SPF-PERMISSIVE", "DNS-DMARC-MONITOR-ONLY"}


def test_dns_failure_is_not_reported_as_missing():
    findings, cov = dnschecks.run_dns_checks(["a.com"], FakeHttp({}, fail=True))
    assert findings == [] and cov["status"] == "incomplete" and cov["lookup_failed"] == ["a.com"]


def test_cli_flow(lab_port, tmp_path, capsys):
    d = str(tmp_path)
    assert cli.main(["engage", "--dir", d, "new", "Test Shop", "--scope", "127.0.0.1"]) == 0
    assert cli.main(["engage", "--dir", d, "scan", "test-shop", "-p", str(lab_port)]) == 0
    assert cli.main(["engage", "--dir", d, "findings", "test-shop"]) == 0
    assert cli.main(["engage", "--dir", d, "note", "test-shop", "1", "--note", "hi", "--price", "100"]) == 0
    assert cli.main(["engage", "--dir", d, "check", "test-shop", "acct-mfa", "fail"]) == 0
    assert cli.main(["engage", "--dir", d, "status", "test-shop"]) == 0
    assert cli.main(["engage", "--dir", d, "report", "test-shop"]) == 0
    assert cli.main(["engage", "--dir", d, "note", "test-shop", "999", "--note", "x"]) == 1
    assert cli.main(["engage", "--dir", d, "status", "nope"]) == 1


def test_webui_security_and_flow(tmp_path):
    make(tmp_path)
    srv = make_server(tmp_path, 0, "tok")
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{port}"
    try:
        def call(path, body=None, headers=None):
            h = {"X-Token": "tok"}
            h.update(headers or {})
            req = urllib.request.Request(base + path, data=json.dumps(body).encode() if body is not None else None,
                                         headers=h)
            return json.load(urllib.request.urlopen(req))

        assert call("/api/engagements")[0]["slug"] == "mama-njeri-fashions"
        st = call("/api/e/mama-njeri-fashions/check", {"id": "acct-mfa", "status": "fail", "note": "n"})
        assert {r["id"]: r for r in st["checklist"]}["acct-mfa"]["effective"] == "fail"
        with pytest.raises(HTTPError) as e:
            urllib.request.urlopen(urllib.request.Request(base + "/api/engagements"))
        assert e.value.code == 403
        with pytest.raises(HTTPError) as e:
            call("/api/engagements", headers={"Host": "evil.example"})
        assert e.value.code == 403
        with pytest.raises(HTTPError) as e:
            call("/api/engagements", headers={"Origin": "http://evil.example"})
        assert e.value.code == 403
    finally:
        srv.shutdown()
        srv.server_close()


def test_suggested_text_prefills_and_appears_in_report(lab_port, tmp_path):
    from vulnscan import explain
    assert "file sharing" in explain.suggest({"check_id": "PORT-SMB"})[0].lower()
    assert explain.suggest({"check_id": "WEB-EXPOSED-ENV"})[1]  # prefix match
    assert explain.suggest({"check_id": "X-NEW", "description": "d", "remediation": "r"}) == ("d", "r")
    eng = make(tmp_path)
    eng.run_scan(ports=str(lab_port), timeout=1.0, threads=20)
    assert all(f["suggest_note"] and f["suggest_fix"] for f in eng.findings())
    assert "What I can do about it" in render_html(eng, GEN)


def test_passing_items_are_prefilled_and_report_link_works(lab_port, tmp_path):
    rows = {r["id"]: r for r in checklist.evaluate({}, [], ["scan"])}
    assert rows["web-tls"]["effective"] == "pass"
    assert "no problems" in rows["web-tls"]["suggest_note"].lower() and rows["web-tls"]["suggest_fix"]
    rows = {r["id"]: r for r in checklist.evaluate({"acct-mfa": {"status": "fail"}}, [], [])}
    assert rows["acct-mfa"]["suggest_note"] and rows["acct-mfa"]["suggest_fix"]
    assert rows["pay-mpesa"]["suggest_note"] == ""  # still to do: nothing suggested
    make(tmp_path)
    srv = make_server(tmp_path, 0, "tok")
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        req = urllib.request.Request(f"http://127.0.0.1:{srv.server_address[1]}/report/mama-njeri-fashions",
                                     headers={"X-Token": "tok"})
        page = urllib.request.urlopen(req).read().decode()
        assert "Mama Njeri Fashions" in page
    finally:
        srv.shutdown()
        srv.server_close()


# ---- protocol identification -------------------------------------------------------------

import socket
import struct

from vulnscan import identify
from vulnscan.models import PortInfo
from vulnscan.portscan import service_findings


def fake_ex(reply):
    return lambda addr, port, payload, timeout: reply


def test_identify_redis_open_and_protected():
    ident = identify.identify("x", 6379, ex=fake_ex(b"+PONG\r\n"))
    assert ident.name == "Redis" and ident.open_access and ident.auth_required is False
    ident = identify.identify("x", 6379, ex=fake_ex(b"-NOAUTH Authentication required.\r\n"))
    assert ident.auth_required is True and not ident.open_access
    assert identify.identify("x", 6379, ex=fake_ex(b"HTTP/1.1 400 Bad\r\n")) is None
    assert identify.identify("x", 6379, ex=fake_ex(None)) is None


def test_identify_other_protocols():
    assert identify.identify("x", 11211, ex=fake_ex(b"VERSION 1.6.9\r\n")).open_access
    greet = b"\x4a\x00\x00\x00" + b"\x0a" + b"8.0.35\x00" + b"\x00" * 20
    assert "8.0.35" in identify.identify("x", 3306, ex=fake_ex(greet)).detail
    assert identify.identify("x", 5432, ex=fake_ex(b"N")).name == "PostgreSQL"
    reply = struct.pack("<iiii", 36, 1, 2004, 1) + b"\x00" * 20
    assert identify.identify("x", 27017, ex=fake_ex(reply)).name == "MongoDB"
    assert identify.identify("x", 27017, ex=fake_ex(b"garbage")) is None
    es = b'HTTP/1.1 200 OK\r\n\r\n{"cluster_name":"c","version":{"number":"7.10.2"},"tagline":"You Know, for Search"}'
    assert "7.10.2" in identify.identify("x", 9200, ex=fake_ex(es)).detail
    assert identify.identify("x", 1234, ex=fake_ex(b"x")) is None


def test_identify_over_a_real_socket():
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    port = srv.getsockname()[1]

    def serve():
        c, _ = srv.accept()
        c.recv(100)
        c.sendall(b"+PONG\r\n")
        c.close()

    threading.Thread(target=serve, daemon=True).start()
    ident = identify._redis("127.0.0.1", port, identify.exchange, 2.0)
    srv.close()
    assert ident and ident.open_access


def test_service_findings_use_the_handshake_result():
    info = PortInfo(port=6379)
    open_redis = identify.Identity("Redis", "answered PING without a password", False, True)
    f = service_findings("h", info, "127.0.0.1", open_redis, probed=True)[0]
    assert f.check_id == "PORT-DATASTORE-OPEN" and f.severity.name == "CRITICAL"
    f = service_findings("h", PortInfo(port=27017), "127.0.0.1", identify.Identity("MongoDB", "ok"), True)[0]
    assert f.check_id == "PORT-DATASTORE" and "confirmed" in f.title
    f = service_findings("h", PortInfo(port=27017), "127.0.0.1", None, probed=True)[0]
    assert f.check_id == "PORT-UNVERIFIED" and f.severity.name == "LOW"
    f = service_findings("h", PortInfo(port=445), "127.0.0.1", None, probed=True)[0]
    assert f.check_id == "PORT-SMB"  # never downgraded when a probe merely got no answer


# ---- Windows audit -----------------------------------------------------------------------

from datetime import date
from vulnscan import winaudit

GOOD = {"os": {"caption": "Windows 11 Pro"}, "firewall": [{"name": "Public", "enabled": True}],
        "defender": {"enabled": True, "realtime": True, "signature_age_days": 1}, "last_update": "2026-11-01",
        "bitlocker": [{"mount": "C:", "protected": True}], "smb1": False, "rdp_enabled": False, "uac": True,
        "guest_enabled": False, "secure_boot": True, "auto_login": False, "admin": True}


def test_winaudit_clean_machine_has_no_findings():
    findings, unchecked = winaudit.evaluate(GOOD, "pc", date(2026, 11, 14))
    assert findings == [] and unchecked == []


def test_winaudit_flags_problems_and_tracks_unchecked():
    bad = dict(GOOD, firewall=[{"name": "Public", "enabled": False}, {"name": "Private", "enabled": True}],
               defender={"enabled": True, "realtime": False, "signature_age_days": 30},
               last_update="2026-05-01", bitlocker=[{"mount": "C:", "protected": False}], smb1=True,
               rdp_enabled=True, rdp_nla=False, uac=False, guest_enabled=True, secure_boot=False,
               auto_login=True, admin=False)
    findings, unchecked = winaudit.evaluate(bad, "pc", date(2026, 11, 14))
    ids = {f.check_id for f in findings}
    assert ids == {"WIN-FIREWALL-OFF", "WIN-AV-OFF", "WIN-AV-STALE", "WIN-UPDATES-OLD", "WIN-DISK-UNENCRYPTED",
                   "WIN-SMB1", "WIN-RDP-ON", "WIN-UAC-OFF", "WIN-GUEST-ON", "WIN-SECUREBOOT-OFF",
                   "WIN-AUTOLOGIN"}
    assert any("Administrator" in u for u in unchecked)
    from vulnscan import explain
    assert all(explain.suggest({"check_id": i})[0] and i in explain.TEXT for i in ids)


def test_winaudit_unreadable_facts_are_unchecked_not_problems():
    findings, unchecked = winaudit.evaluate({"admin": False}, "pc", date(2026, 11, 14))
    assert findings == [] and len(unchecked) >= 4


def test_winaudit_collect_parses_powershell_output():
    calls = []

    def runner(cmd):
        calls.append(cmd[0])
        return 0, "warning noise\n" + json.dumps(GOOD)

    assert winaudit.collect(runner)["smb1"] is False and calls == ["powershell"]
    with pytest.raises(RuntimeError):
        winaudit.collect(lambda cmd: (1, ""))


def test_engagement_winaudit_run_feeds_checklist(tmp_path):
    eng = make(tmp_path)
    bad = dict(GOOD, smb1=True)
    eng.run_winaudit(facts=bad)
    rows = {r["id"]: r for r in eng.checklist_rows()}
    assert rows["dev-updates"]["effective"] == "fail"
    assert any(f["check_id"] == "WIN-SMB1" for f in eng.findings())
    if not winaudit.is_windows():
        with pytest.raises(EngagementError, match="Windows"):
            eng.run_winaudit()


def test_winaudit_accepts_single_object_instead_of_list():
    one = dict(GOOD, firewall={"name": "Public", "enabled": False}, bitlocker={"mount": "C:", "protected": False})
    ids = {f.check_id for f in winaudit.evaluate(one, "pc", date(2026, 11, 14))[0]}
    assert ids == {"WIN-FIREWALL-OFF", "WIN-DISK-UNENCRYPTED"}


# ---- code scan -----------------------------------------------------------------------------

import subprocess
from vulnscan import codescan
from vulnscan.cache import Cache

FAKE_KEY = "sk_live_" + "a1B2c3D4e5F6g7H8i9J0k1L2"
FAKE_MPESA = "Zx9Qm4Rt7Vb2Nk8Pw3Ls6Dh1Fj5Gc0Y"


class FakeOsv:
    def post_json(self, url, obj):
        out = []
        for q in obj["queries"]:
            hit = q["package"]["name"] == "lodash" and q["version"] == "4.17.15"
            out.append({"vulns": [{"id": "GHSA-test", "modified": "1"}]} if hit else {})
        return {"results": out}

    def get_json(self, url):
        return {"id": "GHSA-test", "aliases": ["CVE-2020-8203"], "summary": "Prototype pollution",
                "database_specific": {"severity": "HIGH"},
                "affected": [{"package": {"name": "lodash", "ecosystem": "npm"},
                              "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "4.17.19"}]}]}]}


def make_project(tmp_path):
    proj = tmp_path / "shopzone"
    proj.mkdir()
    (proj / "app.js").write_text(f'const stripe = require("stripe")("{FAKE_KEY}");\n'
                                 f'const mpesa_consumer_secret = "{FAKE_MPESA}";\n'
                                 'const password = "your_password_here";\n'
                                 'const url = process.env.DATABASE_URL;\n')
    (proj / ".env").write_text("SECRET=abcdef1234567890\n")
    (proj / "package-lock.json").write_text(json.dumps({"packages": {"": {}, "node_modules/lodash": {"version": "4.17.15"},
                                                                    "node_modules/ok": {"version": "1.0.0"}}}))
    (proj / "requirements.txt").write_text("flask==3.0.0\nrequests\n")
    (proj / "node_modules").mkdir()
    (proj / "node_modules" / "skip.js").write_text(f'"{FAKE_KEY}"')
    return proj


def test_codescan_finds_secrets_but_not_placeholders(tmp_path):
    proj = make_project(tmp_path)
    findings, notes = codescan.scan_secrets(proj, "shopzone", history=False)
    titles = [f.title for f in findings]
    assert any("Stripe live key in app.js" in t for t in titles)
    assert any("M-Pesa" in t for t in titles)
    assert not any("node_modules" in f.evidence for f in findings)
    assert not any("your_password_here" in f.evidence for f in findings)
    assert all(FAKE_KEY not in f.evidence and FAKE_MPESA not in f.evidence for f in findings)  # redacted


def test_codescan_git_history_and_tracked_env(tmp_path):
    proj = tmp_path / "p"
    proj.mkdir()
    run = lambda *a: subprocess.run(["git", "-C", str(proj), "-c", "user.email=a@b.c", "-c", "user.name=t", *a],
                                    check=True, capture_output=True)
    run("init", "-q")
    (proj / "config.py").write_text(f'KEY = "{FAKE_KEY}"\n')
    (proj / ".env").write_text("A=1\n")
    run("add", "-A")
    run("commit", "-q", "-m", "oops")
    (proj / "config.py").write_text("KEY = None\n")
    run("commit", "-qam", "removed")
    findings, _ = codescan.scan_secrets(proj, "p", history=True)
    ids = {f.check_id for f in findings}
    assert "CODE-SECRET-HISTORY" in ids and "CODE-ENV-TRACKED" in ids
    assert all(FAKE_KEY not in f.evidence for f in findings)


def test_codescan_dependencies(tmp_path):
    proj = make_project(tmp_path)
    findings, notes, checked = codescan.scan_dependencies(proj, "shopzone", FakeOsv(), Cache(tmp_path / "c"))
    assert checked == 2 + 1  # two npm packages + flask pin
    assert len(findings) == 1 and findings[0].severity.name == "HIGH"
    assert "4.17.19" in findings[0].remediation
    assert any("requests" in n and "not pinned" in n for n in notes)


def test_codescan_via_engagement_feeds_checklist(tmp_path):
    proj = make_project(tmp_path)
    eng = make(tmp_path / "eng")
    eng.run_codescan(str(proj), history=False, http=FakeOsv(), cache=Cache(tmp_path / "c"))
    rows = {r["id"]: r for r in eng.checklist_rows()}
    assert rows["code-deps"]["effective"] == "fail" and rows["pay-mpesa"]["effective"] == "fail"
    with pytest.raises(EngagementError):
        eng.run_codescan(str(tmp_path / "nope"))


# ---- crawler -----------------------------------------------------------------------------------

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from vulnscan import crawler
from vulnscan.webchecks import WebTarget

HITS = []


class Site(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def reply(self, code, body, ctype="text/html", extra=None):
        data = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        HITS.append(self.path)
        authed = "sid=abc" in (self.headers.get("Cookie") or "")
        path, _, query = self.path.partition("?")
        if path == "/":
            extra = '<a href="/secret">secret</a><a href="/leaky">leaky</a>' if authed else ""
            return self.reply(200, '<a href="/about">a</a><a href="/dashboard">d</a><a href="/search?q=x">s</a>'
                                   '<a href="/logout">out</a><a href="/delete-all">del</a>'
                                   '<form method="post" action="/login"><input name="u"><input type="password" name="p">'
                                   '</form><script src="/app.js"></script>' + extra)
        if path == "/about":
            return self.reply(200, "about us")
        if path == "/dashboard":
            return self.reply(200, "<h1>Admin dashboard</h1>")
        if path == "/search":
            return self.reply(200, "you searched " + __import__("urllib.parse").parse.unquote(query))
        if path == "/app.js":
            return self.reply(200, "fetch('/api/orders'); axios.get('/api/health')", "application/javascript")
        if path == "/api/orders":
            return self.reply(200, '[{"id":1}]', "application/json")
        if path == "/api/health":
            return self.reply(200, '{"ok":true}', "application/json")
        if path == "/secret":
            return self.reply(200, "private stuff " * 5) if authed else self.reply(302, "", extra={"Location": "/"})
        if path == "/leaky":
            return self.reply(200, "supposedly private " * 5)
        self.reply(404, "nope")


def start_site():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), Site)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def test_crawler_finds_issues_and_never_touches_destructive_links():
    srv = start_site()
    HITS.clear()
    try:
        port = srv.server_address[1]
        findings, cov = crawler.run_crawl("127.0.0.1", "127.0.0.1", port, False,
                                          headers={"Cookie": "sid=abc"})
    finally:
        srv.shutdown()
        srv.server_close()
    ids = {f.check_id for f in findings}
    assert {"WEB-SURFACE", "WEB-FORM-NO-CSRF", "WEB-REFLECTED-INPUT",
            "WEB-PRIVATE-PAGE-OPEN", "WEB-API-OPEN", "WEB-AUTH-NOT-ENFORCED"} <= ids
    leaky = [f for f in findings if f.check_id == "WEB-AUTH-NOT-ENFORCED"]
    assert len(leaky) == 1 and "/leaky" in leaky[0].evidence  # /secret redirects when logged out: fine
    assert not any(h.startswith(("/logout", "/delete-all")) for h in HITS)
    assert not any("sid=abc" in f.evidence + f.description for f in findings)  # credential never recorded
    assert cov["authenticated_crawl"] and cov["pages_found"] >= 4 and "/api/orders" in " ".join(
        f.evidence for f in findings if f.check_id == "WEB-SURFACE")


def test_crawler_anonymous_only_and_request_cap():
    srv = start_site()
    try:
        port = srv.server_address[1]
        t = WebTarget("127.0.0.1", "127.0.0.1", port, False)
        res = crawler.crawl(t, max_pages=3)
        assert len(res.pages) <= 3
        findings, cov = crawler.run_crawl("127.0.0.1", "127.0.0.1", port, False)
        assert not cov["authenticated_crawl"]
        assert not any(f.check_id == "WEB-AUTH-NOT-ENFORCED" for f in findings)
    finally:
        srv.shutdown()
        srv.server_close()


def test_engagement_crawl_enforces_scope_and_authorization(tmp_path):
    srv = start_site()
    try:
        port = srv.server_address[1]
        eng = make(tmp_path)
        info = eng.run_crawl(f"http://127.0.0.1:{port}")
        assert info["findings"] > 0
        with pytest.raises(EngagementError):
            eng.run_crawl(f"http://127.0.0.2:{port}")  # not in scope
        with pytest.raises(EngagementError):
            eng.run_crawl("ftp://127.0.0.1")
        pub = Engagement.create("Public", ["8.8.8.8"], tmp_path)
        with pytest.raises(EngagementError, match="authoriz"):
            pub.run_crawl("http://8.8.8.8")
    finally:
        srv.shutdown()
        srv.server_close()


def test_findings_from_any_run_reach_their_checklist_item():
    rows = {r["id"]: r for r in checklist.evaluate({}, ["WEB-AUTH-NOT-ENFORCED"], ["scan"])}
    assert rows["web-access"]["effective"] == "fail"
    rows = {r["id"]: r for r in checklist.evaluate({}, [], ["scan"])}
    assert rows["web-access"]["effective"] == "todo" and "site crawl" in rows["web-access"]["hint"]


# ---- Nmap / Nuclei integrations --------------------------------------------------------------

from vulnscan import external

NMAP_XML = """<nmaprun><host><ports>
<port protocol="tcp" portid="22"><state state="open"/><service name="ssh" product="OpenSSH" version="7.4"/></port>
<port protocol="tcp" portid="80"><state state="open"/><service name="http" product="Apache httpd" version="2.4.49"/></port>
<port protocol="tcp" portid="81"><state state="closed"/><service name="x"/></port>
<port protocol="tcp" portid="9"><state state="open"/><service name="discard"/></port>
</ports></host></nmaprun>"""

NUCLEI_OUT = ('{"template-id":"git-config","info":{"name":"Git config exposed","severity":"medium",'
              '"description":"d","classification":{"cwe-id":["cwe-200"],"cve-id":null}},"matched-at":"http://x/.git/config"}\n'
              'not json\n'
              '{"template-id":"old-cve","info":{"name":"Old thing","severity":"critical",'
              '"classification":{"cve-id":["CVE-2021-1"]}},"matched-at":"http://x/a"}\n'
              '{"template-id":"git-config","info":{"name":"Git config exposed","severity":"medium"},'
              '"matched-at":"http://x/.git/config"}\n')


def test_nmap_parsing_and_version_rules():
    services = external.parse_nmap_xml(NMAP_XML)
    assert [s["port"] for s in services] == [22, 80, 9]
    findings = external.nmap_findings("h", services)
    ids = {f.check_id for f in findings}
    assert "COMP-OUTDATED" in ids and "EXT-NMAP-SERVICES" in ids
    titles = " ".join(f.title for f in findings)
    assert "OpenSSH" in titles and "Apache" in titles
    assert external.parse_nmap_xml("not xml") == []


def test_nuclei_parsing_dedupes_and_maps_severity():
    f = external.parse_nuclei(NUCLEI_OUT, "x", 80)
    assert [x.check_id for x in f] == ["NUCLEI-git-config", "NUCLEI-old-cve"]
    assert f[0].cwe == "CWE-200" and f[1].severity.name == "CRITICAL" and "CVE-2021-1" in f[1].description


def test_engagement_external_tools_with_fake_runner(tmp_path):
    eng = make(tmp_path)
    info = eng.run_external("nmap", "127.0.0.1", runner=lambda cmd, t: (0, NMAP_XML))
    assert info["findings"] >= 2
    info = eng.run_external("nuclei", "http://127.0.0.1:3000", runner=lambda cmd, t: (0, NUCLEI_OUT))
    assert info["findings"] == 2
    assert any(r["id"] == "web-exposed" and r["effective"] == "fail" for r in eng.checklist_rows())
    with pytest.raises(EngagementError):
        eng.run_external("nmap", "127.0.0.2", runner=lambda c, t: (0, ""))
    with pytest.raises(EngagementError):
        eng.run_external("zap", "x")
    if not external.available("nmap"):
        with pytest.raises(EngagementError, match="not installed"):
            eng.run_external("nmap", "127.0.0.1")
