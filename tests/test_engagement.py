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
    assert by["pay-mpesa"]["auto"] == "manual"
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
