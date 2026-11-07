import io
import json
import zipfile

import pytest

from vulnscan import cwe, enrich, inventory, owasp
from vulnscan.cache import Cache
from vulnscan.cvss import base_score_v3, severity_label
from vulnscan.http import Http, HttpError
from vulnscan.vercmp import compare, dpkg_compare, generic_compare, pick_fixed

PAGE = """
# A05:2025 Injection ![icon](../assets/x.png){: style="height:80px" align="right"}

## Background.
Mentions CWE-79 in prose which must not be counted.

## List of Mapped CWEs

* [CWE-20 Improper Input Validation](https://cwe.mitre.org/data/definitions/20.html)

* [CWE-79 Improper Neutralization](https://cwe.mitre.org/data/definitions/79.html)

## How to prevent
* [CWE-999 not in the list section](https://example.test)
"""


def test_parse_category_page():
    cat, name, cwes = owasp.parse_category(PAGE)
    assert (cat, name) == ("A05:2025", "Injection") and cwes == [20, 79]


def test_parse_category_2021_dash_title():
    cat, name, _ = owasp.parse_category("# A01:2021 – Broken Access Control\n## List of Mapped CWEs\n* [CWE-22 x](u)\n")
    assert (cat, name) == ("A01:2021", "Broken Access Control")


def test_bundled_snapshots_are_complete_and_consistent_with_static_names():
    for ed in ("2025", "2021"):
        snap = owasp.load_snapshot(ed)
        assert snap and len(snap.categories) == 10 and len(snap.cwe_map) > 150
        for key, (cid, name) in owasp.EDITIONS[ed].items():
            assert snap.categories[cid] == name, (ed, key)
    assert owasp.load_snapshot("2025").categories_for(79) == ["A05:2025"]


class StubHttp:
    def __init__(self, fail=False):
        self.fail = fail

    def get_json(self, url):
        raise HttpError("no listing", 403)

    def get_text(self, url):
        if self.fail:
            raise HttpError("down")
        n = int(url.split("/A")[1][:2])
        edition = url.split("/")[-4]
        return f"# A{n:02d}:{edition} Cat{n}\n## List of Mapped CWEs\n* [CWE-{n} x](u)\n"


def test_get_owasp_refreshes_caches_and_falls_back(tmp_path):
    cache = Cache(tmp_path)
    data, warns = owasp.get_owasp("2025", cache, StubHttp(), "auto")
    assert data.origin == "live" and data.categories["A03:2025"] == "Cat3" and warns == []
    again, _ = owasp.get_owasp("2025", cache, StubHttp(fail=True), "auto")
    assert again.origin == "cache"  # fresh cache wins, no network needed
    cache2 = Cache(tmp_path / "other")
    snap, warns = owasp.get_owasp("2025", cache2, StubHttp(fail=True), "auto")
    assert snap.origin == "snapshot" and warns and "snapshot" in warns[-1]
    off, warns = owasp.get_owasp("2021", cache2, StubHttp(), "offline")
    assert off.origin == "snapshot" and warns == []


CWE_XML = b"""<?xml version="1.0"?>
<Weakness_Catalog xmlns="http://cwe.mitre.org/cwe-7"><Weaknesses>
<Weakness ID="121" Name="Stack overflow"><Related_Weaknesses>
  <Related_Weakness Nature="ChildOf" CWE_ID="787" View_ID="1000" Ordinal="Primary"/>
  <Related_Weakness Nature="ChildOf" CWE_ID="555" View_ID="999"/>
</Related_Weaknesses></Weakness>
<Weakness ID="787" Name="OOB write"><Related_Weaknesses>
  <Related_Weakness Nature="ChildOf" CWE_ID="119" View_ID="1000"/></Related_Weaknesses></Weakness>
<Weakness ID="89" Name="SQLi"><Related_Weaknesses>
  <Related_Weakness Nature="ChildOf" CWE_ID="74" View_ID="1000"/></Related_Weaknesses></Weakness>
</Weaknesses></Weakness_Catalog>"""


def test_cwe_hierarchy_parse_and_resolve():
    parents = cwe.parse_cwe_xml(CWE_XML)
    assert parents == {121: [787], 787: [119], 89: [74]}
    data = owasp.OwaspData("2025", {"A05:2025": "Injection"}, {74: ["A05:2025"], 79: ["A05:2025"]})
    assert cwe.resolve_owasp(79, data, parents) == ("A05:2025", 79, False)
    assert cwe.resolve_owasp(89, data, parents) == ("A05:2025", 74, True)  # SQLi -> parent 74
    assert cwe.resolve_owasp(121, data, parents) is None  # chain never reaches an OWASP-listed CWE
    assert cwe.resolve_owasp(5, data, {5: [6], 6: [5]}) is None  # cycles terminate


def test_cwe_zip_download(tmp_path):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("cwec_v4.xml", CWE_XML)

    class H:
        def get_bytes(self, url):
            return buf.getvalue()

    assert cwe.fetch_cwe_parents(H())[121] == [787]
    parents, warns = cwe.load_cwe_parents(Cache(tmp_path), H(), "auto")
    assert parents[89] == [74] and warns == []


@pytest.mark.parametrize("vec,score", [
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0), ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
    ("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 7.8), ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0), ("CVSS:3.0/AV:P/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N", 1.6)])
def test_cvss_scores(vec, score):
    assert base_score_v3(vec) == score


def test_cvss_rejects_garbage_and_v4():
    assert base_score_v3("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N") is None
    assert base_score_v3("nonsense") is None and base_score_v3("CVSS:3.1/AV:N") is None
    assert [severity_label(x) for x in (9.8, 7.0, 4.0, 0.1, 0.0, None)] == ["CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE", None]


@pytest.mark.parametrize("a,b,want", [
    ("1.0-1", "1.0-2", -1), ("1:0.9", "2.0", 1), ("1.0~rc1", "1.0", -1), ("1.10", "1.9", 1),
    ("2.39.3-9ubuntu6.6", "2.39.3-9ubuntu6.7", -1), ("1.9.5p2-2", "1.9.5p2-3", -1), ("1.0", "1.0", 0)])
def test_dpkg_version_order(a, b, want):
    assert dpkg_compare(a, b) == want


def test_generic_and_pick_fixed():
    assert generic_compare("2.11.2", "2.11.3") < 0 and generic_compare("1.0rc1", "1.0") < 0
    assert generic_compare("1.0.1", "1.0") > 0
    assert pick_fixed("1.0-1", ["1.0-3", "1.0-2", "0.9"], "Debian:12") == "1.0-2"
    assert pick_fixed("5", [], "PyPI") == "" and pick_fixed("5", ["4"], "PyPI") == ""
    assert compare("1.2", "1.10", "npm") < 0


def test_os_release_and_ecosystems():
    assert inventory.osv_os_ecosystem("ubuntu", "22.04") == "Ubuntu:22.04:LTS"
    assert inventory.osv_os_ecosystem("ubuntu", "23.10") == "Ubuntu:23.10"
    assert inventory.osv_os_ecosystem("debian", "12") == "Debian:12"
    assert inventory.osv_os_ecosystem("alpine", "3.19.1") == "Alpine:v3.19"
    assert inventory.osv_os_ecosystem("rocky", "9.3") == "Rocky Linux"
    assert inventory.osv_os_ecosystem("almalinux", "8.9") == "AlmaLinux"
    assert inventory.osv_os_ecosystem("kali", "2024.1") is None
    info = inventory.system_info_from_os_release("x", "host", 'ID=kali\nID_LIKE=debian\nVERSION_ID="2024.1"\nPRETTY_NAME="Kali"\n')
    assert info.os_ecosystem is None and "--ecosystem" in info.notes[0]
    forced = inventory.system_info_from_os_release("x", "host", "ID=kali\nVERSION_ID=2024.1\n", "Debian:12")
    assert forced.os_ecosystem == "Debian:12" and not forced.notes


def test_package_manager_parsers():
    deb = inventory.parse_dpkg("bsdutils\t1:2.39-1\tutil-linux\t2.39-1\tii \nx\t1\tx\t1\trc \n", "Debian:12")
    assert [(p.name, p.osv_name, p.osv_version) for p in deb] == [("bsdutils", "util-linux", "2.39-1")]
    apk = inventory.parse_apk("musl-1.2.4-r2 x86_64 {musl} (MIT) [installed]\n"
                              "busybox-ssl_client-1.36.1-r5 x86_64 {busybox} (GPL-2.0-only) [installed]\n", "Alpine:v3.19")
    assert [(p.name, p.osv_name, p.version) for p in apk] == [("musl", "musl", "1.2.4-r2"),
                                                              ("busybox-ssl_client", "busybox", "1.36.1-r5")]
    rpm = inventory.parse_rpm("openssl\t1:3.0.7-1.el9\topenssl-3.0.7.src.rpm\nbash\t0:5.1-2\tbash.src.rpm\n", "Rocky Linux:9")
    assert [(p.name, p.version) for p in rpm] == [("openssl", "1:3.0.7-1.el9"), ("bash", "5.1-2")]


def test_project_files(tmp_path):
    (tmp_path / "requirements.txt").write_text("Flask==2.0.1  # web\nrequests[socks]==2.25.0\n-r other.txt\nnumpy>=1.0\n")
    (tmp_path / "web").mkdir()
    (tmp_path / "web" / "package-lock.json").write_text(json.dumps({"packages": {
        "": {"name": "app"}, "node_modules/lodash": {"version": "4.17.20"},
        "node_modules/a/node_modules/minimist": {"version": "1.2.5"}, "node_modules/local": {"link": True}}}))
    (tmp_path / "Pipfile.lock").write_text(json.dumps({"default": {"Django": {"version": "==3.0.0"}}, "develop": {}}))
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "package-lock.json").write_text("{}")
    pkgs, files = inventory.collect_project(str(tmp_path))
    got = {(p.ecosystem, p.name, p.version) for p in pkgs}
    assert got == {("PyPI", "flask", "2.0.1"), ("PyPI", "requests", "2.25.0"), ("PyPI", "django", "3.0.0"),
                   ("npm", "lodash", "4.17.20"), ("npm", "minimist", "1.2.5")}
    assert len(files) == 3
    with pytest.raises(inventory.InventoryError):
        inventory.collect_project(str(tmp_path / "missing"))


def test_package_lock_v1_format():
    pkgs = inventory.parse_package_lock(json.dumps({"dependencies": {"a": {"version": "1.0.0",
                                                    "dependencies": {"b": {"version": "2.0.0"}}}}}))
    assert {(p.name, p.version) for p in pkgs} == {("a", "1.0.0"), ("b", "2.0.0")}


def test_cve_org_record_parsing_and_urls():
    doc = {"cveMetadata": {"state": "PUBLISHED"}, "containers": {
        "cna": {"problemTypes": [{"descriptions": [{"cweId": "CWE-502", "description": "CWE-502 x"}]}],
                "metrics": [{"other": {"type": "unknown"}}]},
        "adp": [{"metrics": [{"cvssV3_1": {"baseScore": 10, "vectorString": "CVSS:3.1/AV:N"}}],
                 "problemTypes": [{"descriptions": [{"description": "CWE-400 Uncontrolled"}]}]}]}}
    rec = enrich.parse_cve_record(doc)
    assert rec["cwes"] == [502, 400] and rec["cvss"] == 10.0 and not rec["rejected"]
    assert enrich.cve_record_url("CVE-2021-44228").endswith("/cves/2021/44xxx/CVE-2021-44228.json")
    assert enrich.cve_record_url("CVE-2024-0002").endswith("/cves/2024/0xxx/CVE-2024-0002.json")
    assert enrich.cve_record_url("GHSA-1234") is None
    assert enrich.parse_cve_record({"cveMetadata": {"state": "REJECTED"}, "containers": {"cna": {}}})["rejected"]


def test_http_retries_then_raises():
    sleeps = []
    h = Http(retries=2, sleep=sleeps.append)
    with pytest.raises(HttpError, match="invalid request"):
        h.get_bytes("not a url")
    h2 = Http(timeout=0.2, retries=1, sleep=sleeps.append)
    with pytest.raises(HttpError):
        h2.get_bytes("http://127.0.0.1:1/")  # connection refused, retried once then reported
    assert sleeps  # backoff happened


def test_cache_roundtrip_and_expiry(tmp_path):
    c = Cache(tmp_path)
    c.set("k", {"a": [1, 2]})
    assert c.get("k") == {"a": [1, 2]} and c.get("k", max_age=0.0) is None and c.get("missing") is None
    assert Cache(tmp_path).get("k") == {"a": [1, 2]}  # persisted on disk
