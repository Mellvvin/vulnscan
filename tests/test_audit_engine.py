import json
import os

import pytest

import fakes
from vulnscan import inventory, report
from vulnscan.audit import AuditOptions, run_audit
from vulnscan.cache import Cache
from vulnscan.cli import main
from vulnscan.models import Severity
from vulnscan.output import write_json


@pytest.fixture
def env(tmp_path, monkeypatch):
    monkeypatch.setattr(inventory, "local_system_info", lambda override=None: fakes.ubuntu_info())
    monkeypatch.setattr(inventory.shutil, "which", lambda name: "/usr/bin/" + name if name == "dpkg-query" else None)
    cache = Cache(tmp_path / "cache")
    cache.set("cwe:parents", fakes.PARENTS)
    return cache


def audit(cache, http=None, **kw):
    opts = AuditOptions(npm=False, **kw)
    return run_audit(opts, http or fakes.FakeHttp(), cache, runner=fakes.runner)


def by_id(result):
    return {f.check_id.split(":")[0]: f for f in result.findings}


def test_inventory_filters_removed_packages(env):
    res = audit(env)
    names = {p for t in res.targets for pk in t.packages for p in [pk.name]}
    assert "removed-pkg" not in names and "clean" in names


def test_aliases_merge_and_kev_priority(env):
    f = by_id(audit(env))["CVE-2021-3156"]
    assert f.severity == Severity.HIGH
    d = f.extra
    assert d["kev"]["added"] == "2022-04-06" and d["epss"] == pytest.approx(0.97)
    assert d["fixed"] == "1.9.5p2-3"
    assert sorted(d["advisories"]) == ["UBUNTU-CVE-2021-3156", "USN-4705-1"]
    assert d["cvss"] == 7.8 and d["severity_basis"] == "cvss"
    assert "sudo apt-get update && sudo apt-get install --only-upgrade sudo" in d["upgrade_command"]
    # CWE-193 is not on OWASP's list: falls back to the component category, and says why
    assert f.to_dict("2025")["owasp"] == "A03:2025" and "not on OWASP" in d["owasp_basis"]
    assert sum(1 for x in audit(env).findings if "CVE-2021-3156" in x.check_id) == 1


def test_binary_packages_group_under_source(env):
    f = by_id(audit(env))["CVE-2023-0001"]
    assert f.extra["packages"] == ["libfoo-dev", "libfoo1"] and f.extra["component"] == "foo"
    assert "libfoo-dev libfoo1" in f.extra["upgrade_command"]


def test_unrated_and_no_fix_are_reported_honestly(env):
    f = by_id(audit(env))["CVE-2023-0001"]
    assert f.severity == Severity.MEDIUM and "unrated" in f.extra["severity_basis"]
    assert f.extra["fixed"] == "" and "No fixed version" in f.remediation


def test_owasp_via_cwe_hierarchy_and_cve_org_enrichment(env):
    f = by_id(audit(env))["CVE-2024-0002"]
    assert f.to_dict("2025")["owasp"] == "A05:2025"
    assert "via parent CWE-79" in f.extra["owasp_basis"] and f.extra["cwes"] == ["CWE-9999"]
    assert f.severity == Severity.MEDIUM and f.extra["cvss"] == 6.5


def test_pip_package_with_osv_cwe_and_withdrawn_skipped(env):
    res = audit(env)
    f = by_id(res)["CVE-2020-28493"]
    assert f.to_dict("2025")["owasp"] == "A05:2025"
    assert f.extra["cvss"] == 5.3 and f.severity == Severity.MEDIUM and f.extra["fixed"] == "2.11.3"
    assert "GHSA-withdrawn" not in " ".join(x.check_id for x in res.findings)
    assert res.targets[0].vulnerable_components == 4


def test_edition_switch_changes_ids(env):
    res = audit(env, edition="2021")
    f = by_id(res)["CVE-2020-28493"]
    assert f.to_dict("2021")["owasp"] == "A03:2021"  # CWE-79 is Injection in 2021 (A03)
    assert by_id(res)["CVE-2021-3156"].to_dict("2021")["owasp"] == "A06:2021"  # component fallback


def test_incomplete_osv_data_is_flagged_not_clean(env):
    res = audit(env, http=fakes.FakeHttp(fail_batch=True))
    assert res.findings == []
    assert res.sources["osv"]["incomplete"] is True
    assert any("INCOMPLETE" in w for w in res.warnings)


def test_audit_survives_optional_sources_being_down(env):
    res = audit(env, http=fakes.FakeHttp(kev=False))
    assert len(res.findings) == 4
    assert any("KEV" in w for w in res.warnings)
    assert by_id(res)["CVE-2021-3156"].extra["kev"] is None


def test_second_run_uses_cache(env):
    http = fakes.FakeHttp()
    audit(env, http=http)
    first = len(http.calls)
    audit(env, http=http)
    # An unreachable OWASP source is (rightly) retried every run; everything else comes from cache.
    repeated = [c for c in http.calls[first:] if "OWASP" not in c[1]]
    assert repeated == []


def test_offline_uses_cache_only(env):
    audit(env)
    http = fakes.FakeHttp()
    res = audit(env, http=http, offline=True)
    assert http.calls == [] and len(res.findings) == 4


def test_offline_without_cache_says_unchecked(tmp_path, monkeypatch):
    monkeypatch.setattr(inventory, "local_system_info", lambda override=None: fakes.ubuntu_info())
    res = audit(Cache(tmp_path / "empty"), offline=True)
    assert res.findings == [] and res.sources["osv"]["incomplete"] is True  # unchecked != clean
    assert any("not checked" in w for w in res.warnings)


def make_doc(res, tmp_path):
    path = tmp_path / "results.json"
    write_json(str(path), {"started": "2026-11-03T10:00:00+00:00", "duration_seconds": 1.2, "targets": ["testhost"]},
               [], res.findings, "2025",
               {"systems": [t.to_dict() for t in res.targets], "sources": res.sources, "warnings": res.warnings})
    return json.loads(path.read_text())


def test_report_escapes_untrusted_text_and_shows_priorities(env, tmp_path):
    doc = make_doc(audit(env), tmp_path)
    html = report.render_html(doc)
    assert "<img src=x" not in html and "&lt;img src=x onerror=alert(1)&gt;" in html
    assert "Fix first" in html and "exploited in the wild" in html.lower()
    assert 'data-owasp="A05:2025"' in html and "not assessable" in html
    assert html.index("CVE-2021-3156") < html.index("CVE-2023-0001")  # KEV ahead of unrated
    assert "sudo apt-get update" in html and "Upgrade plan" in html
    md = report.render_markdown(doc)
    assert "## Fix first" in md and "CVE-2021-3156" in md


def test_report_merge_and_cli(env, tmp_path):
    doc = make_doc(audit(env), tmp_path)
    merged = report.merge_docs([doc, doc])
    assert len(merged["findings"]) == len(doc["findings"])
    assert main(["report", str(tmp_path)]) == 0
    assert (tmp_path / "report.html").exists() and (tmp_path / "report.md").exists()


def test_cli_audit_offline_reports_unchecked_packages(tmp_path, monkeypatch):
    monkeypatch.setenv("VULNSCAN_CACHE_DIR", str(tmp_path / "c"))
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "requirements.txt").write_text("jinja2==2.11.2\n")
    out = tmp_path / "out"
    rc = main(["audit", "--offline", "--no-host", "--project", str(proj), "-o", str(out), "-q"])
    assert rc == 3  # nothing could be checked offline: never reported as a clean result
    doc = json.loads((out / "results.json").read_text())
    assert doc["systems"][0]["packages"] == 1
    assert doc["coverage"]["network"]["status"] == "not_applicable"
    assert any("no host target" in item for item in doc["coverage"]["network"]["skipped_checks"])
    assert "local host software inventory disabled by --no-host" in doc["coverage"]["package_audit"]["skipped_checks"]
    assert any("not checked" in w for w in doc["warnings"])


def test_unsupported_release_is_not_reported_as_clean(env):
    matches = {k: v for k, v in fakes.MATCHES.items() if k[1] != "openssl"}  # OSV has nothing for this release
    res = audit(env, http=fakes.FakeHttp(matches=matches))
    assert res.sources["osv"]["unsupported_ecosystems"] == [fakes.UBUNTU]
    assert res.sources["osv"]["incomplete"] is True
    assert any("end-of-life" in w for w in res.warnings)


def test_canary_results_never_become_findings(env):
    res = audit(env)
    assert not any("CANARY" in f.check_id for f in res.findings)
    assert res.sources["osv"]["unsupported_ecosystems"] == []
