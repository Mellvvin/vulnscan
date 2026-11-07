import builtins
import io
import json

import pytest

from vulnscan import inventory, report
from vulnscan.models import PortInfo
from vulnscan.output import write_json
from vulnscan.portscan import service_findings
from vulnscan.scope import classify_exposure


@pytest.mark.parametrize("address,scope", [
    ("127.0.0.1", "localhost"), ("::1", "localhost"),
    ("10.2.3.4", "lan"), ("192.168.1.10", "lan"), ("172.20.0.4", "lan"),
    ("169.254.1.2", "lan"), ("fd00::1", "lan"),
    ("8.8.8.8", "public"), ("2606:4700:4700::1111", "public"),
    ("192.0.2.1", "special"), ("100.64.0.1", "special"),
])
def test_exposure_classifies_destination_not_service_bind(address, scope):
    assert classify_exposure(address)["scope"] == scope


@pytest.mark.parametrize("address,scope,label", [
    ("127.0.0.1", "localhost", "localhost"),
    ("192.168.1.22", "lan", "private/LAN address"),
    ("8.8.8.8", "public", "public-routable address"),
])
def test_datastore_finding_uses_observed_scope(address, scope, label):
    finding = service_findings("target", PortInfo(port=27017, service="mongodb"), address)[0]
    assert finding.check_id == "PORT-DATASTORE"
    assert label in finding.title and "potential" in finding.title.lower()
    assert "protocol not verified" in finding.evidence
    assert "reachable over the network" not in finding.title.lower()
    assert finding.extra["exposure"]["scope"] == scope
    assert address in finding.evidence and "TCP connect" in finding.evidence
    assert "from this vantage point only" in finding.description
    assert "does not establish" in finding.description


def test_host_json_and_reports_show_exposure_and_skipped_coverage(tmp_path):
    from vulnscan.models import HostResult

    path = tmp_path / "results.json"
    write_json(str(path), {"mode": "scan"}, [HostResult("localhost", "127.0.0.1")], [], "2025",
               {"coverage": {"network": {"status": "completed", "target": "127.0.0.1",
                                           "scope": "localhost", "scanner_vantage": "this machine",
                                           "selected_tcp_ports": 36, "web_checks": "disabled",
                                           "skipped_checks": ["HTTP(S) checks disabled by --no-web"],
                                           "limitations": ["LAN reachability was not tested"]}}})
    doc = json.loads(path.read_text(encoding="utf-8"))
    assert doc["hosts"][0]["exposure"]["scope"] == "localhost"
    html = report.render_html(doc)
    assert "Coverage and skipped checks" in html
    assert "localhost" in html and "HTTP(S) checks disabled by --no-web" in html
    assert "Interpretation limits" in html and "LAN reachability was not tested" in html
    md = report.render_markdown(doc)
    assert "Coverage and skipped checks" in md and "localhost" in md
    assert "Interpretation limit: LAN reachability was not tested" in md


def test_merged_report_keeps_coverage_from_each_run(tmp_path):
    from vulnscan.models import HostResult

    base_path = tmp_path / "base.json"
    other_path = tmp_path / "other.json"
    coverage = {"network": {"status": "completed", "target": "127.0.0.1", "scope": "localhost",
                            "selected_tcp_ports": 10, "web_checks": "enabled", "skipped_checks": []},
                "package_audit": {"package_versions": 4, "unchecked_package_versions": 1,
                                  "unavailable_advisory_records": 0, "skipped_checks": []}}
    write_json(str(base_path), {"mode": "audit"}, [HostResult("local", "127.0.0.1")], [], "2025",
               {"coverage": coverage})
    other_coverage = {"network": {"status": "completed", "target": "192.168.1.9", "scope": "lan",
                                  "selected_tcp_ports": 20, "web_checks": "disabled", "skipped_checks": []},
                      "package_audit": {"package_versions": 2, "unchecked_package_versions": 0,
                                        "unavailable_advisory_records": 0, "skipped_checks": []}}
    write_json(str(other_path), {"mode": "scan"}, [HostResult("lan-host", "192.168.1.9")], [], "2025",
               {"coverage": other_coverage})
    merged = report.merge_docs([json.loads(base_path.read_text()), json.loads(other_path.read_text())])
    html = report.render_html(merged)
    assert "127.0.0.1 (localhost)" in html and "192.168.1.9 (lan)" in html
    assert "4 unique package versions" in html and "2 unique package versions" in html


@pytest.mark.parametrize("ecosystem,tool", [
    ("Debian:12", "dpkg-query"), ("Alpine:v3.19", "apk"), ("Rocky Linux", "rpm"),
])
def test_missing_os_package_manager_is_reported(ecosystem, tool, monkeypatch):
    monkeypatch.setattr(inventory.shutil, "which", lambda _name: None)
    info = inventory.SystemInfo(label="host", kind="host", os_ecosystem=ecosystem)
    assert inventory.collect_os_packages(info) == []
    assert any(tool in note and "not found" in note for note in info.notes)


@pytest.mark.parametrize("os_name", ["Windows", "Darwin", "Linux"])
def test_native_platform_audit_coverage_is_explicit(os_name, monkeypatch):
    monkeypatch.setattr(inventory.platform, "system", lambda: os_name)
    real_open = builtins.open

    def fake_open(path, *args, **kwargs):
        if os_name == "Linux" and path in ("/etc/os-release", "/usr/lib/os-release"):
            return io.StringIO('ID=ubuntu\nVERSION_ID="24.04"\nPRETTY_NAME="Ubuntu 24.04 LTS"\n')
        return real_open(path, *args, **kwargs)

    monkeypatch.setattr(builtins, "open", fake_open)
    info = inventory.local_system_info()
    if os_name == "Linux":
        assert info.platform_name == "Linux" and info.os_ecosystem == "Ubuntu:24.04:LTS"
        assert not any("not covered by OSV" in note for note in info.notes)
    else:
        assert info.platform_name == os_name and info.os_ecosystem is None
        assert any("operating-system packages are not covered" in note for note in info.notes)
        assert any("Python/npm packages" in note for note in info.notes)
