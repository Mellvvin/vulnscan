import json
import os
import shutil
import subprocess
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BASH = shutil.which("bash") if sys.platform != "win32" else None  # Bash scripts are for Linux/macOS/WSL


def run_cli(*args):
    return subprocess.run([sys.executable, "-m", "vulnscan", *args], cwd=ROOT,
                          capture_output=True, text=True, timeout=120)


def test_cli_end_to_end_outputs(lab_port, tmp_path):
    out = tmp_path / "scan"
    proc = run_cli("127.0.0.1", "-p", str(lab_port), "-o", str(out), "-q")
    assert proc.returncode == 0, proc.stderr
    data = json.loads((out / "results.json").read_text())
    assert data["meta"]["owasp_edition"] == "2025"
    assert data["summary"]["HIGH"] >= 1
    assert data["hosts"][0]["open_ports"][0]["port"] == lab_port
    assert data["hosts"][0]["exposure"]["scope"] == "localhost"
    coverage = data["coverage"]["network"]
    assert coverage["status"] == "completed" and coverage["method"] == "TCP connect"
    assert coverage["selected_tcp_ports_per_host"] == data["meta"]["ports_per_host"]
    assert "UDP services are not tested" in coverage["skipped_checks"]
    html = (out / "report.html").read_text(encoding="utf-8")
    assert "Coverage and skipped checks" in html and "localhost" in html
    assert f"{data['meta']['ports_per_host']} selected TCP ports per host" in html
    rows = (out / "findings.tsv").read_text().splitlines()
    assert rows[0].startswith("severity\thost\tport")
    assert all(len(r.split("\t")) == 10 for r in rows)


def test_cli_edition_switch_and_fail_on(lab_port, tmp_path):
    out = tmp_path / "scan"
    proc = run_cli("127.0.0.1", "-p", str(lab_port), "-o", str(out), "-q",
                   "--owasp-edition", "2021", "--fail-on", "high")
    assert proc.returncode == 2
    assert "2021" in (out / "findings.tsv").read_text()


def test_cli_refuses_public_target():
    proc = run_cli("8.8.8.8", "-p", "53", "-q")
    assert proc.returncode == 1 and "allow-public" in proc.stderr


@pytest.mark.skipif(BASH is None, reason="bash required")
def test_report_and_diff_scripts(lab_port, tmp_path):
    old, new = tmp_path / "old", tmp_path / "new"
    assert run_cli("127.0.0.1", "-p", str(lab_port), "-o", str(old), "-q").returncode == 0
    assert run_cli("127.0.0.1", "-p", str(lab_port), "-o", str(new), "-q").returncode == 0

    rep = subprocess.run([BASH, "scripts/report.sh", str(new), "--no-color"], cwd=ROOT,
                         capture_output=True, text=True)
    assert rep.returncode == 0, rep.stderr
    md = (new / "digest.md").read_text()
    assert "## By OWASP Top 10 category" in md and "A02:2025" in md
    html = (new / "report.html").read_text()  # written by the Python CLI, not the Bash digest
    assert 'id="findings"' in html and "OWASP Top 10:2025" in html

    # --fail-on gates the exit code
    gate = subprocess.run([BASH, "scripts/report.sh", str(new), "--fail-on", "HIGH", "--no-color"],
                          cwd=ROOT, capture_output=True, text=True)
    assert gate.returncode == 2

    # Remove one finding from "new" and confirm the diff reports it as resolved.
    lines = (new / "findings.tsv").read_text().splitlines()
    removed_check = lines[1].split("\t")[3]
    (new / "findings.tsv").write_text("\n".join([lines[0]] + lines[2:]) + "\n")
    diff = subprocess.run([BASH, "scripts/diff_scans.sh", str(old / "findings.tsv"),
                           str(new / "findings.tsv")], cwd=ROOT, capture_output=True, text=True)
    assert diff.returncode == 0
    assert "Resolved findings: 1" in diff.stdout and removed_check in diff.stdout


def test_python_report_escapes_hostile_findings(tmp_path):
    out = tmp_path / "scan"
    out.mkdir()
    doc = {"meta": {"owasp_edition": "2025", "version": "t"}, "summary": {}, "hosts": [], "findings": [{
        "host": "h", "port": 80, "check_id": "X", "title": "<script>alert(1)</script>", "severity": "HIGH",
        "owasp": "A02:2025", "owasp_name": "Security Misconfiguration", "cwe": "CWE-1",
        "description": "<b>d</b>", "remediation": "fix", "evidence": "\"&\""}]}
    (out / "results.json").write_text(json.dumps(doc))
    assert run_cli("report", str(out)).returncode == 0
    html = (out / "report.html").read_text()
    assert "<script>alert(1)</script>" not in html and "&lt;script&gt;alert(1)&lt;/script&gt;" in html
