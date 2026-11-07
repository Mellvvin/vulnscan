from vulnscan.models import Severity
from vulnscan.owasp import EDITIONS, lookup
from vulnscan.versions import version_findings
from vulnscan.webchecks import run_web_checks

EXPECTED = {
    "WEB-NO-CSP", "WEB-SERVER-VERSION", "WEB-X-POWERED-BY", "WEB-LOGIN-OVER-HTTP",
    "WEB-CORS-REFLECT-CREDS", "WEB-EXPOSED-GIT", "WEB-EXPOSED-ENV", "WEB-EXPOSED-PHPINFO",
    "WEB-DIR-LISTING", "WEB-TRACE-ENABLED", "WEB-RISKY-METHODS", "WEB-VERBOSE-ERRORS",
    "WEB-SQL-ERROR", "WEB-REFLECTED-INPUT", "WEB-NO-SRI", "COMP-OUTDATED",
}


def _ids(findings):
    return {f.check_id.split(":")[0] for f in findings}


def test_lab_server_triggers_expected_checks(lab_port):
    findings = run_web_checks("127.0.0.1", "127.0.0.1", lab_port, tls=False)
    missing = EXPECTED - _ids(findings)
    assert not missing, f"checks that did not fire: {sorted(missing)}"


def test_no_false_positive_on_signature_checks(lab_port):
    """Paths that are not exposed must not be reported (404 page contains no signatures)."""
    ids = _ids(run_web_checks("127.0.0.1", "127.0.0.1", lab_port, tls=False))
    for absent in ("WEB-EXPOSED-DSSTORE", "WEB-EXPOSED-BACKUP", "WEB-EXPOSED-ACTUATOR",
                   "WEB-EXPOSED-PHPMYADMIN", "WEB-EXPOSED-SERVER-STATUS"):
        assert absent not in ids


def test_unreachable_port_returns_no_findings():
    assert run_web_checks("127.0.0.1", "127.0.0.1", 1, tls=False, timeout=0.3) == []


def test_cookie_flags_scored_by_name(lab_port):
    findings = run_web_checks("127.0.0.1", "127.0.0.1", lab_port, tls=False)
    sess = next(f for f in findings if f.check_id == "WEB-COOKIE-NO-HTTPONLY:PHPSESSID")
    theme = next(f for f in findings if f.check_id == "WEB-COOKIE-NO-HTTPONLY:theme")
    assert sess.severity == Severity.MEDIUM and theme.severity == Severity.LOW


def test_version_rules():
    assert version_findings("h", 22, "SSH-2.0-OpenSSH_7.4")[0].check_id == "COMP-OUTDATED"
    assert version_findings("h", 22, "SSH-2.0-OpenSSH_9.6") == []
    bad = version_findings("h", 21, "220 (vsftpd 2.3.4)")
    assert bad[0].severity == Severity.CRITICAL
    assert version_findings("h", 80, "nginx/1.25.3") == []
    assert version_findings("h", 80, "nginx/1.18.0")[0].check_id == "COMP-OUTDATED"


def test_every_category_maps_in_every_edition():
    keys = {"access_control", "misconfig", "supply_chain", "crypto", "injection",
            "insecure_design", "auth", "integrity", "logging", "exceptions"}
    for edition in EDITIONS:
        for key in keys:
            owasp_id, name = lookup(key, edition)
            assert owasp_id.endswith(edition) and name
