"""Test doubles that mimic the documented shapes of OSV, CISA KEV, EPSS and CVE.org responses."""

from vulnscan import enrich, osv
from vulnscan.http import HttpError
from vulnscan.inventory import Package, SystemInfo

UBUNTU = "Ubuntu:24.04:LTS"

DPKG_OUT = (
    "sudo\t1.9.5p2-2\tsudo\t1.9.5p2-2\tii \n"
    "libfoo1\t1.0-1\tfoo\t1.0-1\tii \n"
    "libfoo-dev\t1.0-1\tfoo\t1.0-1\tii \n"
    "baz\t2.0-1\tbaz\t2.0-1\tii \n"
    "removed-pkg\t1.0\tremoved-pkg\t1.0\trc \n"
    "clean\t3.0-1\tclean\t3.0-1\tii \n"
)

PIP_OUT = '[{"name": "Jinja2", "version": "2.11.2"}, {"name": "requests", "version": "2.32.3"}]'


def ubuntu_info(label="testhost"):
    return SystemInfo(label=label, kind="host", os_id="ubuntu", os_version_id="24.04",
                      os_pretty="Ubuntu 24.04 LTS", os_ecosystem=UBUNTU, platform_name="Linux")


def runner(cmd, timeout=0):
    if cmd and cmd[0] == "dpkg-query":
        return 0, DPKG_OUT
    if "pip" in cmd:
        return 0, PIP_OUT
    return 127, ""


def aff(name, eco, fixed=None):
    events = [{"introduced": "0"}] + ([{"fixed": fixed}] if fixed else [])
    return {"package": {"name": name, "ecosystem": eco}, "ranges": [{"type": "ECOSYSTEM", "events": events}]}


RECORDS = {
    # two OSV records for the same CVE on the same package: must merge into ONE finding
    "UBUNTU-CVE-2021-3156": {
        "id": "UBUNTU-CVE-2021-3156", "aliases": ["CVE-2021-3156"], "summary": "sudo heap overflow",
        "severity": [{"type": "Ubuntu", "score": "high"}], "affected": [aff("sudo", UBUNTU, "1.9.5p2-3")],
        "references": [{"type": "WEB", "url": "https://ubuntu.com/security/CVE-2021-3156"}]},
    "USN-4705-1": {
        "id": "USN-4705-1", "aliases": ["CVE-2021-3156"], "summary": "Sudo vulnerabilities",
        "affected": [aff("sudo", UBUNTU, "1.9.5p2-3")]},
    # unrated, no CWE anywhere, no fix, hostile text in the summary
    "UBUNTU-CVE-2023-0001": {
        "id": "UBUNTU-CVE-2023-0001", "aliases": ["CVE-2023-0001"],
        "summary": "<img src=x onerror=alert(1)> foo flaw", "affected": [aff("foo", UBUNTU)]},
    # CWE only known via CVE.org, resolvable to OWASP only through the CWE hierarchy
    "UBUNTU-CVE-2024-0002": {
        "id": "UBUNTU-CVE-2024-0002", "aliases": ["CVE-2024-0002"], "summary": "baz parsing bug",
        "affected": [aff("baz", UBUNTU, "2.0-2")]},
    # GitHub-advisory style record with its own CVSS vector and CWE list
    "GHSA-g3rq-g295-4j3m": {
        "id": "GHSA-g3rq-g295-4j3m", "aliases": ["CVE-2020-28493"], "summary": "Jinja2 ReDoS",
        "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N"}],
        "database_specific": {"cwe_ids": ["CWE-79"], "severity": "MODERATE"},
        "affected": [aff("jinja2", "PyPI", "2.11.3")]},
    "GHSA-withdrawn": {"id": "GHSA-withdrawn", "withdrawn": "2024-01-01T00:00:00Z", "affected": []},
}

MATCHES = {
    (UBUNTU, "sudo", "1.9.5p2-2"): ["UBUNTU-CVE-2021-3156", "USN-4705-1"],
    (UBUNTU, "foo", "1.0-1"): ["UBUNTU-CVE-2023-0001"],
    (UBUNTU, "baz", "2.0-1"): ["UBUNTU-CVE-2024-0002"],
    ("PyPI", "jinja2", "2.11.2"): ["GHSA-g3rq-g295-4j3m", "GHSA-withdrawn"],
    (UBUNTU, "openssl", "0"): ["UBUNTU-CVE-CANARY"],  # coverage probe: release is supported by OSV
}

KEV_DOC = {"catalogVersion": "test", "dateReleased": "2026-01-01", "vulnerabilities": [{
    "cveID": "CVE-2021-3156", "vendorProject": "Sudo", "product": "Sudo", "dateAdded": "2022-04-06",
    "dueDate": "2022-04-27", "vulnerabilityName": "Sudo Heap-Based Buffer Overflow",
    "knownRansomwareCampaignUse": "Unknown", "cwes": ["CWE-193"], "requiredAction": "Apply updates."}]}


def cve_doc(cwe=None, score=None, vector=None):
    cna = {"problemTypes": [{"descriptions": [{"type": "CWE", "cweId": f"CWE-{cwe}", "lang": "en",
                                               "description": f"CWE-{cwe} thing"}]}] if cwe else []}
    adp = []
    if score:
        adp = [{"metrics": [{"cvssV3_1": {"baseScore": score, "vectorString": vector}}]}]
    return {"cveMetadata": {"state": "PUBLISHED"}, "containers": {"cna": cna, "adp": adp}}


CVE_DOCS = {
    "CVE-2021-3156": cve_doc(193, 7.8, "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"),
    "CVE-2024-0002": cve_doc(9999, 6.5, "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N"),
}
PARENTS = {"9999": [79]}  # synthetic child of CWE-79 (Injection in 2025)


class FakeHttp:
    def __init__(self, matches=None, fail_batch=False, kev=True):
        self.matches = MATCHES if matches is None else matches
        self.fail_batch = fail_batch
        self.kev = kev
        self.calls = []

    def post_json(self, url, obj):
        self.calls.append(("POST", url))
        if url != osv.BATCH_URL:
            raise HttpError("unexpected POST", 404)
        if self.fail_batch:
            raise HttpError("network error")
        out = []
        for q in obj["queries"]:
            key = (q["package"]["ecosystem"], q["package"]["name"], q["version"])
            out.append({"vulns": [{"id": i, "modified": "2026-01-01T00:00:00Z"} for i in self.matches.get(key, [])]})
        return {"results": out}

    def get_json(self, url):
        self.calls.append(("GET", url))
        if url.startswith("https://api.osv.dev/v1/vulns/"):
            vid = url.rsplit("/", 1)[1]
            if vid in RECORDS:
                return RECORDS[vid]
            raise HttpError("not found", 404)
        if url in enrich.KEV_URLS:
            if self.kev:
                return KEV_DOC
            raise HttpError("down")
        if url.startswith("https://api.first.org/data/v1/epss"):
            asked = url.split("cve=")[1].split(",")
            return {"data": [{"cve": c, "epss": "0.97000", "percentile": "0.99900"}
                             for c in asked if c == "CVE-2021-3156"]}
        if url.startswith("https://raw.githubusercontent.com/CVEProject/"):
            cve = url.rsplit("/", 1)[1][:-5]
            if cve in CVE_DOCS:
                return CVE_DOCS[cve]
            raise HttpError("not found", 404)
        raise HttpError(f"no route for {url}", 404)

    def get_bytes(self, url):
        raise HttpError("no route", 404)

    def get_text(self, url):
        raise HttpError("no route", 404)
