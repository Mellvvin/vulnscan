"""Regenerates docs/sample-report/ from SYNTHETIC audit data plus a real scan of the bundled
lab server.  Run:  python tests/make_sample_report.py   (maintainers only; not a pytest module)."""

import os
import shutil
import sys
import tempfile
import threading

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path[:0] = [HERE, os.path.join(ROOT, "lab"), ROOT]

import fakes  # noqa: E402
from vuln_server import make_server  # noqa: E402
from vulnscan import inventory  # noqa: E402
from vulnscan.audit import AuditOptions, run_audit  # noqa: E402
from vulnscan.cache import Cache  # noqa: E402
from vulnscan.cli import main  # noqa: E402
from vulnscan.output import write_json  # noqa: E402

work = tempfile.mkdtemp()
inventory.local_system_info = lambda override=None: fakes.ubuntu_info("lab-ubuntu")
inventory.shutil.which = lambda n: "/usr/bin/" + n if n == "dpkg-query" else None
cache = Cache(os.path.join(work, "cache"))
cache.set("cwe:parents", fakes.PARENTS)
res = run_audit(AuditOptions(npm=False), fakes.FakeHttp(), cache, runner=fakes.runner)
os.makedirs(os.path.join(work, "audit"))
write_json(os.path.join(work, "audit", "results.json"),
           {"started": "2026-11-03T10:00:00+00:00", "duration_seconds": 4.2, "targets": ["lab-ubuntu"],
            "mode": "audit"}, [], res.findings, "2025",
           {"systems": [t.to_dict() for t in res.targets], "sources": res.sources,
            "warnings": ["SAMPLE REPORT: the package findings come from synthetic test data and the web "
                         "findings from the bundled lab server. It illustrates the format; it is not an "
                         "assessment of a real system."]})
srv = make_server("127.0.0.1", 0)
threading.Thread(target=srv.serve_forever, daemon=True).start()
main(["scan", "127.0.0.1", "-p", str(srv.server_address[1]), "-o", os.path.join(work, "net"), "-q", "--no-report"])
srv.shutdown()
dest = os.path.join(ROOT, "docs", "sample-report")
shutil.rmtree(dest, ignore_errors=True)
main(["report", os.path.join(work, "audit"), os.path.join(work, "net"), "-o", dest])
print("written to", dest)
