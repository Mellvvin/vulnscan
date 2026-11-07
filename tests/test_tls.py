import shutil
import sys
import subprocess
import threading

import pytest

from vuln_server import make_server
from vulnscan.tlschecks import check_tls


@pytest.mark.skipif(shutil.which("openssl") is None or sys.platform == "win32", reason="openssl required")
def test_self_signed_cert_detected(tmp_path):
    cert, key = tmp_path / "c.pem", tmp_path / "k.pem"
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "30",
                    "-subj", "/CN=lab.local", "-keyout", str(key), "-out", str(cert)],
                   check=True, capture_output=True)
    server = make_server("127.0.0.1", 0, str(cert), str(key))
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        ids = {f.check_id for f in check_tls("127.0.0.1", "127.0.0.1", server.server_address[1])}
        assert "TLS-SELF-SIGNED" in ids
    finally:
        server.shutdown()
        server.server_close()
