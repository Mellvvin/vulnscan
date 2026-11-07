#!/usr/bin/env python3
"""Deliberately misconfigured web server for testing vulnscan.

Every "secret" here is fake.  The server binds to 127.0.0.1 by default and
must never be exposed to an untrusted network.

    python3 lab/vuln_server.py --port 8099
    python3 lab/vuln_server.py --port 8443 --tls-cert cert.pem --tls-key key.pem
"""

import argparse
import ssl
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

INDEX = """<!doctype html>
<html><head><title>Acme Intranet (lab)</title>
<script src="https://cdn.example.net/lib.js"></script>
</head><body>
<h1>Acme Intranet</h1>
<form method="post" action="/login">
  <input name="user"><input type="password" name="pw"><button>Login</button>
</form>
{extra}
</body></html>
"""

TRACEBACK = (
    "<pre>Traceback (most recent call last):\n"
    '  File "app.py", line 42, in handle\n'
    "    raise KeyError(path)\nKeyError: 'not found'</pre>"
)


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.0"

    def version_string(self):
        return "Apache/2.4.49 (Unix)"  # fake banner: vulnerable version

    def log_message(self, *args):  # keep test output quiet
        pass

    def _send(self, status, body, ctype="text/html", head_only=False):
        data = body.encode()
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("X-Powered-By", "PHP/5.6.40")
        self.send_header("Set-Cookie", "PHPSESSID=lab123; Path=/")
        self.send_header("Set-Cookie", "theme=dark; Path=/")
        origin = self.headers.get("Origin")
        if origin:
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Access-Control-Allow-Credentials", "true")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        if not head_only:
            self.wfile.write(data)

    def _route(self, head_only=False):
        parts = urlsplit(self.path)
        path, query = parts.path, parse_qs(parts.query)
        values = [v for vs in query.values() for v in vs]

        if any("'" in v for v in values):
            return self._send(500, "You have an error in your SQL syntax; check the manual "
                                   "that corresponds to your MySQL server version", head_only=head_only)
        if path == "/":
            extra = "".join(f"<p>You searched for: {v}</p>" for v in values[:1])
            return self._send(200, INDEX.format(extra=extra), head_only=head_only)
        if path == "/.git/HEAD":
            return self._send(200, "ref: refs/heads/main\n", "text/plain", head_only)
        if path == "/.env":
            return self._send(200, "APP_ENV=production\nDB_PASSWORD=not-a-real-password\n",
                              "text/plain", head_only)
        if path == "/phpinfo.php":
            return self._send(200, "<title>phpinfo()</title><h1>PHP Version 5.6.40</h1>", head_only=head_only)
        if path == "/uploads/":
            return self._send(200, "<title>Index of /uploads</title><h1>Index of /uploads</h1>",
                              head_only=head_only)
        return self._send(404, TRACEBACK, head_only=head_only)

    def do_GET(self):
        self._route()

    def do_HEAD(self):
        self._route(head_only=True)

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Allow", "GET, HEAD, POST, OPTIONS, TRACE, PUT, DELETE")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_TRACE(self):
        self._send(200, f"TRACE {self.path} {self.request_version}\r\n", "message/http")


def make_server(host="127.0.0.1", port=0, certfile=None, keyfile=None):
    server = ThreadingHTTPServer((host, port), Handler)
    if certfile:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(certfile, keyfile)
        server.socket = ctx.wrap_socket(server.socket, server_side=True,
                                        do_handshake_on_connect=False)
    return server


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8099)
    ap.add_argument("--tls-cert")
    ap.add_argument("--tls-key")
    args = ap.parse_args()
    srv = make_server(args.host, args.port, args.tls_cert, args.tls_key)
    scheme = "https" if args.tls_cert else "http"
    print(f"lab target listening on {scheme}://{args.host}:{args.port}  (Ctrl-C to stop)", flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
