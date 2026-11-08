#!/usr/bin/env bash
# demo.sh - quick offline-friendly demo of the *network scan* half of vulnscan.
#
# Starts the bundled deliberately-misconfigured web server on 127.0.0.1 (nothing
# leaves your machine), scans it, and builds the reports. This is a smoke test and
# a way to see the report format. To assess a real system, use:
#   python3 -m vulnscan audit        (installed-software vulnerabilities)
#   python3 -m vulnscan scan <host>  (exposed services and web misconfigurations)
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PYTHON="${PYTHON:-python3}"
HTTP_PORT="${HTTP_PORT:-8099}"
TLS_PORT="${TLS_PORT:-8443}"

TMP="$(mktemp -d)"
PIDS=()
cleanup() {
  for pid in "${PIDS[@]:-}"; do
    if [[ -n "$pid" ]]; then kill "$pid" 2>/dev/null || true; fi
  done
  rm -rf "$TMP"
}
trap cleanup EXIT

echo "==> Starting lab web server on 127.0.0.1:$HTTP_PORT"
"$PYTHON" "$ROOT/lab/vuln_server.py" --port "$HTTP_PORT" >/dev/null &
PIDS+=($!)
PORTS="$HTTP_PORT"

if command -v openssl >/dev/null; then
  echo "==> Starting TLS lab server (self-signed cert) on 127.0.0.1:$TLS_PORT"
  openssl req -x509 -newkey rsa:2048 -nodes -days 30 -subj "/CN=lab.local" \
    -keyout "$TMP/key.pem" -out "$TMP/cert.pem" >/dev/null 2>&1
  "$PYTHON" "$ROOT/lab/vuln_server.py" --port "$TLS_PORT" \
    --tls-cert "$TMP/cert.pem" --tls-key "$TMP/key.pem" >/dev/null &
  PIDS+=($!)
  PORTS="$HTTP_PORT,$TLS_PORT"
fi

for _ in $(seq 1 50); do
  if "$PYTHON" -c 'import socket, sys; socket.create_connection(("127.0.0.1", int(sys.argv[1])), 0.2).close()' "$HTTP_PORT" 2>/dev/null; then
    break
  fi
  sleep 0.1
done

"$ROOT/scripts/assess.sh" scan 127.0.0.1 -p "$PORTS" || [[ $? -eq 2 ]]
