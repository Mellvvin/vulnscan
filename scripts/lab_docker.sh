#!/usr/bin/env bash
# lab_docker.sh - start the Docker lab, assess it (network scan + image audit), tear it down.
#
# Usage: scripts/lab_docker.sh [--keep]     (--keep leaves the containers running)
# Needs Docker with the Compose plugin. Everything is bound to 127.0.0.1.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COMPOSE=(docker compose -f "$ROOT/lab/docker-compose.yml")
KEEP=0
[[ "${1:-}" == "--keep" ]] && KEEP=1

command -v docker >/dev/null || { echo "error: docker not found" >&2; exit 1; }
docker info >/dev/null 2>&1 || { echo "error: the Docker engine is not running" >&2; exit 1; }

# shellcheck disable=SC2317,SC2329  # invoked through the EXIT trap
cleanup() { [[ $KEEP -eq 1 ]] || "${COMPOSE[@]}" down >/dev/null 2>&1 || true; }
trap cleanup EXIT

echo "==> Starting lab containers"
"${COMPOSE[@]}" up -d
echo "==> Waiting for services"
sleep 15

rc=0
echo "==> Exposure scan (live containers)"
"$ROOT/scripts/assess.sh" scan 127.0.0.1 -p 8081-8084 || rc=$?
echo "==> Software audit (container images)"
"$ROOT/scripts/assess.sh" audit --no-host --no-network \
  --docker vulnerables/web-dvwa --docker httpd:2.4.49 \
  --docker nginx:1.18 --docker bkimminich/juice-shop || rc=$?
echo "==> Done. Reports are under reports/ (open each report.html)."
exit "$rc"
