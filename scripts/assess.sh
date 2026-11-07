#!/usr/bin/env bash
# assess.sh - one repeatable assessment cycle: scan/audit -> report -> diff -> archive.
#
# Usage:
#   scripts/assess.sh audit [vulnscan audit options]      e.g. audit --docker nginx:1.18
#   scripts/assess.sh scan  <targets> [vulnscan scan options]   e.g. scan 192.168.56.101
#
# Creates reports/<timestamp>/ with results.json, findings.tsv, report.html, report.md,
# digest.md, a SHA-256 manifest and a .tar.gz archive. If an earlier run of the same
# mode exists, the new and resolved findings are written to diff.txt.
# Exit status: 0 clean, 2 if --fail-on threshold hit, 3 if vulnerability data was incomplete.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PYTHON="${PYTHON:-python3}"

MODE="${1:-}"
case "$MODE" in
  audit|scan) shift ;;
  *) sed -n '2,12p' "$0" | sed 's/^# \{0,1\}//'; exit 1 ;;
esac
command -v "$PYTHON" >/dev/null || { echo "error: $PYTHON not found" >&2; exit 1; }

STAMP="$(date +%Y%m%d-%H%M%S)"
REPORTS="$ROOT/reports"
OUT="$REPORTS/$STAMP"
mkdir -p "$OUT"

# Newest earlier run of the same mode, for regression diffing.
PREV=""
while IFS= read -r dir; do
  [[ "$dir" == "$OUT" ]] && continue
  if [[ -f "$dir/results.json" ]] && grep -q "\"mode\": \"$MODE\"" "$dir/results.json" 2>/dev/null; then
    PREV="$dir/findings.tsv"; break
  fi
done < <(find "$REPORTS" -mindepth 1 -maxdepth 1 -type d -name '2*' 2>/dev/null | sort -r)

echo "==> vulnscan $MODE"
set +e
(cd "$ROOT" && "$PYTHON" -m vulnscan "$MODE" "$@" -o "$OUT" --include-data)
RC=$?
set -e
# 0 clean, 2 = --fail-on threshold, 3 = incomplete data: still digest and archive, then propagate.
[[ $RC -eq 0 || $RC -eq 2 || $RC -eq 3 ]] || exit "$RC"

echo "==> Digest"
"$ROOT/scripts/report.sh" "$OUT" --no-color

if [[ -n "$PREV" && -f "$PREV" ]]; then
  echo "==> Changes since $(basename "$(dirname "$PREV")")"
  "$ROOT/scripts/diff_scans.sh" "$PREV" "$OUT/findings.tsv" | tee "$OUT/diff.txt"
fi

echo "==> Archiving"
(cd "$OUT" && sha256sum results.json findings.tsv report.html report.md digest.md > SHA256SUMS)
tar -C "$REPORTS" -czf "$REPORTS/$MODE-$STAMP.tar.gz" "$STAMP"
echo "    $REPORTS/$MODE-$STAMP.tar.gz"
echo "==> Done. Open $OUT/report.html"
exit "$RC"
