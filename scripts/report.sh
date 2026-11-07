#!/usr/bin/env bash
# report.sh - terminal digest, Markdown summary and CI gate for a vulnscan result folder.
#
# Usage: scripts/report.sh <scan-dir | findings.tsv> [--fail-on SEVERITY] [--no-color]
#
# Reads findings.tsv only, so it needs nothing but bash, awk, sort and coreutils.
# The full HTML report is produced by `python3 -m vulnscan` itself; this script is
# the quick look for a headless Linux box, and the exit-code gate for pipelines.
set -euo pipefail

usage() {
  sed -n '2,9p' "$0" | sed 's/^# \{0,1\}//'
  exit "${1:-1}"
}

IN=""
FAIL_ON=""
COLOR=1
while [[ $# -gt 0 ]]; do
  case "$1" in
    -h|--help) usage 0 ;;
    --fail-on) FAIL_ON="${2:-}"; shift 2 ;;
    --no-color) COLOR=0; shift ;;
    -*) echo "unknown option: $1" >&2; usage 1 ;;
    *) IN="$1"; shift ;;
  esac
done
[[ -n "$IN" ]] || usage 1

if [[ -d "$IN" ]]; then OUTDIR="${IN%/}"; TSV="$OUTDIR/findings.tsv"
else TSV="$IN"; OUTDIR="$(dirname "$IN")"; fi
[[ -f "$TSV" ]] || { echo "error: $TSV not found" >&2; exit 1; }
[[ -t 1 ]] || COLOR=0

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
SORTED="$WORK/sorted.tsv"

# Prefix each row with a severity rank, then sort: severity, host, port, check.
tail -n +2 "$TSV" | awk -F'\t' 'BEGIN { OFS="\t"; r["CRITICAL"]=0; r["HIGH"]=1; r["MEDIUM"]=2; r["LOW"]=3; r["INFO"]=4 }
  NF >= 4 { print (($1 in r) ? r[$1] : 5), $0 }' \
  | sort -t$'\t' -k1,1n -k3,3 -k4,4n -k5,5 > "$SORTED"

TOTAL=$(wc -l < "$SORTED" | tr -d ' ')
HOSTS=$(cut -f3 "$SORTED" | sort -u | grep -c . || true)
GENERATED="$(date -u '+%Y-%m-%d %H:%M UTC')"

count_sev() { awk -F'\t' -v s="$1" '$2==s {n++} END {print n+0}' "$SORTED"; }
C_CRIT=$(count_sev CRITICAL); C_HIGH=$(count_sev HIGH); C_MED=$(count_sev MEDIUM)
C_LOW=$(count_sev LOW);       C_INFO=$(count_sev INFO)

# OWASP breakdown: "<id>\t<name>\t<count>" sorted by id.
awk -F'\t' '{ k=$6 "\t" $7; n[k]++ } END { for (k in n) print k "\t" n[k] }' "$SORTED" \
  | sort -t$'\t' -k1,1 > "$WORK/owasp.tsv"

# ---------------------------------------------------------------- Markdown digest
MD="$OUTDIR/digest.md"
{
  echo "# Findings digest"
  echo
  echo "- **Generated:** $GENERATED"
  echo "- **Targets with findings:** $HOSTS"
  echo "- **Total findings:** $TOTAL"
  echo
  echo "| Severity | Count |"
  echo "|---|---:|"
  echo "| Critical | $C_CRIT |"
  echo "| High | $C_HIGH |"
  echo "| Medium | $C_MED |"
  echo "| Low | $C_LOW |"
  echo "| Info | $C_INFO |"
  echo
  echo "## By OWASP Top 10 category"
  echo
  echo "| Category | Findings |"
  echo "|---|---:|"
  awk -F'\t' '{ printf "| %s %s | %s |\n", $1, $2, $3 }' "$WORK/owasp.tsv"
  echo
  echo "## Critical and High"
  echo
  if [[ $((C_CRIT + C_HIGH)) -eq 0 ]]; then
    echo "_None._"
  else
    awk -F'\t' '$2=="CRITICAL" || $2=="HIGH" {
      port = ($4 == "-") ? "" : ":" $4
      printf "- **%s** `%s%s` - %s (%s)\n", $2, $3, port, $9, $6 }' "$SORTED"
  fi
} > "$MD"

# ---------------------------------------------------------------- terminal summary
c() { if [[ $COLOR -eq 1 ]]; then printf '\033[%sm%s\033[0m' "$1" "$2"; else printf '%s' "$2"; fi; }
echo "Digest written: $MD"
echo -n "Findings: "
c "1;31" "CRITICAL=$C_CRIT"; echo -n "  "
c "31" "HIGH=$C_HIGH"; echo -n "  "
c "33" "MEDIUM=$C_MED"; echo -n "  "
c "36" "LOW=$C_LOW"; echo -n "  "
c "2" "INFO=$C_INFO"; echo

if [[ -n "$FAIL_ON" ]]; then
  case "${FAIL_ON^^}" in
    CRITICAL) N=$C_CRIT ;;
    HIGH)     N=$((C_CRIT + C_HIGH)) ;;
    MEDIUM)   N=$((C_CRIT + C_HIGH + C_MED)) ;;
    LOW)      N=$((C_CRIT + C_HIGH + C_MED + C_LOW)) ;;
    *) echo "error: --fail-on must be CRITICAL, HIGH, MEDIUM or LOW" >&2; exit 1 ;;
  esac
  [[ $N -eq 0 ]] || exit 2
fi
