#!/usr/bin/env bash
# diff_scans.sh - show findings that appeared or were resolved between two scans.
#
# Usage: scripts/diff_scans.sh <old findings.tsv> <new findings.tsv>
#
# A finding is identified by host + port + check_id, so wording changes in a
# remediation text do not show up as noise.
set -euo pipefail

[[ $# -eq 2 ]] || { sed -n '2,7p' "$0" | sed 's/^# \{0,1\}//'; exit 1; }
OLD="$1"; NEW="$2"
for f in "$OLD" "$NEW"; do [[ -f "$f" ]] || { echo "error: $f not found" >&2; exit 1; }; done

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# key<TAB>severity<TAB>title, keyed on host|port|check_id
keyed() {
  tail -n +2 "$1" | awk -F'\t' 'NF >= 8 { print $2 "|" $3 "|" $4 "\t" $1 "\t" $8 }' | sort -t$'\t' -k1,1
}
keyed "$OLD" > "$WORK/old"
keyed "$NEW" > "$WORK/new"

NEW_ONLY="$(join -t$'\t' -v2 "$WORK/old" "$WORK/new" | awk -F'\t' '{ printf "  + [%s] %s  (%s)\n", $2, $3, $1 }')"
GONE="$(join -t$'\t' -v1 "$WORK/old" "$WORK/new" | awk -F'\t' '{ printf "  - [%s] %s  (%s)\n", $2, $3, $1 }')"

N_NEW=$(printf '%s' "$NEW_ONLY" | grep -c . || true)
N_GONE=$(printf '%s' "$GONE" | grep -c . || true)

echo "New findings: $N_NEW"
[[ -z "$NEW_ONLY" ]] || echo "$NEW_ONLY"
echo "Resolved findings: $N_GONE"
[[ -z "$GONE" ]] || echo "$GONE"
