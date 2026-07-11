#!/usr/bin/env bash
# =============================================================================
# audit-os.sh [--baseline | --verify]
#
# Installs Lynis (CISOfy) and audits the OS: prints the HARDENING INDEX, warnings
# and top suggestions. Lynis is READ-ONLY — it measures, it does not change the
# system. Use it as a bracket around the hardening:
#     sudo audit-os.sh --baseline     # before harden-os.sh
#     sudo harden-os.sh ...           # apply hardening
#     sudo audit-os.sh --verify       # after — see the index go up + delta
#
# Reports: /var/log/hardening-audit/  (lynis-<tag>.txt + report .dat snapshots)
# =============================================================================
set -euo pipefail

SELF="$(cd "$(dirname "$0")" && pwd)"
. "$SELF/lib/common.sh"
require_root

TAG="audit"
case "${1:-}" in
  --baseline) TAG="baseline" ;;
  --verify)   TAG="verify" ;;
  "" ) ;;
  * ) die "usage: audit-os.sh [--baseline | --verify]" ;;
esac

OUT="/var/log/hardening-audit"; mkdir -p "$OUT"
DAT="/var/log/lynis-report.dat"

# --- install Lynis -----------------------------------------------------------
if ! command -v lynis >/dev/null 2>&1; then
  log "installing lynis"
  DEBIAN_FRONTEND=noninteractive apt-get update -qq 2>/dev/null || warn "apt update failed (offline?)"
  DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends lynis \
    || die "could not install lynis (apt). For the latest, use the CISOfy apt repo."
fi
info "lynis $(lynis show version 2>/dev/null || echo '?')"

# --- audit -------------------------------------------------------------------
log "running: lynis audit system  (a few minutes, read-only)"
lynis audit system --quiet --no-colors > "$OUT/lynis-${TAG}.txt" 2>&1 || true
[ -f "$DAT" ] || die "no lynis report at $DAT — did the audit run?"
cp -f "$DAT" "$OUT/lynis-report-${TAG}.dat"

get() { grep -m1 "^$1=" "$DAT" 2>/dev/null | cut -d= -f2- ; }
INDEX="$(get hardening_index)"; INDEX="${INDEX:-?}"
NWARN="$(grep -c '^warning\[\]=' "$DAT" 2>/dev/null || echo 0)"
NSUGG="$(grep -c '^suggestion\[\]=' "$DAT" 2>/dev/null || echo 0)"

echo
log "===== Lynis result (${TAG}) ====="
echo "    HARDENING INDEX : ${INDEX}/100"
echo "    warnings        : ${NWARN}"
echo "    suggestions     : ${NSUGG}"
echo "    full report     : $OUT/lynis-${TAG}.txt   (details: /var/log/lynis.log)"

if [ "$NWARN" -gt 0 ]; then
  echo; echo "  -- warnings --"
  grep '^warning\[\]=' "$DAT" | sed -E 's/^warning\[\]=//; s/\|.*$//' | sed 's/^/    ! /' | head -20
fi
echo; echo "  -- top suggestions (testid: what) --"
grep '^suggestion\[\]=' "$DAT" | awk -F'|' '{gsub(/^suggestion\[\]=/,"",$1); printf "    [%-11s] %s\n", $1, $2}' | head -25

# --- delta vs baseline (when verifying) --------------------------------------
if [ "$TAG" = verify ] && [ -f "$OUT/lynis-report-baseline.dat" ]; then
  BINDEX="$(grep -m1 '^hardening_index=' "$OUT/lynis-report-baseline.dat" | cut -d= -f2)"
  echo; log "delta vs baseline: ${BINDEX:-?} -> ${INDEX}  (index change: $(( ${INDEX:-0} - ${BINDEX:-0} )))"
fi
echo
info "re-run after hardening with:  audit-os.sh --verify"
