#!/usr/bin/env bash
# =============================================================================
# audit-cis.sh [--level2] [--profile NAME] [--remediate]
#
# OpenSCAP evaluation against the CIS benchmark using the SCAP Security Guide
# (ubuntu2204 datastream). Produces an HTML report + pass/fail score.
# READ-ONLY by default. --remediate APPLIES fixes (RISKY — opt-in; re-test after).
#
# Report -> /var/log/hardening-audit/cis-report.html
# =============================================================================
set -euo pipefail

SELF="$(cd "$(dirname "$0")" && pwd)"
. "$SELF/lib/common.sh"
require_root

PROFILE="cis_level1_server"; REMEDIATE=""
while [ $# -gt 0 ]; do
  case "$1" in
    --level2)    PROFILE="cis_level2_server" ;;
    --profile)   PROFILE="${2:?}"; shift ;;
    --remediate) REMEDIATE="--remediate" ;;
    *) die "usage: audit-cis.sh [--level2 | --profile NAME] [--remediate]" ;;
  esac; shift
done
OUT="/var/log/hardening-audit"; mkdir -p "$OUT"
SSG_VER="${SSG_VERSION:-0.1.73}"

apti() { for p in "$@"; do dpkg -s "$p" >/dev/null 2>&1 || DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends "$p" >/dev/null 2>&1; done; }

# --- oscap + datastream ------------------------------------------------------
# On Ubuntu the `oscap` binary is shipped by libopenscap8 (not openscap-scanner).
if ! command -v oscap >/dev/null 2>&1; then
  log "installing OpenSCAP (libopenscap8)"
  DEBIAN_FRONTEND=noninteractive apt-get update -qq 2>/dev/null || true
  DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends libopenscap8 \
    || die "could not install OpenSCAP (libopenscap8)"
fi

DS=""
for p in /usr/share/xml/scap/ssg/content/ssg-ubuntu2204-ds.xml /opt/ssg/*/ssg-ubuntu2204-ds.xml /opt/ssg/ssg-ubuntu2204-ds.xml; do
  [ -f "$p" ] && { DS="$p"; break; }
done
if [ -z "$DS" ]; then
  apti ssg-debian 2>/dev/null || true
  [ -f /usr/share/xml/scap/ssg/content/ssg-ubuntu2204-ds.xml ] && DS=/usr/share/xml/scap/ssg/content/ssg-ubuntu2204-ds.xml
fi
if [ -z "$DS" ]; then
  log "downloading SCAP Security Guide v${SSG_VER} (ubuntu2204 datastream)"
  apti wget unzip
  mkdir -p /opt/ssg
  wget -q "https://github.com/ComplianceAsCode/content/releases/download/v${SSG_VER}/scap-security-guide-${SSG_VER}.zip" -O /opt/ssg/ssg.zip \
    || die "SSG download failed (internet?). Set SSG_VERSION to an available release."
  # extract ONLY the ubuntu2204 datastream (the full zip is ~1GB unpacked).
  unzip -oj /opt/ssg/ssg.zip '*/ssg-ubuntu2204-ds.xml' -d /opt/ssg >/dev/null \
    || die "could not extract ssg-ubuntu2204-ds.xml from the SSG release"
  rm -f /opt/ssg/ssg.zip
  DS="$(find /opt/ssg -name 'ssg-ubuntu2204-ds.xml' | head -1)"
fi
[ -n "$DS" ] && [ -f "$DS" ] || die "no ubuntu2204 SCAP datastream found"

PID="xccdf_org.ssgproject.content_profile_${PROFILE}"
[ -n "$REMEDIATE" ] && warn "REMEDIATE mode: OpenSCAP will CHANGE the system (opt-in). Re-test the sites afterwards."
log "OpenSCAP eval — profile: ${PROFILE}  (datastream: $(basename "$DS"))"

# oscap returns 0 (all pass), 2 (some rules failed = normal), other = error.
set +e
oscap xccdf eval --profile "$PID" $REMEDIATE \
  --results "$OUT/cis-results.xml" --report "$OUT/cis-report.html" "$DS" \
  > "$OUT/cis-eval.txt" 2>&1
rc=$?
set -e
[ "$rc" -le 2 ] || { tail -5 "$OUT/cis-eval.txt" >&2; die "oscap failed (rc=$rc). Check the profile id / datastream."; }

PASS="$(grep -c 'result>pass<' "$OUT/cis-eval.txt" 2>/dev/null || true)"; PASS="${PASS:-0}"
FAIL="$(grep -c 'result>fail<' "$OUT/cis-eval.txt" 2>/dev/null || true)"; FAIL="${FAIL:-0}"
# oscap text output lines look like: "Result\tpass" — fall back to that if needed
[ "$PASS" = 0 ] && PASS="$(grep -cE '^Result[[:space:]]+pass' "$OUT/cis-eval.txt" 2>/dev/null || echo 0)"
[ "$FAIL" = 0 ] && FAIL="$(grep -cE '^Result[[:space:]]+fail' "$OUT/cis-eval.txt" 2>/dev/null || echo 0)"
TOTAL=$((PASS + FAIL)); SCORE="?"
[ "$TOTAL" -gt 0 ] && SCORE="$(( PASS * 100 / TOTAL ))%"

echo
log "===== CIS (${PROFILE}) ====="
echo "    pass  : $PASS"
echo "    fail  : $FAIL"
echo "    score : $SCORE"
echo "    report: $OUT/cis-report.html   (open in a browser)"
info "top failed rules:"
grep -B1 -E '^Result[[:space:]]+fail' "$OUT/cis-eval.txt" 2>/dev/null | grep -E '^Title' | sed 's/^Title[[:space:]]*/    - /' | head -15 || true
