#!/usr/bin/env bash
# =============================================================================
# scan-cve.sh [--severity LEVELS] [--all]
#
# Installs Trivy and scans the installed OS packages for known CVEs — the
# "are you patched?" axis, complementary to config hardening. Read-only.
#   --severity  default HIGH,CRITICAL (or: LOW,MEDIUM,HIGH,CRITICAL)
#   --all       also scan application dependencies found under / (slower)
# Report -> /var/log/hardening-audit/trivy-report.txt
# =============================================================================
set -euo pipefail

SELF="$(cd "$(dirname "$0")" && pwd)"
. "$SELF/lib/common.sh"
require_root

SEV="${TRIVY_SEVERITY:-HIGH,CRITICAL}"; SCOPE="--pkg-types os"
while [ $# -gt 0 ]; do
  case "$1" in
    --severity) SEV="${2:?}"; shift ;;
    --all) SCOPE="" ;;
    *) die "usage: scan-cve.sh [--severity L] [--all]" ;;
  esac; shift
done
OUT="/var/log/hardening-audit"; mkdir -p "$OUT"

# --- install Trivy (Aqua apt repo) -------------------------------------------
if ! command -v trivy >/dev/null 2>&1; then
  log "installing Trivy (official installer -> /usr/local/bin)"
  dpkg -s curl >/dev/null 2>&1 || DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends curl ca-certificates >/dev/null 2>&1 || true
  curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin \
    || die "Trivy install failed (needs internet to github). See https://trivy.dev/latest/getting-started/installation/"
  hash -r
fi
info "trivy $(trivy --version 2>/dev/null | head -1)"

# --- scan --------------------------------------------------------------------
log "scanning installed packages for CVEs (severity: $SEV) — first run downloads the vuln DB"
# shellcheck disable=SC2086
trivy rootfs --scanners vuln $SCOPE --severity "$SEV" --no-progress / \
  | tee "$OUT/trivy-report.txt" | tail -40 || true

echo
if grep -qE '^Total: ' "$OUT/trivy-report.txt"; then
  log "CVE summary:"; grep -E '^Total: ' "$OUT/trivy-report.txt" | sed 's/^/    /'
else
  log "no vulnerabilities at severity $SEV (or nothing to report)."
fi
info "full report: $OUT/trivy-report.txt"
info "remediation = apply security updates:  apt-get update && apt-get upgrade   (unattended-upgrades is enabled)"
