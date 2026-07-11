#!/usr/bin/env bash
# =============================================================================
# deploy-test.sh <site> [--remove]
#
# Drops the (un-gated) hardening self-test page tools/hardening-check.php into a
# site's docroot with the CORRECT ownership for the web_user model
# (www-data:www-data, mode 640) so the PHP-FPM worker — which reaches code via
# the www-data group — can actually read and run it. This is the safe way to
# test a fresh vhost: a file copied in as root (root:root) is unreadable by the
# runtime user and yields a php-fpm "Access denied".
#
# It ALSO drops a tiny probe .php into a runtime-WRITABLE dir (e.g. images/),
# which is exactly where a webshell would land. nginx must REFUSE to execute PHP
# there (the hardening:nophp deny), so that URL MUST return 403 — the script
# checks it for you. If instead you see the probe's output, the deny is broken.
#
#   --remove   delete both test files again
#
# NOTE: temporary. Remove it (--remove) when you're done.
# =============================================================================
set -euo pipefail

SELF="$(cd "$(dirname "$0")" && pwd)"
REPO="$(dirname "$SELF")"
. "$SELF/lib/common.sh"
. "$SELF/lib/policy.sh"
require_root

SITE="${1:-}"; shift 2>/dev/null || true
[ -n "$SITE" ] || die "usage: deploy-test.sh <site> [--remove]"
REMOVE=0
[ "${1:-}" = "--remove" ] && REMOVE=1

policy_site_exists "$SITE" || die "unknown site '$SITE' (run harden-vhost.sh first)"
DOCROOT="$(policy_meta_get "$SITE" DOCROOT)"; DOCROOT="${DOCROOT%/}"
WEB_USER="$(policy_meta_get "$SITE" WEB_USER)"; WEB_USER="${WEB_USER:-www-data}"
SERVER_NAME="$(policy_meta_get "$SITE" SERVER_NAME)"
PRIMARY="$(awk '{print $1}' <<< "$SERVER_NAME")"; PRIMARY="${PRIMARY:-$SITE.local}"
[ -n "$DOCROOT" ] && [ -d "$DOCROOT" ] || die "docroot missing for $SITE ($DOCROOT)"

SRC="$REPO/tools/hardening-check.php"
DEST="$DOCROOT/hardening-check.php"
PROBE_NAME="nophp-probe.php"

# Pick the first runtime-writable dir UNDER the docroot — that's a PHP-forbidden
# dir (nginx nophp deny). Dirs outside the docroot aren't web-served, so skip.
FORBIDDEN_DIR=""; FORBIDDEN_REL=""
STATE="$(policy_state_dir "$SITE")"
if [ -f "$STATE/reach-rw.paths" ]; then
  while IFS= read -r p; do
    p="${p%/}"; [ -n "$p" ] || continue
    case "$p/" in "$DOCROOT"/*) FORBIDDEN_DIR="$p"; FORBIDDEN_REL="${p#"$DOCROOT"/}"; break ;; esac
  done < "$STATE/reach-rw.paths"
fi
PROBE="${FORBIDDEN_DIR:+$FORBIDDEN_DIR/$PROBE_NAME}"

if [ "$REMOVE" = 1 ]; then
  rm -f "$DEST"; log "removed test page: $DEST"
  [ -n "$PROBE" ] && { rm -f "$PROBE"; log "removed forbidden-dir probe: $PROBE"; }
  exit 0
fi

[ -f "$SRC" ] || die "missing $SRC (is the repo complete?)"
install -o "$WEB_USER" -g "$WEB_USER" -m 640 "$SRC" "$DEST"
log "deployed test page -> $DEST"
info "owner ${WEB_USER}:${WEB_USER}, mode 640 (readable by the runtime user via the ${WEB_USER} group)"

# The forbidden-dir probe: readable by nginx/php (so IF it ran it would print the
# marker), placed in a writable dir where nginx must refuse to execute PHP.
if [ -n "$PROBE" ] && [ -d "$FORBIDDEN_DIR" ]; then
  tmp="$(mktemp)"
  printf '%s\n' '<?php /* deploy-test nophp probe — if this runs, the writable-dir PHP deny is BROKEN */ echo "NOPHP-PROBE-EXECUTED"; ?>' > "$tmp"
  install -o "$WEB_USER" -g "$WEB_USER" -m 640 "$tmp" "$PROBE"; rm -f "$tmp"
  log "deployed forbidden-dir probe -> $PROBE"
else
  warn "no writable dir under docroot to place the forbidden-dir probe (skipping that check)"
fi

echo
echo "    Open:  http://${PRIMARY}/hardening-check.php        (or https:// if TLS is on)"
echo "    JSON:  add  ?format=json"

# Auto-verify: the docroot page should be served/executed (200); the probe in the
# writable dir MUST be blocked by nginx (403). Best-effort — needs curl + served site.
if [ -n "$PROBE" ] && command -v curl >/dev/null 2>&1; then
  _code() { curl -sk -o /dev/null -w '%{http_code}' -L \
    --resolve "${PRIMARY}:80:127.0.0.1" --resolve "${PRIMARY}:443:127.0.0.1" "$1" 2>/dev/null || echo 000; }
  echo
  fc="$(_code "http://${PRIMARY}/${FORBIDDEN_REL}/${PROBE_NAME}")"
  echo "    Forbidden-dir probe:  http://${PRIMARY}/${FORBIDDEN_REL}/${PROBE_NAME}"
  if [ "$fc" = 403 ]; then
    log  "  -> HTTP 403 as required: PHP execution in the writable dir '${FORBIDDEN_REL}/' is BLOCKED. ✓"
  elif [ "$fc" = 200 ]; then
    err  "  -> HTTP 200 — the probe RAN! The writable-dir PHP deny is NOT working. Re-run 'refresh-vhost.sh ${SITE}' and check the hardening:nophp region in the nginx snippet."
  else
    warn "  -> HTTP ${fc} (expected 403). If the site isn't served on this host you can't rely on this check; open the URL in a browser — it must be Forbidden."
  fi
fi
echo
echo "    When done, remove both:  deploy-test.sh $SITE --remove"
