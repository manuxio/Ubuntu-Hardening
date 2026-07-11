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
#   --remove   delete the test page again
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
DOCROOT="$(policy_meta_get "$SITE" DOCROOT)"
WEB_USER="$(policy_meta_get "$SITE" WEB_USER)"; WEB_USER="${WEB_USER:-www-data}"
SERVER_NAME="$(policy_meta_get "$SITE" SERVER_NAME)"
PRIMARY="$(awk '{print $1}' <<< "$SERVER_NAME")"
[ -n "$DOCROOT" ] && [ -d "$DOCROOT" ] || die "docroot missing for $SITE ($DOCROOT)"

SRC="$REPO/tools/hardening-check.php"
DEST="$DOCROOT/hardening-check.php"

if [ "$REMOVE" = 1 ]; then
  rm -f "$DEST"
  log "removed test page: $DEST"
  exit 0
fi

[ -f "$SRC" ] || die "missing $SRC (is the repo complete?)"
install -o "$WEB_USER" -g "$WEB_USER" -m 640 "$SRC" "$DEST"
log "deployed test page -> $DEST"
info "owner ${WEB_USER}:${WEB_USER}, mode 640 (readable by the runtime user via the ${WEB_USER} group)"
echo
echo "    Open:  http://${PRIMARY:-$SITE.local}/hardening-check.php        (or https:// if TLS is on)"
echo "    JSON:  add  ?format=json"
echo "    When done, remove it:  deploy-test.sh $SITE --remove"
