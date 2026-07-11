#!/usr/bin/env bash
# =============================================================================
# destroy-vhost.sh <site> [--keep-user] [--yes]
#
# Removes EVERY hardening/serving artifact for a vhost — PHP-FPM pool, AppArmor
# hat, nginx site (available+enabled+snippet), per-uid egress chain, auditd rule,
# systemd sandbox drop-ins, policy state — and (by default) its runtime user.
#
# It DOES NOT delete your data: the docroot, uploaded files and the database are
# left untouched. Re-create the site later with harden-vhost.sh.
#
#   --keep-user   leave the Unix runtime user in place
#   --yes         don't prompt (ASSUME_YES)
# =============================================================================
set -euo pipefail

SELF="$(cd "$(dirname "$0")" && pwd)"
REPO="$(dirname "$SELF")"
. "$SELF/lib/common.sh"
. "$SELF/lib/policy.sh"
require_root

SITE="${1:-}"; shift 2>/dev/null || true
[ -n "$SITE" ] || die "usage: destroy-vhost.sh <site> [--keep-user] [--yes]"
[[ "$SITE" =~ ^[a-z0-9][a-z0-9_-]*$ ]] || die "bad site name '$SITE'"
case "$SITE" in www|www.*) die "refusing to operate on '$SITE'" ;; esac

KEEP_USER=0
while [ $# -gt 0 ]; do
  case "$1" in
    --keep-user) KEEP_USER=1 ;;
    --yes)       ASSUME_YES=1 ;;
    *) die "unknown option: $1" ;;
  esac; shift
done

policy_site_exists "$SITE" || die "unknown site '$SITE' (nothing to destroy). Known: $(ls "$STATE_ROOT" 2>/dev/null | tr '\n' ' ')"

PHP_VERSION="$(policy_meta_get "$SITE" PHP_VERSION)"; PHP_VERSION="${PHP_VERSION:-8.1}"
RUNTIME_USER="$(policy_meta_get "$SITE" RUNTIME_USER)"
DOCROOT="$(policy_meta_get "$SITE" DOCROOT)"

POOL="/etc/php/${PHP_VERSION}/fpm/pool.d/${SITE}.conf"
HAT="${APPARMOR_D}/${SITE}"
DROPIN_DIR="/etc/systemd/system/php${PHP_VERSION}-fpm.service.d"

warn "DESTROY vhost '$SITE' — this removes its CONFIG, not your data."
echo  "    KEEPS  : docroot ${DOCROOT:-?}  ·  uploaded files  ·  database"
echo  "    REMOVES: pool, AppArmor hat, nginx site, egress chain, auditd rule,"
echo  "             systemd sandbox, policy state$( [ "$KEEP_USER" = 0 ] && printf ', user %s' "${RUNTIME_USER:-?}" )"
confirm "Proceed with destroying '$SITE'?" || die "aborted."

# 1) nginx: drop the site (available + enabled + app snippet)
rm -f "/etc/nginx/sites-enabled/${SITE}" "/etc/nginx/sites-available/${SITE}" \
      "/etc/nginx/snippets/${SITE}-app.conf"
log "removed nginx site"

# 2) AppArmor child hat: remove the file, then reload the master (drops the hat)
if [ -f "$HAT" ]; then rm -f "$HAT"; apparmor_reload "/etc/apparmor.d/php-fpm" 2>/dev/null || true; log "removed AppArmor hat"; fi

# 3) PHP-FPM pool
rm -f "$POOL"; log "removed PHP-FPM pool"

# 4) systemd sandbox drop-ins (reach + limits)
rm -f "$DROPIN_DIR/${SITE}-reach.conf" "$DROPIN_DIR/${SITE}-limits.conf"
has_systemd && systemctl daemon-reload 2>/dev/null || true

# 5) auditd per-site rule
rm -f "/etc/audit/rules.d/site-${SITE}.rules"
command -v augenrules >/dev/null 2>&1 && { augenrules --load >/dev/null 2>&1 || true; }

# 6) policy state — remove BEFORE egress_rebuild so the site's chain disappears
rm -rf "$(policy_state_dir "$SITE")"; log "removed policy state"

# 7) rebuild egress (removes this site's chain from before.rules) + reload ufw
egress_rebuild
# drop the now-unreferenced per-uid chain from the LIVE tables too (ufw reload
# leaves an orphan empty chain otherwise)
for _ipt in iptables ip6tables; do
  command -v "$_ipt" >/dev/null 2>&1 || continue
  "$_ipt" -F "${SITE}_EGRESS" 2>/dev/null || true
  "$_ipt" -X "${SITE}_EGRESS" 2>/dev/null || true
done

# 8) reload the web stack
reload_service "php${PHP_VERSION}-fpm" 2>/dev/null || true
reload_service "nginx" 2>/dev/null || true

# 9) runtime user — userdel WITHOUT -r, so the docroot/home DATA stays on disk
if [ "$KEEP_USER" = 0 ] && [ -n "$RUNTIME_USER" ] && id "$RUNTIME_USER" >/dev/null 2>&1; then
  if userdel "$RUNTIME_USER" 2>/dev/null; then log "removed runtime user $RUNTIME_USER (its files were NOT deleted)"
  else warn "could not remove user $RUNTIME_USER (a process may still run as it)"; fi
fi

echo
log "vhost '$SITE' destroyed."
echo "    Your data is intact: ${DOCROOT:-docroot} and the database were not touched."
echo "    Re-create it any time with:  harden-vhost.sh   (or the menu -> Nuovo sito)"
