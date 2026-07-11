#!/usr/bin/env bash
# =============================================================================
# enforce-vhost.sh — flip a site's AppArmor confinement from complain to enforce,
# safely (run after the complain-mode soak).
#
# Safety features:
#   * refuses to enforce if a recent soak still shows unresolved denials for the
#     hat (override with --force);
#   * flips the per-pool CHILD hat by default (per-site, independent of other
#     sites); --with-master also enforces the shared master profile;
#   * after enforcing it restarts php-fpm, spawns a worker and health-checks it —
#     if the worker fails to enter the hat, it AUTO-ROLLS BACK to complain and
#     reports the denials to fix.
#
# Usage:
#   enforce-vhost.sh <SITE>                 # enforce the site's hat (recommended)
#   enforce-vhost.sh <SITE> --with-master   # also enforce the master (do last, once all sites soaked)
#   enforce-vhost.sh <SITE> --revert        # put the hat (and master if enforced) back to complain
#   enforce-vhost.sh <SITE> --url URL       # explicit health-check URL (else derived)
#   enforce-vhost.sh <SITE> --force         # enforce despite pending soak denials
#   enforce-vhost.sh <SITE> --dry-run       # show what would happen
# =============================================================================
set -euo pipefail

SELF="$(cd "$(dirname "$0")" && pwd)"
REPO="$(dirname "$SELF")"
. "$SELF/lib/common.sh"
. "$SELF/lib/policy.sh"
require_root

# --- args --------------------------------------------------------------------
SITE=""; WITH_MASTER=0; REVERT=0; FORCE=0; DRY=0; URL=""
while [ $# -gt 0 ]; do
  case "$1" in
    --with-master) WITH_MASTER=1 ;;
    --revert)      REVERT=1 ;;
    --force)       FORCE=1 ;;
    --dry-run)     DRY=1 ;;
    --url)         URL="${2:?}"; shift ;;
    -*)            die "unknown option: $1" ;;
    *)             [ -z "$SITE" ] && SITE="$1" || die "unexpected arg: $1" ;;
  esac
  shift
done
[ -n "$SITE" ] || die "usage: enforce-vhost.sh <SITE> [--with-master|--revert|--url URL|--force|--dry-run]"
policy_site_exists "$SITE" || die "unknown site '$SITE' — run harden-vhost.sh first"

PHP_VERSION="$(policy_meta_get "$SITE" PHP_VERSION)"
SERVER_NAME="$(policy_meta_get "$SITE" SERVER_NAME)"
MASTER="/etc/apparmor.d/php-fpm"
HAT="${APPARMOR_D}/${SITE}"
FPM="php${PHP_VERSION}-fpm"
FPM_LOG="/var/log/php${PHP_VERSION}-fpm.log"
AUDIT_LOG="/var/log/audit/audit.log"
[ -f "$HAT" ] || die "hat profile not found: $HAT (run harden-vhost.sh)"

# --- flag helpers (complain <-> enforce) -------------------------------------
# Operate ONLY on the `profile …` declaration line — a comment may legitimately
# contain the text "flags=(complain,...)" and must not be matched or edited.
profile_is_complain() { grep -qE '^[[:space:]]*profile\b.*flags=\([^)]*complain' "$1"; }
set_enforce()  { sed -i -E '/^[[:space:]]*profile\b/{ s/(flags=\()complain, */\1/; s/, *complain\)/)/; s/flags=\(complain\)/flags=()/ }' "$1"; }
set_complain() { profile_is_complain "$1" || sed -i -E '/^[[:space:]]*profile\b/ s/flags=\(/flags=(complain,/' "$1"; }

reload_master() { apparmor_parser -r "$MASTER"; }

# spawn a worker and return 0 if it served cleanly, 1 if it failed. Catches both
# hard hat-transition failures (fpm log) and a broken worker (HTTP 5xx / no
# connection). Sets HEALTH_CODE for reporting.
HEALTH_CODE=""
health_check() {
  local pos new code
  pos="$(wc -l < "$FPM_LOG" 2>/dev/null || echo 0)"
  # NB: capture curl's own http_code; don't append `|| echo 000` (curl already
  # prints "000" on failure, so appending would yield "000000" and evade the case).
  if [ -n "$URL" ]; then
    code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 8 "$URL" 2>/dev/null)" || true
  elif [ -n "$SERVER_NAME" ]; then
    code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 8 --resolve "${SERVER_NAME}:80:127.0.0.1" "http://${SERVER_NAME}/" 2>/dev/null)" || true
  else
    code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 8 http://127.0.0.1/ 2>/dev/null)" || true
  fi
  HEALTH_CODE="${code:-000}"; code="$HEALTH_CODE"
  sleep 1
  new="$(tail -n +"$((pos+1))" "$FPM_LOG" 2>/dev/null || true)"
  # hard failure: worker couldn't enter the hat
  if printf '%s' "$new" | grep -qE 'failed to change to new confinement|child failed to initialize'; then
    return 1
  fi
  # broken worker / gateway: 5xx or no connection (2xx/3xx/4xx = worker responded)
  case "$code" in 5*|000) return 1 ;; esac
  return 0
}

worker_label() { ps axZ 2>/dev/null | grep "[p]ool ${SITE}" | awk '{print $1}' | head -1; }

# --- revert mode -------------------------------------------------------------
if [ "$REVERT" -eq 1 ]; then
  log "reverting '$SITE' hat to complain"
  if [ "$DRY" -eq 1 ]; then info "would set complain on $HAT$( [ $WITH_MASTER -eq 1 ] && echo ' + '$MASTER)"; exit 0; fi
  set_complain "$HAT"
  [ "$WITH_MASTER" -eq 1 ] && set_complain "$MASTER"
  reload_master
  reload_service "$FPM"; systemctl restart "$FPM" 2>/dev/null || true
  sleep 1
  log "reverted. worker: $(worker_label || echo '(none yet)')"
  exit 0
fi

# --- enforce mode: pre-flight -----------------------------------------------
command -v aa-status >/dev/null 2>&1 && aa-status --enabled 2>/dev/null || \
  { [ "$(cat /sys/module/apparmor/parameters/enabled 2>/dev/null)" = "Y" ] || die "AppArmor is not enabled on this kernel"; }
systemctl is-active --quiet "$FPM" || warn "$FPM is not active — will start on restart"

if ! profile_is_complain "$HAT"; then
  log "'$SITE' hat is already in enforce — nothing to do. (use --revert to go back)"
  exit 0
fi

# --- soak advisory: any unresolved denials for this hat? ---------------------
DENIALS=""
if command -v ausearch >/dev/null 2>&1; then
  DENIALS="$(ausearch -m AVC -ts recent -i 2>/dev/null | grep "php-fpm//${SITE}" | grep -viE 'profile_(load|replace)' || true)"
elif [ -f "$AUDIT_LOG" ]; then
  DENIALS="$(grep 'apparmor=' "$AUDIT_LOG" 2>/dev/null | grep "php-fpm//${SITE}" | grep 'denied_mask' | grep -viE 'profile_(load|replace)' | tail -20 || true)"
fi
if [ -n "$DENIALS" ]; then
  printf '%s\n' "$DENIALS" | grep -oE 'operation="[^"]*"|denied_mask="[^"]*"|name="[^"]*"' | paste - - - | sort -u | sed 's/^/    /' >&2
  # exec denials (denied_mask="x") are the hat doing its job; only NON-exec gaps
  # (file/network access the app legitimately needs) actually break the site.
  NONEXEC="$(printf '%s\n' "$DENIALS" | grep 'denied_mask' | grep -v 'denied_mask="x"' || true)"
  if [ -n "$NONEXEC" ]; then
    warn "recent soak shows NON-EXEC denials for php-fpm//${SITE} (these can break the site)."
    if [ "$FORCE" -ne 1 ]; then
      die "resolve these in $HAT (or run 'aa-logprof'), re-soak, then retry — or pass --force (auto-rollback still guards)."
    fi
    warn "--force given: enforcing despite non-exec denials."
  else
    info "recent denials are exec-only (the hat blocking exec — expected); safe to enforce."
  fi
fi

# --- plan / confirm ----------------------------------------------------------
TARGETS="$HAT"; [ "$WITH_MASTER" -eq 1 ] && TARGETS="$MASTER $HAT"
if [ "$DRY" -eq 1 ]; then
  log "DRY-RUN: would enforce -> $TARGETS, reload master, restart $FPM, health-check, auto-rollback on failure"
  exit 0
fi
[ "$WITH_MASTER" -eq 1 ] && warn "the MASTER profile is shared — enforcing it affects every pool without its own hat."
confirm "Enforce AppArmor for '$SITE'${WITH_MASTER:+ (+master)}? A broken worker auto-reverts to complain." || { log "aborted."; exit 0; }

# --- flip to enforce ---------------------------------------------------------
log "enforcing $TARGETS"
set_enforce "$HAT"
[ "$WITH_MASTER" -eq 1 ] && set_enforce "$MASTER"
reload_master
systemctl restart "$FPM"
sleep 1

# --- health-check + auto-rollback -------------------------------------------
if health_check; then
  log "enforce OK — worker: $(worker_label || echo '?'), health HTTP ${HEALTH_CODE}"
  echo
  log "'$SITE' is now ENFORCED. Verify:"
  echo "    ps axZ | grep '[p]ool ${SITE}'                         # php-fpm//${SITE} (enforce)"
  echo "    sudo aa-exec -p php-fpm//${SITE} -- /bin/sh -c 'wget -V'   # Permission denied"
  echo "    revert with:  $0 ${SITE} --revert"
else
  err "enforce health check FAILED (HTTP ${HEALTH_CODE}) — rolling back to complain."
  set_complain "$HAT"
  [ "$WITH_MASTER" -eq 1 ] && set_complain "$MASTER"
  reload_master
  systemctl restart "$FPM"; sleep 1
  echo
  err "Rolled back. Denials logged since the attempt (add these to $HAT, then retry):"
  { command -v ausearch >/dev/null 2>&1 && ausearch -m AVC -ts recent -i 2>/dev/null | grep "php-fpm//${SITE}" | grep -viE 'profile_(load|replace)'; } \
    | grep -oE 'operation="[^"]*"|denied_mask="[^"]*"|name="[^"]*"' | paste - - - | sort -u | sed 's/^/    /' >&2 || true
  exit 1
fi
