#!/usr/bin/env bash
# =============================================================================
# add-aa-permit.sh <SITE> <ID> [--force]     grant denial #ID (from show-aa-denials.sh)
# add-aa-permit.sh <SITE> --list             list currently granted permits
# add-aa-permit.sh <SITE> --remove <N>       remove granted permit line N
#
# Adds the rule into a managed region of the pool's hat and reloads AppArmor.
# EXEC permits are refused unless --force (granting exec breaks the no-exec model).
# =============================================================================
set -euo pipefail

SELF="$(cd "$(dirname "$0")" && pwd)"
. "$SELF/lib/common.sh"
. "$SELF/lib/policy.sh"
require_root

SITE="${1:-}"; shift || true
[ -n "$SITE" ] || die "usage: add-aa-permit.sh <SITE> <ID>|--list|--remove <N> [--force]"
policy_site_exists "$SITE" || die "unknown site '$SITE' (run harden-vhost.sh first)"

STATE="$(policy_state_dir "$SITE")"
TSV="$STATE/denials.tsv"
PERMITS="$STATE/permits.rules"
HAT="${APPARMOR_D}/${SITE}"
MASTER="/etc/apparmor.d/php-fpm"
[ -f "$HAT" ] || die "hat not found: $HAT"

# ensure the hat has a managed permits region (insert before the final '}' if absent)
ensure_permits_region() {
  grep -qF '# >>> hardening:permits >>>' "$HAT" && return 0
  local tmp; tmp="$(mktemp)"
  awk '
    { L[NR]=$0 }
    END {
      last=0; for (i=1;i<=NR;i++) if (L[i] ~ /^}[[:space:]]*$/) last=i
      for (i=1;i<=NR;i++) {
        if (i==last) { print "# >>> hardening:permits >>>"; print "# <<< hardening:permits <<<" }
        print L[i]
      }
    }' "$HAT" > "$tmp"
  cat "$tmp" > "$HAT"; rm -f "$tmp"
}

rebuild_region() {
  ensure_permits_region
  local block=""
  if [ -s "$PERMITS" ]; then
    while IFS= read -r r; do [ -n "$r" ] && block+="  ${r}"$'\n'; done < "$PERMITS"
  fi
  [ -z "$block" ] && block="  # (no manual permits)"
  write_region "$HAT" "permits" "${block%$'\n'}"
  apparmor_reload "$MASTER"
}

# --- subcommands -------------------------------------------------------------
case "${1:-}" in
  --list)
    log "granted permits for $SITE:"
    [ -s "$PERMITS" ] && nl -ba "$PERMITS" | sed 's/^/  /' || echo "  (none)"
    exit 0 ;;
  --remove)
    N="${2:?line number}"
    [ -s "$PERMITS" ] || die "no permits to remove"
    rule="$(sed -n "${N}p" "$PERMITS")"; [ -n "$rule" ] || die "no permit on line $N"
    tmp="$(mktemp)"; sed "${N}d" "$PERMITS" > "$tmp"; mv "$tmp" "$PERMITS"
    log "removed: $rule"
    rebuild_region
    reload_service "php$(policy_meta_get "$SITE" PHP_VERSION)-fpm"
    exit 0 ;;
esac

# --- grant a denial by ID ----------------------------------------------------
ID="${1:-}"; FORCE=0; [ "${2:-}" = "--force" ] && FORCE=1
[ -n "$ID" ] || die "usage: add-aa-permit.sh $SITE <ID>|--list|--remove <N>"
[ -f "$TSV" ] || die "no denial list — run: show-aa-denials.sh $SITE"

row="$(awk -F'\t' -v id="$ID" '$1==id{print; exit}' "$TSV")"
[ -n "$row" ] || die "no denial #$ID in $TSV (re-run show-aa-denials.sh $SITE)"
kind="$(cut -f3 <<< "$row")"; perm="$(cut -f4 <<< "$row")"; target="$(cut -f5 <<< "$row")"; rule="$(cut -f6 <<< "$row")"

if [ "$kind" = exec ] || printf '%s' "$perm" | grep -q 'x'; then
  if [ "$FORCE" -ne 1 ]; then
    err "denial #$ID is an EXEC permit ($target)."
    die "granting exec defeats the per-pool no-exec model. If you REALLY must, re-run with --force."
  fi
  warn "--force: granting an EXEC permit ($target) — this weakens the hat."
fi

mkdir -p "$STATE"
if grep -qxF "$rule" "$PERMITS" 2>/dev/null; then
  log "already granted: $rule"
else
  ensure_line "$PERMITS" "$rule"
  log "granting: $rule"
fi
rebuild_region

PHPV="$(policy_meta_get "$SITE" PHP_VERSION)"
log "added to $HAT and reloaded. Apply to running workers:"
echo "    sudo systemctl restart php${PHPV}-fpm"
echo "    then re-soak:  $SELF/show-aa-denials.sh $SITE"
