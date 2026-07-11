#!/usr/bin/env bash
# =============================================================================
# probe-vhost.sh <site> [<other-site>]
#
# Runs the ISOLATION matrix against EXISTING vhost(s) — nothing is created or
# destroyed. It deploys the probe page into the docroot with the correct
# ownership, curls it through nginx (following the TLS redirect), asserts that
# every escape is DENIED and the site's own writable dir works, then removes the
# probe. With a second site it also proves cross-site isolation both ways.
#
# Use this to verify a real site's containment without the heavy end-to-end test
# (which provisions throwaway site1/site2).
# =============================================================================
set -uo pipefail

SELF="$(cd "$(dirname "$0")" && pwd)"
REPO="$(dirname "$SELF")"
. "$SELF/lib/common.sh"
. "$SELF/lib/policy.sh"
require_root

PROBE_SRC="$REPO/test/checks/xsite-probe.php"
[ -f "$PROBE_SRC" ] || die "probe not found: $PROBE_SRC"

SITE="${1:-}"; OTHER="${2:-}"
[ -n "$SITE" ] || die "usage: probe-vhost.sh <site> [<other-site>]"
policy_site_exists "$SITE" || die "unknown site '$SITE'"

# Pick the 'other' target: an explicit/auto second site (real cross-site test),
# else a host path outside the site's open_basedir (host-isolation only).
if [ -z "$OTHER" ]; then
  OTHER="$(ls "$STATE_ROOT" 2>/dev/null | grep -vx "$SITE" | head -1 || true)"
fi
if [ -n "$OTHER" ] && policy_site_exists "$OTHER"; then
  OTHER_DIR="$(dirname "$(policy_meta_get "$OTHER" DOCROOT)")"
  info "cross-site target: '$OTHER' ($OTHER_DIR)"
else
  OTHER=""; OTHER_DIR="/root"
  warn "no second site — testing host isolation only (cross-site keys still assert via open_basedir)."
fi

PASS=0; FAIL=0
ok(){ PASS=$((PASS+1)); printf '  \033[32mPASS\033[0m %s\n' "$1"; }
no(){ FAIL=$((FAIL+1)); printf '  \033[31mFAIL\033[0m %s  <<<\n' "$1"; }

# fetch a path from a site via nginx (follow TLS redirect, accept self-signed,
# pin :80/:443 of the primary domain to loopback)
fetch(){ # fetch <site> <path?query>
  local s="$1" pq="$2" dom
  dom="$(awk '{print $1}' <<< "$(policy_meta_get "$s" SERVER_NAME)")"; dom="${dom:-$s.local}"
  curl -sk -L --resolve "${dom}:80:127.0.0.1" --resolve "${dom}:443:127.0.0.1" "http://${dom}/probe_$$.php?${pq}"
}

run_probe(){ # run_probe <attacker-site> <target-dir> <target-label>
  local s="$1" other="$2" label="$3" docroot web out k
  docroot="$(policy_meta_get "$s" DOCROOT)"
  web="$(policy_meta_get "$s" WEB_USER)"; web="${web:-www-data}"
  install -o "$web" -g "$web" -m 640 "$PROBE_SRC" "$docroot/probe_$$.php"
  echo "== isolation: '$s' -> ${label} =="
  out="$(fetch "$s" "other=${other}")"
  rm -f "$docroot/probe_$$.php"
  if ! grep -q '=' <<< "$out"; then no "$s: probe did not run (HTTP error / no PHP) — is the site served?"; return; fi
  for k in xsite_read_config xsite_list_dir xsite_read_secret xsite_write \
           read_etc_shadow exec_denied shell_spawn_denied egress_80_denied own_write_ok; do
    case "$(grep -oE "^$k=[A-Z]+" <<< "$out" | cut -d= -f2)" in
      PASS) ok "$k" ;; *) no "$k (got '$(grep -oE "^$k=[A-Z]+" <<< "$out" | cut -d= -f2)')" ;;
    esac
  done
}

run_probe "$SITE" "$OTHER_DIR" "${OTHER:-host}"
if [ -n "$OTHER" ]; then
  run_probe "$OTHER" "$(dirname "$(policy_meta_get "$SITE" DOCROOT)")" "$SITE"
fi

echo
[ "$FAIL" -eq 0 ] && log "ISOLATION OK — PASS=$PASS FAIL=0" || err "ISOLATION has failures — PASS=$PASS FAIL=$FAIL"
exit "$FAIL"
