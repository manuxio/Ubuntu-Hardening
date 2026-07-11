#!/usr/bin/env bash
# =============================================================================
# refresh-vhost.sh <site>
#
# Re-renders an EXISTING site's config (nginx snippet + server block, PHP-FPM
# pool, AppArmor hat, egress, auditd, systemd) from the CURRENT templates, using
# the parameters saved at creation time (state/answers.env). This is how
# template / security improvements reach sites that already exist.
#
# Idempotent and non-destructive: it does NOT touch the docroot, uploaded files
# or the database — only the generated config. Under the hood it re-runs
# harden-vhost.sh with the site's stored answers.
# =============================================================================
set -euo pipefail

SELF="$(cd "$(dirname "$0")" && pwd)"
. "$SELF/lib/common.sh"
. "$SELF/lib/policy.sh"
require_root

SITE="${1:-}"
[ -n "$SITE" ] || die "usage: refresh-vhost.sh <site>"
policy_site_exists "$SITE" || die "unknown site '$SITE' (run harden-vhost.sh first)"

ANSWERS="$(policy_state_dir "$SITE")/answers.env"
if [ ! -f "$ANSWERS" ]; then
  die "no saved config for '$SITE' (it was created before refresh existed).
     Run harden-vhost.sh once for it (its answers will be saved), then refresh works."
fi

log "refreshing '$SITE' from saved answers + current templates (config only, data untouched)"
( set -a; . "$ANSWERS"; set +a; ASSUME_YES=1 bash "$SELF/harden-vhost.sh" )
log "'$SITE' config re-rendered. Verify:  nginx -t  &&  php-fpm -t"
