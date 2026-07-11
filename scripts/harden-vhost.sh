#!/usr/bin/env bash
# =============================================================================
# harden-vhost.sh — per-virtual-host setup (run once per site)
#
# Generic + interactive: every username/path/host is prompted (env-overridable,
# so `sites/<name>.env` can pre-seed a whole run). Idempotent. Implements the
# "web_user" identity model: code owned by www-data, runtime user reaches it via the
# www-data group; runtime-writable dirs are setgid so web_user + ftp_user share them.
#
#   set -a; . sites/web_user.env; set +a; sudo -E ./scripts/harden-vhost.sh
# =============================================================================
set -euo pipefail

SELF="$(cd "$(dirname "$0")" && pwd)"
REPO="$(dirname "$SELF")"
. "$SELF/lib/common.sh"
. "$SELF/lib/policy.sh"
TPL="$REPO/templates"

require_root

# --- Gather inputs -----------------------------------------------------------
prompt SITE          "Short site name (pool/hat/socket id)"      "web_user"
[[ "$SITE" =~ ^[a-z0-9][a-z0-9_-]*$ ]] || die "SITE must be [a-z0-9_-], got '$SITE'"
prompt SERVER_NAME   "Server name(s) for the nginx block"        "${SITE}.local"
prompt DOCROOT       "Document root (docroot)"                   "/var/www/html/${SITE}/public_html"
DOCROOT="${DOCROOT%/}"
prompt RUNTIME_USER  "PHP-FPM runtime user"                      "$SITE"
prompt WEB_USER      "Web/FTP identity (owns code; runtime user is in its GROUP)" "www-data"
prompt PHP_VERSION   "PHP version"                               "8.1"
prompt WRITABLE_DIRS "Runtime-writable dirs (relative, space-sep)" "images media cache administrator/cache"
prompt TMP_PATH      "Temp path (outside docroot)"               "$(dirname "$DOCROOT")/tmp"
prompt SESSION_PATH  "Session path (outside docroot)"            "$(dirname "$DOCROOT")/sessions"
prompt LOG_PATH      "Log path (outside docroot)"                "$(dirname "$DOCROOT")/logs"
prompt DB_HOST       "Database host (egress allow)"              "10.0.0.10"
prompt DB_PORT       "Database port"                             "3306"
prompt MAIL_HOST     "SMTP relay IP (blank = no outbound mail)"  ""
prompt MAIL_PORTS    "SMTP ports"                                "25,465,587"
prompt ALLOW_HTTPS   "Allow outbound 443 (yes/no)"               "yes"
prompt COOKIE_SECURE "session.cookie_secure (on needs HTTPS)"    "off"

RUNTIME_GROUP="${RUNTIME_GROUP:-$RUNTIME_USER}"
SOCKET="/run/php/php${PHP_VERSION}-${SITE}.sock"

# Per-site tunables — env-overridable (set in the site .env), sensible defaults
# if omitted. Not prompted, to keep the interactive flow short.
PM_MAX_CHILDREN="${PM_MAX_CHILDREN:-10}"
PM_MAX_REQUESTS="${PM_MAX_REQUESTS:-500}"
MEMORY_LIMIT="${MEMORY_LIMIT:-256M}"
UPLOAD_MAX_FILESIZE="${UPLOAD_MAX_FILESIZE:-32M}"
POST_MAX_SIZE="${POST_MAX_SIZE:-32M}"
MAX_EXECUTION_TIME="${MAX_EXECUTION_TIME:-60}"
CLIENT_MAX_BODY="${CLIENT_MAX_BODY:-${UPLOAD_MAX_FILESIZE}}"   # nginx body cap matches uploads

SITE_PARENT="$(dirname "$DOCROOT")"
POOL="/etc/php/${PHP_VERSION}/fpm/pool.d/${SITE}.conf"
HAT="/etc/apparmor.d/php-fpm.d/${SITE}"
NGX_AVAIL="/etc/nginx/sites-available/${SITE}"
NGX_ENABLED="/etc/nginx/sites-enabled/${SITE}"

# --- Preflight ---------------------------------------------------------------
# Fail FAST with an actionable message if a hard dependency is missing, instead
# of aborting mid-run on `php-fpm -t`. A missing database is only a heads-up: it
# may be provisioned later, and harden-vhost only opens egress toward it.
preflight() {
  local miss=()
  have_cmd nginx || miss+=("nginx")
  have_cmd "php-fpm${PHP_VERSION}" || miss+=("php${PHP_VERSION}-fpm")
  if [ "${#miss[@]}" -gt 0 ]; then
    die "missing required tool(s): ${miss[*]} — run scripts/harden-os.sh first (or: apt-get install ${miss[*]})"
  fi
  if [ "${ENABLE_APPARMOR_HAT:-0}" = "1" ] && ! is_container && ! have_cmd apparmor_parser; then
    warn "apparmor_parser not found -> the AppArmor hat won't attach (apt-get install apparmor apparmor-utils)"
  fi
  if [ -n "${DB_HOST:-}" ] && [ -n "${DB_PORT:-}" ]; then
    if tcp_open "$DB_HOST" "$DB_PORT" 2; then
      info "database reachable at ${DB_HOST}:${DB_PORT}"
    else
      warn "nothing answering at ${DB_HOST}:${DB_PORT} -> egress will be allowed, but the site errors until the DB is up"
    fi
  fi
}
preflight

log "Site '$SITE' -> docroot $DOCROOT, runtime user $RUNTIME_USER (PHP $PHP_VERSION)"

# --- Validate docroot --------------------------------------------------------
if [ ! -d "$DOCROOT" ]; then
  if confirm "Docroot '$DOCROOT' does not exist. Create it?"; then
    mkdir -p "$DOCROOT"
  else
    die "docroot missing"
  fi
fi
[ -f "$DOCROOT/configuration.php" ] || warn "no configuration.php in $DOCROOT (not a Joomla root yet?)"

# --- Validate / create runtime user -----------------------------------------
if ! id "$RUNTIME_USER" >/dev/null 2>&1; then
  if confirm "User '$RUNTIME_USER' does not exist. Create it (system, nologin)?"; then
    useradd -r -s /usr/sbin/nologin -d "$DOCROOT" "$RUNTIME_USER"
    log "created user $RUNTIME_USER"
  else
    die "runtime user missing"
  fi
fi
if id -nG "$RUNTIME_USER" | tr ' ' '\n' | grep -qx "$WEB_USER"; then
  info "$RUNTIME_USER is already in the $WEB_USER group"
else
  if confirm "Add '$RUNTIME_USER' to the '$WEB_USER' group (needed to read code)?"; then
    usermod -aG "$WEB_USER" "$RUNTIME_USER"
    log "added $RUNTIME_USER to $WEB_USER (php-fpm restart applies it)"
  else
    warn "$RUNTIME_USER not in $WEB_USER — it will not be able to read the code"
  fi
fi
RUNTIME_UID="$(id -u "$RUNTIME_USER")"

# --- Filesystem model (the joomla-filesystem.sh logic) -----------------------
log "Applying filesystem permission model"
# nginx (www-data) must be able to traverse the parent into the docroot.
chown "${WEB_USER}:${WEB_USER}" "$SITE_PARENT"; chmod 750 "$SITE_PARENT"
# Code: owner (www-data/FTP) writes; group (runtime user) reads; others nothing.
chown -R "${WEB_USER}:${WEB_USER}" "$DOCROOT"
find "$DOCROOT" -type d -exec chmod 750 {} +
find "$DOCROOT" -type f -exec chmod 640 {} +
# Runtime-writable dirs: create if absent, then setgid so new files inherit
# group www-data. They MUST exist: the systemd sandbox (ReadWritePaths),
# open_basedir and the AppArmor hat all reference them, and a declared-but-
# missing path makes php-fpm fail to start (status=226/NAMESPACE). A fresh CMS
# usually ships them; creating them here is idempotent and closes that footgun.
for d in $WRITABLE_DIRS; do
  [ -d "$DOCROOT/$d" ] || info "creating declared writable dir: $d"
  mkdir -p "$DOCROOT/$d"
  chown -R "${WEB_USER}:${WEB_USER}" "$DOCROOT/$d"
  find "$DOCROOT/$d" -type d -exec chmod 2770 {} +
  find "$DOCROOT/$d" -type f -exec chmod 660 {} +
done
# configuration.php stays read-only to the runtime user.
[ -f "$DOCROOT/configuration.php" ] && chmod 640 "$DOCROOT/configuration.php"
# tmp/session/log outside the docroot, writable by the runtime user via group.
for p in "$TMP_PATH" "$SESSION_PATH" "$LOG_PATH"; do
  refuse_bad_path "$p" "runtime path"
  mkdir -p "$p"
  chown -R "${WEB_USER}:${WEB_USER}" "$p"
  find "$p" -type d -exec chmod 2770 {} +
done
mkdir -p /run/php

# --- Render PHP-FPM pool -----------------------------------------------------
log "Rendering PHP-FPM pool -> $POOL"
render_template "$TPL/php-fpm-pool.conf.tmpl" "$POOL" \
  SITE DOCROOT RUNTIME_USER RUNTIME_GROUP SOCKET WEB_USER TMP_PATH SESSION_PATH LOG_PATH COOKIE_SECURE \
  PM_MAX_CHILDREN PM_MAX_REQUESTS MEMORY_LIMIT UPLOAD_MAX_FILESIZE POST_MAX_SIZE MAX_EXECUTION_TIME

# apparmor_hat only attaches when AppArmor actually confines the master. In a
# container (or a php-fpm build without apparmor support) it would make workers
# fail to spawn, so disable it unless explicitly forced.
if is_container && [ "${ENABLE_APPARMOR_HAT:-0}" != "1" ]; then
  sed -i 's/^apparmor_hat/;apparmor_hat/' "$POOL"
  info "apparmor_hat disabled (container) — Tier-2/host attaches php-fpm//${SITE}"
fi
if ! php-fpm"${PHP_VERSION}" -t >/dev/null 2>&1; then
  out="$(php-fpm"${PHP_VERSION}" -t 2>&1 || true)"
  if echo "$out" | grep -qi apparmor_hat; then
    warn "this php-fpm build lacks apparmor_hat — commenting it out (hat won't attach here)"
    sed -i 's/^apparmor_hat/;apparmor_hat/' "$POOL"
  fi
fi
php-fpm"${PHP_VERSION}" -t

# --- Render AppArmor child hat ----------------------------------------------
log "Rendering AppArmor child hat -> $HAT"
mkdir -p "$(dirname "$HAT")"
render_template "$TPL/apparmor-child.tmpl" "$HAT" SITE SITE_PARENT

# --- Render nginx: shared app snippet + HTTP server block -------------------
log "Rendering nginx app snippet + HTTP server block"
WRITABLE_REGEX="$(printf '%s' "$WRITABLE_DIRS" | tr ' ' '|')"
NGX_SNIP="/etc/nginx/snippets/${SITE}-app.conf"
mkdir -p /etc/nginx/snippets
render_template "$TPL/nginx-app.conf.tmpl" "$NGX_SNIP" SITE DOCROOT SOCKET WRITABLE_REGEX CLIENT_MAX_BODY
# Don't clobber an existing TLS wrapper (set up by setup-tls.sh): the shared app
# snippet above is refreshed either way, so both HTTP and HTTPS pick up changes.
if grep -q 'listen 443' "$NGX_AVAIL" 2>/dev/null; then
  info "existing HTTPS config kept (app snippet refreshed) — re-run setup-tls.sh to re-render TLS"
else
  render_template "$TPL/nginx-site.conf.tmpl" "$NGX_AVAIL" SITE SERVER_NAME
fi
ln -sfn "$NGX_AVAIL" "$NGX_ENABLED"
nginx -t

# --- Record state & run the sync engine -------------------------------------
log "Recording policy state and syncing open_basedir / hat / systemd / egress"
policy_meta_set "$SITE" SITE         "$SITE"
policy_meta_set "$SITE" SERVER_NAME  "$SERVER_NAME"
policy_meta_set "$SITE" RUNTIME_USER "$RUNTIME_USER"
policy_meta_set "$SITE" UID          "$RUNTIME_UID"
policy_meta_set "$SITE" PHP_VERSION  "$PHP_VERSION"
policy_meta_set "$SITE" DOCROOT      "$DOCROOT"
policy_meta_set "$SITE" WEB_USER     "$WEB_USER"
policy_meta_set "$SITE" SOCKET       "$SOCKET"

# Reach: code is read-only; writable dirs + tmp/session/log are read-write.
reach_add "$SITE" "$DOCROOT" ro
for d in $WRITABLE_DIRS; do reach_add "$SITE" "$DOCROOT/$d" rw; done
reach_add "$SITE" "$TMP_PATH"     rw
reach_add "$SITE" "$SESSION_PATH" rw
reach_add "$SITE" "$LOG_PATH"     rw
reach_rebuild "$SITE"

# Egress: DB, optional mail relay, optional HTTPS.
egress_allow "$SITE" "-p tcp -d ${DB_HOST} --dport ${DB_PORT}" 4
if [ -n "$MAIL_HOST" ]; then
  egress_allow "$SITE" "-p tcp -d ${MAIL_HOST} -m multiport --dports ${MAIL_PORTS}" 4
else
  warn "MAIL_HOST empty -> outbound SMTP not allowed for $SITE (set it and re-run / use tune-vhost.sh)"
fi
[ "$ALLOW_HTTPS" = "yes" ] && { egress_allow "$SITE" "-p tcp --dport 443" 4; egress_allow "$SITE" "-p tcp --dport 443" 6; }
egress_rebuild

# --- Per-site auditd rule ----------------------------------------------------
if [ -d /etc/audit/rules.d ]; then
  printf -- '-a always,exit -F arch=b64 -S execve -F uid=%s -k %s_exec\n' "$RUNTIME_UID" "$SITE" \
    > "/etc/audit/rules.d/site-${SITE}.rules"
  command -v augenrules >/dev/null 2>&1 && { augenrules --load >/dev/null 2>&1 || true; }
  info "auditd rule: execve by uid $RUNTIME_UID keyed ${SITE}_exec"
fi

# --- Reload services ---------------------------------------------------------
apparmor_reload "/etc/apparmor.d/php-fpm" 2>/dev/null || true
reload_service "php${PHP_VERSION}-fpm"
reload_service "nginx"

# --- Summary -----------------------------------------------------------------
cat <<EOF

$(log "vhost '$SITE' hardened.")
Set in ${DOCROOT}/configuration.php:
    public \$tmp_path = '${TMP_PATH}';
    public \$log_path = '${LOG_PATH}';

Verify:
    ps afxZ | grep 'pool ${SITE}'                 # -> php-fpm//${SITE} once a request hits it
    sudo -u ${RUNTIME_USER} test -w ${DOCROOT}/media   && echo 'can write media (ok)'
    sudo -u ${RUNTIME_USER} test -w ${DOCROOT}/configuration.php || echo 'cannot write config (ok)'

Soak in COMPLAIN, then enforce:
    exercise the site (front end, admin login, article save, media upload, cache clear)
    sudo grep denied_mask /var/log/audit/audit.log | grep 'php-fpm//${SITE}'
    sudo aa-logprof                                # convert denials to rules
    # then strip 'complain' from /etc/apparmor.d/php-fpm and .../php-fpm.d/${SITE}, reload.
EOF
