#!/usr/bin/env bash
# =============================================================================
# setup-tls.sh <SITE> [--self-signed | --letsencrypt --email you@dom [--staging]]
#
# Switches a vhost to HTTPS: obtains/creates a certificate, renders the HTTPS
# server block (HTTP redirects to HTTPS, ACME path kept for renewals), reloads
# nginx and flips session.cookie_secure=on. For Let's Encrypt it also installs a
# renewal deploy-hook (reload nginx) and enables the certbot timer.
#
#   --self-signed   immediate/staging cert (browser warning; no HSTS)
#   --letsencrypt   real cert via webroot http-01 (needs a PUBLIC domain -> this host)
#   --staging       use the LE staging CA (untrusted, for testing the flow)
# =============================================================================
set -euo pipefail

SELF="$(cd "$(dirname "$0")" && pwd)"
. "$SELF/lib/common.sh"
. "$SELF/lib/policy.sh"
TPL="$(dirname "$SELF")/templates"
require_root

SITE="${1:-}"; shift || true
[ -n "$SITE" ] || die "usage: setup-tls.sh <SITE> [--self-signed | --letsencrypt --email X [--staging]]"
policy_site_exists "$SITE" || die "unknown site '$SITE' (run harden-vhost.sh first)"

MODE="self-signed"; EMAIL=""; STAGING=""
while [ $# -gt 0 ]; do
  case "$1" in
    --self-signed) MODE=self-signed ;;
    --letsencrypt) MODE=letsencrypt ;;
    --email)       EMAIL="${2:?}"; shift ;;
    --staging)     STAGING="--staging" ;;
    *) die "unknown option: $1" ;;
  esac; shift
done

SERVER_NAME="$(policy_meta_get "$SITE" SERVER_NAME)"
DOCROOT="$(policy_meta_get "$SITE" DOCROOT)"
PHPV="$(policy_meta_get "$SITE" PHP_VERSION)"
[ -n "$SERVER_NAME" ] && [ -n "$DOCROOT" ] || die "missing SERVER_NAME/DOCROOT in state (re-run harden-vhost.sh)"
PRIMARY="$(awk '{print $1}' <<< "$SERVER_NAME")"
NGX_AVAIL="/etc/nginx/sites-available/${SITE}"
HSTS='# HSTS omitted for a self-signed cert'

# --- obtain the certificate --------------------------------------------------
if [ "$MODE" = self-signed ]; then
  SSLDIR="/etc/nginx/ssl/${SITE}"; mkdir -p "$SSLDIR"
  TLS_CERT="$SSLDIR/fullchain.pem"; TLS_KEY="$SSLDIR/privkey.pem"
  log "generating self-signed cert for $PRIMARY (365d)"
  openssl req -x509 -newkey rsa:2048 -sha256 -days 365 -nodes \
    -keyout "$TLS_KEY" -out "$TLS_CERT" \
    -subj "/CN=${PRIMARY}" -addext "subjectAltName=DNS:${PRIMARY}" >/dev/null 2>&1
  chmod 600 "$TLS_KEY"
else
  command -v certbot >/dev/null 2>&1 || die "certbot not installed — run harden-os.sh (or: apt install certbot)"
  [ -n "$EMAIL" ] || die "--email is required for Let's Encrypt"
  local_d=""; for d in $SERVER_NAME; do local_d="$local_d -d $d"; done
  mkdir -p "$DOCROOT/.well-known/acme-challenge"
  chown -R "$(policy_meta_get "$SITE" WEB_USER):$(policy_meta_get "$SITE" WEB_USER)" "$DOCROOT/.well-known" 2>/dev/null || true
  log "requesting Let's Encrypt cert (webroot) for:$local_d"
  # shellcheck disable=SC2086
  certbot certonly --webroot -w "$DOCROOT" $local_d \
    --agree-tos -m "$EMAIL" --non-interactive --keep-until-expiring $STAGING \
    || die "certbot failed — is $PRIMARY publicly resolving to this host on :80? Check the ACME challenge."
  TLS_CERT="/etc/letsencrypt/live/${PRIMARY}/fullchain.pem"
  TLS_KEY="/etc/letsencrypt/live/${PRIMARY}/privkey.pem"
  HSTS='add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;'
  # reload nginx automatically after each renewal
  install -d /etc/letsencrypt/renewal-hooks/deploy
  printf '#!/bin/sh\nsystemctl reload nginx\n' > /etc/letsencrypt/renewal-hooks/deploy/reload-nginx.sh
  chmod +x /etc/letsencrypt/renewal-hooks/deploy/reload-nginx.sh
  systemctl enable --now certbot.timer >/dev/null 2>&1 || true
  info "auto-renewal: certbot.timer active; deploy-hook reloads nginx"
fi

# --- render the HTTPS server block + reload ---------------------------------
log "rendering HTTPS server block -> $NGX_AVAIL"
render_template "$TPL/nginx-site-tls.conf.tmpl" "$NGX_AVAIL" \
  SITE SERVER_NAME DOCROOT TLS_CERT TLS_KEY HSTS
ln -sfn "$NGX_AVAIL" "/etc/nginx/sites-enabled/${SITE}"
nginx -t
reload_service nginx

# --- flip session.cookie_secure on (now that TLS is live) -------------------
bash "$SELF/tune-vhost.sh" "$SITE" tls-on >/dev/null 2>&1 || warn "could not flip cookie_secure (do: tune-vhost.sh $SITE tls-on)"

cat <<EOF

$(log "TLS enabled for '$SITE' ($MODE).")
    https://${PRIMARY}/    (HTTP now 301-redirects here)
    session.cookie_secure -> on
$( [ "$MODE" = self-signed ] && echo "    NOTE: self-signed -> browser warning; use --letsencrypt for a trusted cert." )
$( [ "$MODE" = letsencrypt ] && echo "    Renewal: certbot renews automatically and reloads nginx (deploy-hook)." )
EOF
