#!/usr/bin/env bash
# =============================================================================
# harden-os.sh — server-wide hardening (run once per server)
#
# Installs the SHARED layer: nginx + php-fpm baseline, AppArmor master profile,
# systemd sandbox defaults, UFW default-deny + egress scaffolding, auditd, AIDE,
# fail2ban, unattended-upgrades, SSH, sysctl. Nothing site-specific — per-site
# hardening is harden-vhost.sh.
#
# Container-aware: in an ephemeral container it still WRITES every config file
# (so Tier-1 tests can inspect them) but skips live activation of
# systemd/ufw/auditd/apparmor, which need a real PID-1 / host kernel.
# =============================================================================
set -euo pipefail

SELF="$(cd "$(dirname "$0")" && pwd)"
REPO="$(dirname "$SELF")"
. "$SELF/lib/common.sh"
. "$SELF/lib/policy.sh"
CFG="$REPO/config"

require_root

prompt PHP_VERSION "PHP version to harden" "$(ls /etc/php 2>/dev/null | sort -V | tail -1 || echo 8.1)"
prompt SSH_HARDEN  "Harden SSH (key-only, no root)? (yes/no)"  "no"
prompt RUN_AIDEINIT "Build the AIDE baseline now (slow)? (yes/no)" "no"

is_container && warn "container detected -> writing configs, skipping live service activation"

# --- 1. Packages -------------------------------------------------------------
ensure_packages() {
  local missing=() p
  for p in "$@"; do dpkg -s "$p" >/dev/null 2>&1 || missing+=("$p"); done
  [ ${#missing[@]} -eq 0 ] && { info "all base packages present"; return 0; }
  log "installing: ${missing[*]}"
  DEBIAN_FRONTEND=noninteractive apt-get update -qq 2>/dev/null || warn "apt update failed (offline?)"
  DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends "${missing[@]}" \
    || warn "apt install failed — ensure the image pre-bakes: ${missing[*]}"
}
ensure_packages nginx "php${PHP_VERSION}-fpm" "php${PHP_VERSION}-cli" \
  "php${PHP_VERSION}-mysql" "php${PHP_VERSION}-gd" "php${PHP_VERSION}-xml" \
  "php${PHP_VERSION}-mbstring" "php${PHP_VERSION}-curl" \
  ufw auditd aide acl apparmor-utils fail2ban unattended-upgrades \
  certbot openssl
# Let's Encrypt auto-renewal: the certbot package ships a systemd timer; make
# sure it's active so certs renew (setup-tls.sh adds an nginx-reload deploy-hook).
if ! is_container && systemctl list-unit-files 2>/dev/null | grep -q '^certbot.timer'; then
  systemctl enable --now certbot.timer >/dev/null 2>&1 && info "certbot.timer enabled (LE auto-renewal)" || true
fi

# --- 2. nginx baseline -------------------------------------------------------
log "nginx baseline"
mkdir -p /etc/nginx/conf.d /etc/nginx/snippets
cp "$CFG/nginx-hardening.conf"  /etc/nginx/conf.d/00-hardening.conf
cp "$CFG/security-headers.conf" /etc/nginx/snippets/security-headers.conf
cp "$CFG/tls-params.conf"       /etc/nginx/snippets/tls-params.conf
rm -f /etc/nginx/sites-enabled/default
nginx -t 2>/dev/null && info "nginx config OK" || warn "nginx -t reported issues"

# --- 3. PHP-FPM baseline -----------------------------------------------------
log "PHP-FPM baseline (PHP $PHP_VERSION)"
POOLD="/etc/php/${PHP_VERSION}/fpm/pool.d"
if [ -f "$POOLD/www.conf" ]; then
  mv "$POOLD/www.conf" "$POOLD/www.conf.disabled"
  info "disabled stock www pool"
fi
mkdir -p /run/php
DROPIN="/etc/systemd/system/php${PHP_VERSION}-fpm.service.d"
mkdir -p "$DROPIN"
cp "$CFG/systemd-fpm-global.conf" "$DROPIN/00-hardening.conf"
has_systemd && systemctl daemon-reload 2>/dev/null || true

# --- 4. AppArmor master profile ---------------------------------------------
log "AppArmor master profile"
cp "$CFG/apparmor-php-fpm-master" /etc/apparmor.d/php-fpm
mkdir -p /etc/apparmor.d/php-fpm.d
apparmor_reload /etc/apparmor.d/php-fpm

# --- 5. UFW default-deny + egress scaffolding --------------------------------
log "UFW baseline + egress scaffolding"
if command -v ufw >/dev/null 2>&1; then
  ufw default deny incoming  >/dev/null 2>&1 || true
  ufw default allow outgoing >/dev/null 2>&1 || true
  for r in OpenSSH 80/tcp 443/tcp; do ufw allow "$r" >/dev/null 2>&1 || true; done
  # scaffold the (empty) per-site egress region just before COMMIT
  _ensure_region_before_anchor "$UFW_BEFORE4" egress '^COMMIT' 2>/dev/null || true
  _ensure_region_before_anchor "$UFW_BEFORE6" egress '^COMMIT' 2>/dev/null || true
  if is_container; then
    info "(container) not enabling ufw; on the host run: ufw enable"
  else
    # --force skips the "may disrupt ssh" prompt AND avoids the SIGPIPE that
    # `yes | ufw enable` triggers under pipefail (a false 'failed' warning).
    ufw --force enable >/dev/null 2>&1 || warn "ufw enable failed"
  fi
fi

# --- 6. auditd global rules --------------------------------------------------
log "auditd global rules"
if [ -d /etc/audit/rules.d ]; then
  cp "$CFG/auditd-hardening.rules" /etc/audit/rules.d/hardening.rules
  mkdir -p /etc/hardening
  if ! is_container && command -v augenrules >/dev/null 2>&1; then
    augenrules --load >/dev/null 2>&1 || warn "augenrules load failed"
  fi
fi

# --- 7. AIDE -----------------------------------------------------------------
log "AIDE"
if [ -d /etc/aide ]; then
  ensure_line /etc/aide/aide.conf.d/99_hardening_exclude '!/var/www/.*/cache'
  ensure_line /etc/aide/aide.conf.d/99_hardening_exclude '!/var/www/.*/sessions'
  ensure_line /etc/aide/aide.conf.d/99_hardening_exclude '!/var/www/.*/tmp'
fi
if [ "$RUN_AIDEINIT" = "yes" ] && command -v aideinit >/dev/null 2>&1 && ! is_container; then
  aideinit -y -f >/dev/null 2>&1 && info "AIDE baseline built" || warn "aideinit failed"
else
  info "skipping AIDE baseline (set RUN_AIDEINIT=yes on a real host)"
fi

# --- 8. fail2ban -------------------------------------------------------------
if [ -d /etc/fail2ban ]; then
  cat > /etc/fail2ban/jail.local <<'EOF'
[DEFAULT]
bantime  = 1h
findtime = 10m
maxretry = 5
[sshd]
enabled = true
[nginx-http-auth]
enabled = true
EOF
  ! is_container && reload_service fail2ban || true
fi

# --- 9. unattended-upgrades --------------------------------------------------
if [ -f /etc/apt/apt.conf.d/20auto-upgrades ] || command -v unattended-upgrade >/dev/null 2>&1; then
  cat > /etc/apt/apt.conf.d/20auto-upgrades <<'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
EOF
  info "unattended-upgrades enabled"
fi

# --- 10. SSH hardening (guarded) --------------------------------------------
if [ "$SSH_HARDEN" = "yes" ] && ! is_container; then
  log "SSH hardening"
  backup_once /etc/ssh/sshd_config
  install -d /etc/ssh/sshd_config.d
  cat > /etc/ssh/sshd_config.d/99-hardening.conf <<'EOF'
PermitRootLogin no
PasswordAuthentication no
ChallengeResponseAuthentication no
X11Forwarding no
MaxAuthTries 3
EOF
  reload_service ssh || reload_service sshd || true
else
  info "skipping SSH hardening (SSH_HARDEN=$SSH_HARDEN, container=$(is_container && echo yes || echo no))"
fi

# --- 11. sysctl --------------------------------------------------------------
log "sysctl hardening"
cat > /etc/sysctl.d/99-hardening.conf <<'EOF'
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.tcp_syncookies = 1
kernel.randomize_va_space = 2
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
EOF
! is_container && sysctl --system >/dev/null 2>&1 || info "(container) sysctl file written, not applied"

log "OS hardening complete. Next: run harden-vhost.sh per site (AppArmor is in COMPLAIN — soak, then enforce)."
