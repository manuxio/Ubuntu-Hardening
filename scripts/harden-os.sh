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

# --- Preflight: these scripts install/harden via apt on Debian/Ubuntu ---------
have_cmd apt-get || die "apt-get not found — harden-os.sh targets Debian/Ubuntu"
. /etc/os-release 2>/dev/null || true
case "${ID:-}" in
  ubuntu|debian) : ;;
  *) warn "untested OS '${ID:-unknown}' — these scripts are validated on Ubuntu 22.04" ;;
esac

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
# Best-effort, per-package install for OPTIONAL tooling: a package with no
# installation candidate (e.g. dropped from a release) must not sink the rest of
# the batch the way a single `apt-get install a b c` transaction would.
install_optional() {
  DEBIAN_FRONTEND=noninteractive apt-get update -qq 2>/dev/null || true
  local p
  for p in "$@"; do
    dpkg -s "$p" >/dev/null 2>&1 && continue
    if DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends "$p" >/dev/null 2>&1; then
      info "installed: $p"
    else
      warn "optional package unavailable, skipped: $p"
    fi
  done
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
# network
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.tcp_syncookies = 1
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.all.accept_ra = 0
# kernel
kernel.randomize_va_space = 2
kernel.kptr_restrict = 2
kernel.dmesg_restrict = 1
kernel.yama.ptrace_scope = 1
kernel.perf_event_paranoid = 3
kernel.unprivileged_bpf_disabled = 1
net.core.bpf_jit_harden = 2
# filesystem
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
fs.protected_fifos = 2
fs.protected_regular = 2
fs.suid_dumpable = 0
EOF
! is_container && sysctl --system >/dev/null 2>&1 || info "(container) sysctl file written, not applied"

# --- 12. OS baseline hardening (Lynis-informed) ------------------------------
log "OS baseline: login.defs, pam_pwquality, core dumps, module blacklist, banner"
# password aging + default umask + password hashing rounds (login.defs).
# set_logindef removes ACTIVE directives for a key (leaving comment lines that
# merely mention the key untouched) and rewrites exactly one — so it is both
# idempotent and self-healing if a previous greedy sed left duplicate lines.
set_logindef(){ # key value
  local k="$1" v="$2" f=/etc/login.defs
  sed -i -E "/^[[:space:]]*${k}[[:space:]]/d" "$f"
  printf '%s\t%s\n' "$k" "$v" >> "$f"
}
if [ -f /etc/login.defs ]; then
  backup_once /etc/login.defs
  set_logindef PASS_MAX_DAYS 365
  set_logindef PASS_MIN_DAYS 1
  set_logindef PASS_WARN_AGE 7
  set_logindef UMASK 027
  set_logindef SHA_CRYPT_MIN_ROUNDS 65536   # AUTH-9230: stronger password hashing
fi
# umask for login shells too (Lynis checks /etc/profile, not just login.defs)
printf '# hardening: restrictive default umask\numask 027\n' > /etc/profile.d/99-hardening-umask.sh
chmod 644 /etc/profile.d/99-hardening-umask.sh
# password quality (affects only NEW passwords; the package wires pam in)
ensure_packages libpam-pwquality
if [ -d /etc/security ]; then
  cat > /etc/security/pwquality.conf <<'EOF'
minlen = 14
minclass = 3
dcredit = -1
ucredit = -1
lcredit = -1
ocredit = -1
maxrepeat = 3
gecoscheck = 1
EOF
fi
# disable core dumps (info-leak) — limits + sysctl (fs.suid_dumpable set above)
mkdir -p /etc/security/limits.d
printf '* hard core 0\n' > /etc/security/limits.d/99-hardening.conf
# blacklist uncommon filesystems/protocols + usb-storage
cp "$CFG/modprobe-hardening.conf" /etc/modprobe.d/hardening.conf
# legal login banners
cp "$CFG/issue-banner" /etc/issue
cp "$CFG/issue-banner" /etc/issue.net

# --- Extended baseline: SSH, integrity/accounting tooling, compilers, nginx TLS
# All low-risk and reversible; raises the audit posture without operational cost.
log "OS baseline (extended): SSH hardening, integrity/accounting tools, compilers"

# SSH: strong, key-only. Drop-in read FIRST (00-) so its values win over the
# cloud-image defaults. Validate before reload; reload keeps live sessions up.
if [ -d /etc/ssh/sshd_config.d ]; then
  cp "$CFG/sshd-hardening.conf" /etc/ssh/sshd_config.d/00-hardening.conf
  chmod 600 /etc/ssh/sshd_config.d/00-hardening.conf
  if sshd -t 2>/tmp/sshd-test.err; then
    systemctl reload ssh 2>/dev/null || systemctl reload sshd 2>/dev/null || true
    info "sshd hardened (config valid, reloaded — existing sessions unaffected)"
  else
    warn "sshd -t failed; removed drop-in, NOT reloading. See /tmp/sshd-test.err"
    rm -f /etc/ssh/sshd_config.d/00-hardening.conf
  fi
fi

# Integrity + accounting + patch-management tooling (audit tools reward presence).
# Best-effort per package (apt-listbugs has no candidate on some releases, etc.).
install_optional debsums libpam-tmpdir apt-listchanges \
                 apt-show-versions sysstat acct rkhunter
systemctl enable --now acct 2>/dev/null || systemctl enable --now psacct 2>/dev/null || true
if [ -f /etc/default/sysstat ]; then
  sed -i 's/^ENABLED=.*/ENABLED="true"/' /etc/default/sysstat
  systemctl enable --now sysstat 2>/dev/null || true
fi
if [ -f /etc/default/rkhunter ]; then
  sed -i -e 's/^CRON_DAILY_RUN=.*/CRON_DAILY_RUN="true"/' \
         -e 's/^APT_AUTOGEN=.*/APT_AUTOGEN="true"/' /etc/default/rkhunter
fi
command -v rkhunter >/dev/null 2>&1 && rkhunter --propupd --quiet 2>/dev/null || true

# Restrict compilers to root only (no non-root code compilation on a web host).
for p in /usr/bin/cc /usr/bin/gcc /usr/bin/g++ /usr/bin/clang /usr/bin/gcc-*; do
  [ -e "$p" ] || continue
  chown root:root "$p" 2>/dev/null || true
  chmod 750 "$p" 2>/dev/null || true
done

# nginx ships TLSv1/1.1 in the default http block — pin to 1.2/1.3 in place.
if [ -f /etc/nginx/nginx.conf ]; then
  sed -i -E 's/^(\s*)ssl_protocols[[:space:]].*/\1ssl_protocols TLSv1.2 TLSv1.3;/' /etc/nginx/nginx.conf
  nginx -t 2>/dev/null && systemctl reload nginx 2>/dev/null || true
fi

log "OS hardening complete. Measure with:  audit-os.sh --verify   (baseline: audit-os.sh --baseline)"
log "Next: harden-vhost.sh per site (AppArmor in COMPLAIN — soak, then enforce)."
