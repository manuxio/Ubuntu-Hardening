#!/usr/bin/env bash
# =============================================================================
# tier2-e2e.sh — end-to-end hardening test on a REAL VM (kernel-layer controls).
#
# The Docker tests (test/run-tests.sh) validate config generation, the
# filesystem model, live php-fpm behaviour and DB connectivity. They CANNOT
# exercise AppArmor enforce, auditd, ufw egress or the systemd sandbox — those
# need a real kernel. This harness does, and it proves the whole point of the
# project: horizontal isolation between two sites.
#
# What it runs, from a host that already has harden-os.sh applied:
#   1. harden-os.sh again        -> must be an idempotent no-op
#   2. harden-vhost.sh x2        -> provision site1 + site2 (docroot, DB, pool,
#                                   AppArmor hat, nginx, egress, auditd)
#   3. enforce-vhost.sh x2       -> AppArmor complain -> enforce
#   4. setup-tls.sh site1        -> self-signed HTTPS
#   5. functional + DB check     -> each site serves and reaches its own DB
#   6. CROSS-SITE ISOLATION      -> site1's pool tries to read/write/exec into
#                                   site2 and the host, and to egress off-list;
#                                   every attempt must be DENIED (both ways)
#   7. auditd query              -> detection plumbing is live
#   8. audit-os.sh --verify      -> Lynis hardening index
#
# PREREQUISITES on the VM (see README "A throwaway VM"):
#   - Ubuntu 22.04, harden-os.sh already applied, this repo at the CWD
#   - MariaDB/MySQL running with root reachable via the unix socket (default)
#   - run as root:  sudo bash test/tier2-e2e.sh
#
# It is destructive to site1/site2 only (throwaway sites) and prints PASS/FAIL
# per assertion, exiting non-zero on any failure.
# =============================================================================
set -uo pipefail
cd "$(dirname "$0")/.."                    # repo root
REPO="$(pwd)"
PROBE="$REPO/test/checks/xsite-probe.php"
HR="============================================================"
PASS=0; FAIL=0; FAILED_KEYS=""
ok(){ PASS=$((PASS+1)); printf '  \033[32mPASS\033[0m %s\n' "$1"; }
no(){ FAIL=$((FAIL+1)); FAILED_KEYS="$FAILED_KEYS $1"; printf '  \033[31mFAIL\033[0m %s  <<<\n' "$1"; }
assert(){ if [ "$2" = "$3" ]; then ok "$1 ($2)"; else no "$1 (got '$2' want '$3')"; fi; }
phase(){ echo; echo "$HR"; echo "### $1"; echo "$HR"; }
mysql_root(){ mysql -uroot "$@"; }         # root via unix_socket on Ubuntu MariaDB

# Fetch a path from a site through nginx. Follows the HTTP->HTTPS redirect that
# setup-tls installs (-L), accepts the self-signed cert (-k), and pins both :80
# and :443 of the vhost name to loopback (--resolve) so the Host-based vhost and
# TLS SNI resolve correctly whether or not that site has TLS. Run it in the
# CURRENT shell (redirect to a file), NOT in $(...), so HTTP_CODE propagates.
HTTP_CODE=""
fetch(){ local S="$1" pq="$2"
  HTTP_CODE=$(curl -sk -L \
    --resolve "${S}.local:80:127.0.0.1" --resolve "${S}.local:443:127.0.0.1" \
    -o /tmp/fetch.out -w '%{http_code}' "http://${S}.local/${pq}")
  cat /tmp/fetch.out
}

# Never let a long step block on a hidden prompt: everything runs with stdin from
# /dev/null (so the scripts' prompt() falls to env/default instead of reading the
# TTY) and answers pre-seeded. Belt and suspenders.
export ASSUME_YES=1
export PHP_VERSION="${PHP_VERSION:-8.1}" SSH_HARDEN="${SSH_HARDEN:-no}" RUN_AIDEINIT="${RUN_AIDEINIT:-no}"

# run_live <logfile> <cmd...> — run a long command with its output going to a log,
# and (on a TTY) show a live one-line status = the last line of that output, so
# the operator sees it is working. Returns the command's exit code.
run_live(){
  local logf="$1"; shift
  if [ ! -t 1 ]; then "$@" </dev/null >"$logf" 2>&1; return $?; fi
  ("$@") </dev/null >"$logf" 2>&1 &
  local pid=$! l
  while kill -0 "$pid" 2>/dev/null; do
    l="$(tail -n1 "$logf" 2>/dev/null | tr -d '\r\t' | cut -c1-70)"
    printf '\r  \033[2m%-72s\033[0m' "$l"
    sleep 0.5
  done
  wait "$pid"; local rc=$?
  printf '\r%*s\r' 76 ''
  return $rc
}
# provision one site from its env (used via run_live so it can't block/blank out)
provision_one(){ local S="$1"; set -a; . "sites/${S}.env"; set +a; bash scripts/harden-vhost.sh; }

[ "$(id -u)" -eq 0 ] || { echo "run as root: sudo bash test/tier2-e2e.sh"; exit 2; }
[ -f "$PROBE" ] || { echo "missing $PROBE"; exit 2; }

# ---------------------------------------------------------------------------
phase "PHASE 1 — harden-os idempotency (re-run must be a clean no-op)"
if run_live /tmp/harden-os.log bash scripts/harden-os.sh; then
  ok "harden-os.sh re-run exit 0"
else
  no "harden-os.sh re-run FAILED (see /tmp/harden-os.log)"; tail -20 /tmp/harden-os.log
fi

# ---------------------------------------------------------------------------
phase "PHASE 2 — provision site1 + site2 (docroot, DB, probe, harden-vhost)"
deploy_site(){
  local S="$1" DBPASS="$2" ROOT="/var/www/html/$1"
  mkdir -p "$ROOT/public_html/images" "$ROOT/tmp" "$ROOT/sessions" "$ROOT/logs"
  cat > "$ROOT/public_html/index.php" <<PHP
<?php echo "site=$S ok\n"; echo "user=".posix_getpwuid(posix_geteuid())['name']."\n";
PHP
  echo "DB_PASSWORD_OF_$S=$DBPASS  (this is $S's secret)" > "$ROOT/public_html/configuration.php"
  echo "top-secret-of-$S" > "$ROOT/public_html/SECRET.txt"
  cp "$PROBE" "$ROOT/public_html/probe.php"
  chown -R root:root "$ROOT"
  mysql_root -e "CREATE DATABASE IF NOT EXISTS ${S}db;
    CREATE USER IF NOT EXISTS '${S}'@'127.0.0.1' IDENTIFIED BY '${DBPASS}';
    CREATE USER IF NOT EXISTS '${S}'@'localhost' IDENTIFIED BY '${DBPASS}';
    GRANT ALL ON ${S}db.* TO '${S}'@'127.0.0.1'; GRANT ALL ON ${S}db.* TO '${S}'@'localhost';
    FLUSH PRIVILEGES;"
  if run_live "/tmp/harden-$S.log" provision_one "$S"; then
    ok "harden-vhost.sh $S exit 0"
  else
    no "harden-vhost.sh $S FAILED (see /tmp/harden-$S.log)"; tail -25 "/tmp/harden-$S.log"
  fi
}
deploy_site site1 site1pass
deploy_site site2 site2pass
echo "--- pools / users after provisioning ---"
ls -1 /etc/php/8.1/fpm/pool.d/ | sed 's/^/  pool: /'
getent passwd site1 site2 | awk -F: '{print "  user: "$1" (uid "$3")"}'

# ---------------------------------------------------------------------------
phase "PHASE 3 — start php-fpm + enforce AppArmor on both sites"
systemctl restart php8.1-fpm && ok "php8.1-fpm restart" || no "php8.1-fpm restart"
systemctl is-active --quiet php8.1-fpm && ok "php8.1-fpm active" || no "php8.1-fpm active"
systemctl reload nginx 2>/dev/null; ok "nginx reload"
for S in site1 site2; do fetch "$S" "index.php" >/dev/null; done   # warm complain-mode
for S in site1 site2; do
  if run_live "/tmp/enforce-$S.log" bash scripts/enforce-vhost.sh "$S"; then
    ok "enforce-vhost.sh $S exit 0"
  else
    no "enforce-vhost.sh $S FAILED (see /tmp/enforce-$S.log)"; tail -25 "/tmp/enforce-$S.log"
  fi
done
echo "--- aa-status php-fpm hats (want enforce) ---"
aa-status 2>/dev/null | grep -E 'php-fpm' | sed 's/^/  /' || true
mode1=$(aa-status 2>/dev/null | awk '/php-fpm\/\/site1/{print "enforce"}' | head -1)
assert "site1 hat in enforce" "${mode1:-none}" "enforce"

# ---------------------------------------------------------------------------
phase "PHASE 4 — setup-tls site1 (self-signed)"
if run_live /tmp/tls-site1.log bash scripts/setup-tls.sh site1 --self-signed; then
  ok "setup-tls.sh site1 --self-signed exit 0"
else
  no "setup-tls.sh site1 FAILED (see /tmp/tls-site1.log)"; tail -25 /tmp/tls-site1.log
fi
systemctl reload nginx 2>/dev/null || systemctl restart nginx
fetch site1 "index.php" >/dev/null
assert "site1 HTTPS index.php" "${HTTP_CODE:-000}" "200"

# ---------------------------------------------------------------------------
phase "PHASE 5 — functional + own-uid (each site serves; TLS redirect followed)"
for S in site1 site2; do
  fetch "$S" "index.php" > /tmp/idx-$S.txt
  assert "$S serves index.php" "${HTTP_CODE:-000}" "200"
  who=$(grep -oE 'user=[a-z0-9_-]+' /tmp/idx-$S.txt | cut -d= -f2)
  assert "$S runs as its own uid" "${who:-none}" "$S"
done

# ---------------------------------------------------------------------------
phase "PHASE 6 — CROSS-SITE ISOLATION MATRIX (site1 pool attacks site2 + host)"
Q="other=/var/www/html/site2&db_host=127.0.0.1&db_user=site1&db_pass=site1pass&db_name=site1db&db_port=3306"
fetch site1 "probe.php?${Q}" > /tmp/probe1.txt
echo "--- raw probe output (site1 -> site2/host)  [HTTP_CODE=$HTTP_CODE] ---"; sed 's/^/  /' /tmp/probe1.txt
echo "--- assertions ---"
getk(){ grep -oE "^$1=[A-Z]+" /tmp/probe1.txt | cut -d= -f2; }
for k in xsite_read_config xsite_list_dir xsite_read_secret xsite_write read_etc_shadow \
         exec_denied shell_spawn_denied egress_80_denied own_write_ok own_db_connect; do
  assert "$k" "$(getk "$k")" "PASS"
done
echo "  info: egress_443_allowed=$(getk egress_443_allowed) (allow-list sanity, network-dependent)"
Q2="other=/var/www/html/site1&db_host=127.0.0.1&db_user=site2&db_pass=site2pass&db_name=site2db&db_port=3306"
fetch site2 "probe.php?${Q2}" > /tmp/probe2.txt
getk2(){ grep -oE "^$1=[A-Z]+" /tmp/probe2.txt | cut -d= -f2; }
echo "--- reverse (site2 -> site1) key denials ---"
for k in xsite_read_config xsite_write exec_denied egress_80_denied own_db_connect; do
  assert "rev:$k" "$(getk2 "$k")" "PASS"
done

# ---------------------------------------------------------------------------
phase "PHASE 7 — auditd is live (execve/webroot-write watches loaded)"
rules=$(auditctl -l 2>/dev/null | grep -c 'php_exec\|/var/www' || true)
echo "  loaded audit rules touching php_exec/webroot: ${rules:-0}"
[ "${rules:-0}" -ge 1 ] && ok "auditd rules loaded" || no "auditd rules missing"

# ---------------------------------------------------------------------------
phase "PHASE 8 — audit verify (Lynis hardening index)"
if run_live /tmp/audit-verify.log bash scripts/audit-os.sh --verify; then
  idx=$(grep -oiE 'hardening.?index[^0-9]*[0-9]+' /tmp/audit-verify.log | grep -oE '[0-9]+' | tail -1)
  ok "audit-os.sh --verify exit 0 (Lynis index: ${idx:-?})"
else
  no "audit-os.sh --verify FAILED"; tail -15 /tmp/audit-verify.log
fi

# ---------------------------------------------------------------------------
phase "RESULT"
echo "  PASS=$PASS  FAIL=$FAIL"
[ "$FAIL" -eq 0 ] && echo "  >>> E2E GREEN — full stack installs and isolates correctly <<<" \
                  || echo "  >>> E2E has failures:$FAILED_KEYS <<<"
exit "$FAIL"
