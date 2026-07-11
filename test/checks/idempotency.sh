#!/usr/bin/env bash
# Re-runs the scripts and asserts the generated state is byte-identical (a clean
# no-op) and both scripts still exit 0.
# Usage: idempotency.sh <repo>
REPO="${1:?repo}"
SITE="${SITE:-web_user}"
PHP_VERSION="${PHP_VERSION:-8.1}"
fail=0
ok()  { echo "  PASS  $*"; }
bad() { echo "  FAIL  $*"; fail=1; }

FILES=(
  "/etc/php/${PHP_VERSION}/fpm/pool.d/${SITE}.conf"
  "/etc/apparmor.d/php-fpm.d/${SITE}"
  "/etc/nginx/sites-available/${SITE}"
  "/etc/systemd/system/php${PHP_VERSION}-fpm.service.d/${SITE}-reach.conf"
  "/etc/ufw/before.rules"
  "/etc/hardening/sites/${SITE}/reach-rw.paths"
  "/etc/hardening/sites/${SITE}/reach-ro.paths"
)
snap()      { for f in "${FILES[@]}"; do echo "== $f =="; cat "$f" 2>/dev/null; done | sha256sum | cut -d' ' -f1; }
snap_list() { for f in "${FILES[@]}"; do printf '%s  %s\n' "$(sha256sum "$f" 2>/dev/null | cut -d' ' -f1)" "$f"; done; }

before="$(snap)"; before_list="$(snap_list)"
cp -a /etc/php/${PHP_VERSION}/fpm/pool.d/${SITE}.conf /tmp/pool.before 2>/dev/null || true
cp -a /etc/apparmor.d/php-fpm.d/${SITE} /tmp/hat.before 2>/dev/null || true
cp -a /etc/ufw/before.rules /tmp/before.rules.before 2>/dev/null || true
# Re-run with the SAME inputs the first run used (in-container.sh points the
# DB egress at the test DB container), or egress_allow appends a different rule.
set -a; . "$REPO/sites/web_user.env"; CONTAINER=1; ASSUME_YES=1; SERVER_NAME=localhost; RUN_AIDEINIT=no; SSH_HARDEN=no
[ -n "${DB_TEST_HOST:-}" ] && DB_HOST="$DB_TEST_HOST"
[ -n "${DB_TEST_PORT:-}" ] && DB_PORT="$DB_TEST_PORT"
set +a

if bash "$REPO/scripts/harden-os.sh"    >/tmp/os2.log 2>&1; then ok "harden-os.sh re-run exit 0"; else bad "harden-os.sh re-run failed (see /tmp/os2.log)"; tail -5 /tmp/os2.log; fi
if bash "$REPO/scripts/harden-vhost.sh" >/tmp/vh2.log 2>&1; then ok "harden-vhost.sh re-run exit 0"; else bad "harden-vhost.sh re-run failed (see /tmp/vh2.log)"; tail -5 /tmp/vh2.log; fi

after="$(snap)"; after_list="$(snap_list)"
if [ "$before" = "$after" ]; then
  ok "generated state unchanged on re-run ($after)"
else
  bad "state changed on re-run"
  echo "    changed files:"; diff <(echo "$before_list") <(echo "$after_list") | sed 's/^/      /'
  for pair in "pool:/etc/php/${PHP_VERSION}/fpm/pool.d/${SITE}.conf:/tmp/pool.before" \
              "hat:/etc/apparmor.d/php-fpm.d/${SITE}:/tmp/hat.before" \
              "before.rules:/etc/ufw/before.rules:/tmp/before.rules.before"; do
    name="${pair%%:*}"; rest="${pair#*:}"; cur="${rest%%:*}"; old="${rest#*:}"
    if ! diff -q "$old" "$cur" >/dev/null 2>&1; then
      echo "    --- diff in $name ---"; diff "$old" "$cur" | sed 's/^/      /'
    fi
  done
fi

# Also verify tune-vhost round-trips through all three reach targets.
echo "--- tune-vhost.sh grant-write /var/www/html/web_user/shared ---"
mkdir -p /var/www/html/web_user/shared
bash "$REPO/scripts/tune-vhost.sh" "$SITE" grant-write /var/www/html/web_user/shared >/tmp/tune.log 2>&1 || { bad "tune grant-write failed"; tail -5 /tmp/tune.log; }
POOL="/etc/php/${PHP_VERSION}/fpm/pool.d/${SITE}.conf"
HAT="/etc/apparmor.d/php-fpm.d/${SITE}"
RWP="/etc/systemd/system/php${PHP_VERSION}-fpm.service.d/${SITE}-reach.conf"
grep -q '/var/www/html/web_user/shared/' "$POOL" && ok "grant-write -> pool open_basedir" || bad "grant-write not in pool open_basedir"
grep -q '/var/www/html/web_user/shared/ rw' "$HAT" && ok "grant-write -> AppArmor hat"     || bad "grant-write not in AppArmor hat"
grep -q '/var/www/html/web_user/shared' "$RWP" && ok "grant-write -> systemd ReadWritePaths" || bad "grant-write not in systemd RWP"

exit $fail
