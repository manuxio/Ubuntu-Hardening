#!/usr/bin/env bash
# Live php-fpm behavior via nginx. Curls the probe + exercises the nginx routing
# protections (script-must-exist, PHP-off in upload dirs, inert static serving).
BASE="${BASE:-http://localhost}"
RU="${RUNTIME_USER:-web_user}"
fail=0
ok()  { echo "  PASS  $*"; }
bad() { echo "  FAIL  $*"; fail=1; }

code() { curl -s -o /dev/null -w '%{http_code}' "$1"; }
body() { curl -s "$1"; }

# 1) probe.php returns 200 and each hardening assertion is PASS.
PROBE="$(body "$BASE/probe.php")"
echo "--- probe.php ---"; echo "$PROBE" | sed 's/^/    /'
for key in open_basedir_passwd disable_functions_set exec_blocked code_write_denied data_write_ok allow_url_fopen_off expose_php_off; do
  if echo "$PROBE" | grep -qx "$key=PASS"; then ok "probe $key"; else bad "probe $key ($(echo "$PROBE" | grep "^$key=" || echo missing))"; fi
done
# runs as the runtime user
if echo "$PROBE" | grep -qx "whoami=$RU"; then ok "worker runs as $RU"; else bad "worker identity $(echo "$PROBE" | grep '^whoami=')"; fi

# 2) script-must-exist: a non-existent .php -> 404, never proxied.
c="$(code "$BASE/does-not-exist.php")"
[ "$c" = "404" ] && ok "nonexistent .php -> 404 (script-must-exist)" || bad "nonexistent .php -> $c (want 404)"

# 3) PHP disabled in an upload dir: images/shell.php -> denied (403), not executed.
c="$(code "$BASE/images/shell.php")"
[ "$c" = "403" ] && ok "images/shell.php -> 403 (PHP off in upload dir)" || bad "images/shell.php -> $c (want 403)"

# 4) PHP smuggled as .jpg is served inert (raw source, not executed).
b="$(body "$BASE/images/photo.jpg")"
if echo "$b" | grep -q '<?php'; then ok "photo.jpg served inert (raw <?php, not executed)"; else bad "photo.jpg body did not contain raw PHP: [$b]"; fi

# 5) Database connectivity through the hardened pool (typical CMS need).
if [ -n "${DB_TEST_HOST:-}" ]; then
  q="db_host=${DB_TEST_HOST}&db_port=${DB_TEST_PORT:-3306}&db_user=${DB_TEST_USER}&db_pass=${DB_TEST_PASS}&db_name=${DB_TEST_NAME}"
  DBOUT="$(body "$BASE/probe.php?$q")"
  echo "--- db probe ---"; echo "$DBOUT" | grep -E '^db_' | sed 's/^/    /'
  if echo "$DBOUT" | grep -qx "db_connect=PASS"; then ok "php-fpm ($RU) connected to MariaDB and ran SELECT 1"; else bad "DB connect failed ($(echo "$DBOUT" | grep '^db_connect='))"; fi
else
  echo "  SKIP  DB connectivity (no DB_TEST_HOST — start with test/run-tests.sh for the MariaDB container)"
fi

exit $fail
