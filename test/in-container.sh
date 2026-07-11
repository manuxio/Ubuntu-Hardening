#!/usr/bin/env bash
# Runs INSIDE the Tier-1 container. Sets up a throwaway Joomla-ish site, runs
# harden-os.sh + harden-vhost.sh non-interactively, starts nginx + php-fpm by
# hand (no systemd here), then runs the checks. Exit non-zero on any failure.
set -uo pipefail

# Work from a CR-stripped copy so a Windows-host mount can't break bash.
rm -rf /opt/h && cp -r /work /opt/h
find /opt/h/scripts -type f -exec dos2unix -q {} + 2>/dev/null || true
find /opt/h/test    -type f -name '*.sh' -exec dos2unix -q {} + 2>/dev/null || true
chmod +x /opt/h/scripts/*.sh /opt/h/test/*.sh /opt/h/test/checks/*.sh 2>/dev/null || true
REPO=/opt/h

echo "############################################################"
echo "# Tier-1 ephemeral hardening test"
echo "############################################################"

# --- Build a throwaway Joomla-like docroot ----------------------------------
DOC=/var/www/html/web_user/public_html
mkdir -p "$DOC"/{images,media,cache,administrator/cache}
cat > "$DOC/configuration.php" <<'PHP'
<?php class JConfig { public $tmp_path='/var/www/html/web_user/tmp'; public $log_path='/var/www/html/web_user/logs'; }
PHP
echo '<?php echo "home";' > "$DOC/index.php"
cp "$REPO/test/checks/probe.php" "$DOC/probe.php"
echo '<?php echo "PWNED-shell";' > "$DOC/images/shell.php"     # webshell dropped in an upload dir
printf '<?php echo "PWNED-jpg"; ?>\n' > "$DOC/images/photo.jpg" # PHP smuggled as an image
echo '<sample/>' > "$DOC/media/sample.txt"

# --- Run the hardening scripts (non-interactive, container mode) -------------
set -a
# shellcheck disable=SC1091
. "$REPO/sites/web_user.env"
CONTAINER=1
ASSUME_YES=1
SERVER_NAME=localhost      # so `curl localhost` matches the server_name
RUN_AIDEINIT=no
SSH_HARDEN=no
# When run-tests.sh provides a MariaDB container, point this site's egress at it
# so the allow rule reflects the real DB the connectivity probe uses.
[ -n "${DB_TEST_HOST:-}" ] && DB_HOST="$DB_TEST_HOST"
[ -n "${DB_TEST_PORT:-}" ] && DB_PORT="$DB_TEST_PORT"
set +a

echo; echo "=== harden-os.sh ==="
bash "$REPO/scripts/harden-os.sh"        || { echo "harden-os.sh FAILED"; exit 1; }
echo; echo "=== harden-vhost.sh ==="
bash "$REPO/scripts/harden-vhost.sh"     || { echo "harden-vhost.sh FAILED"; exit 1; }

# --- Start php-fpm + nginx by hand ------------------------------------------
echo; echo "=== starting php-fpm + nginx ==="
mkdir -p /run/php
pkill -f 'php-fpm: master' 2>/dev/null || true
php-fpm8.1 -t
php-fpm8.1 -D
nginx -t
nginx || nginx -s reload || true
sleep 1
ls -l /run/php/ || true

# --- Run checks --------------------------------------------------------------
rc=0
echo; echo "=== checks/fs-model.sh ===";      bash "$REPO/test/checks/fs-model.sh"      "$DOC" || rc=1
echo; echo "=== checks/php-behavior.sh ===";  bash "$REPO/test/checks/php-behavior.sh"          || rc=1
echo; echo "=== checks/idempotency.sh ===";   bash "$REPO/test/checks/idempotency.sh"   "$REPO" || rc=1

echo
if [ $rc -eq 0 ]; then echo "########## TIER-1: ALL CHECKS PASSED ##########";
else echo "########## TIER-1: FAILURES (rc=$rc) ##########"; fi
exit $rc
