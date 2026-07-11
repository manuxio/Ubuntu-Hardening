#!/usr/bin/env bash
# Asserts the filesystem permission model (the "web_user" identity model).
# Usage: fs-model.sh <docroot>
DOC="${1:?docroot}"
RU="${RUNTIME_USER:-web_user}"
WU="${WEB_USER:-www-data}"
fail=0
ok()   { echo "  PASS  $*"; }
bad()  { echo "  FAIL  $*"; fail=1; }

mode() { stat -c '%a' "$1" 2>/dev/null; }
owng() { stat -c '%U:%G' "$1" 2>/dev/null; }

# Code dir owned by web user, mode 750.
[ "$(owng "$DOC")" = "$WU:$WU" ] && ok "docroot owned $WU:$WU" || bad "docroot owner = $(owng "$DOC") (want $WU:$WU)"
[ "$(mode "$DOC")" = "750" ]     && ok "docroot mode 750"       || bad "docroot mode = $(mode "$DOC") (want 750)"

# Parent traversable by web user (nginx runs as www-data).
PARENT="$(dirname "$DOC")"
[ "$(owng "$PARENT")" = "$WU:$WU" ] && ok "parent owned $WU:$WU (nginx can traverse)" || bad "parent owner = $(owng "$PARENT")"

# configuration.php read-only.
if [ -f "$DOC/configuration.php" ]; then
  [ "$(mode "$DOC/configuration.php")" = "640" ] && ok "configuration.php 640" || bad "configuration.php mode = $(mode "$DOC/configuration.php")"
fi

# Writable dir images/ is setgid + group-writable (2770).
[ "$(mode "$DOC/images")" = "2770" ] && ok "images/ mode 2770 (setgid+group rwx)" || bad "images/ mode = $(mode "$DOC/images")"

# Runtime user can WRITE images, and CANNOT write code / configuration.php.
if id "$RU" >/dev/null 2>&1; then
  sudo -u "$RU" test -w "$DOC/images"            && ok "$RU can write images/"            || bad "$RU cannot write images/ (should)"
  sudo -u "$RU" test ! -w "$DOC/configuration.php" && ok "$RU cannot write configuration.php" || bad "$RU can write configuration.php (should not)"
  # code write: try to create a file in the docroot root as RU (must fail).
  if sudo -u "$RU" bash -c "echo x > '$DOC/_fs_code_probe' 2>/dev/null"; then
    bad "$RU could create a file in the code dir (should not)"; rm -f "$DOC/_fs_code_probe"
  else
    ok "$RU cannot create files in the code dir"
  fi
  # runtime user must be in the web group.
  id -nG "$RU" | tr ' ' '\n' | grep -qx "$WU" && ok "$RU is in the $WU group" || bad "$RU not in $WU group"
else
  bad "runtime user $RU does not exist"
fi

exit $fail
