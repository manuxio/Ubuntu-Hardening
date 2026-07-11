#!/usr/bin/env bash
# Host-side Tier-1 runner. Builds the pre-baked image, starts a small EPHEMERAL
# MariaDB container (the typical CMS database), then runs an ephemeral (--rm)
# test container with the repo bind-mounted read-write at /work. Everything is
# torn down on exit. Works from Linux/macOS and Windows Git-Bash.
set -euo pipefail
cd "$(dirname "$0")/.."
REPO="$(pwd)"

# Docker Desktop on Windows needs a Windows-style mount source.
if pwd -W >/dev/null 2>&1; then MOUNT="$(pwd -W)"; else MOUNT="$REPO"; fi

IMAGE=ubuntu-harden-tier1
NET=harden-test-net
DB=harden-test-db
DB_IMAGE="${DB_IMAGE:-mariadb:11.4}"     # MariaDB = the usual Joomla/WordPress DB
DBNAME=joomla_db
DBUSER=web_user
DBPASS=web_userpass
DBROOT=rootpass

cleanup() {
  echo ">> cleanup"
  docker rm -f "$DB" >/dev/null 2>&1 || true
  docker network rm "$NET" >/dev/null 2>&1 || true
}
trap cleanup EXIT

echo ">> building $IMAGE"
docker build -t "$IMAGE" -f test/Dockerfile.tier1 test/

echo ">> starting ephemeral MariaDB ($DB_IMAGE)"
docker network create "$NET" >/dev/null 2>&1 || true
docker rm -f "$DB" >/dev/null 2>&1 || true
docker run -d --name "$DB" --network "$NET" \
  -e MARIADB_ROOT_PASSWORD="$DBROOT" \
  -e MARIADB_DATABASE="$DBNAME" \
  -e MARIADB_USER="$DBUSER" \
  -e MARIADB_PASSWORD="$DBPASS" \
  "$DB_IMAGE" >/dev/null

echo -n ">> waiting for MariaDB "
ready=0
for _ in $(seq 1 60); do
  if docker exec "$DB" mariadb -uroot -p"$DBROOT" -e 'SELECT 1' >/dev/null 2>&1; then ready=1; echo " ready"; break; fi
  echo -n "."; sleep 2
done
[ "$ready" = 1 ] || { echo " TIMEOUT (DB not ready)"; docker logs --tail 20 "$DB" || true; }

echo ">> running ephemeral Tier-1 container"
MSYS_NO_PATHCONV=1 docker run --rm --network "$NET" \
  -e DB_TEST_HOST="$DB" -e DB_TEST_PORT=3306 \
  -e DB_TEST_USER="$DBUSER" -e DB_TEST_PASS="$DBPASS" -e DB_TEST_NAME="$DBNAME" \
  -v "${MOUNT}:/work" -w /work \
  "$IMAGE" bash /work/test/in-container.sh
