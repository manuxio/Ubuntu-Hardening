#!/usr/bin/env bash
# =============================================================================
# export-site.sh <site> [--compose|--k8s|--both] [-o <outdir>]
#
# Turns a hardened vhost into a minimal, self-contained CONTAINER bundle that
# keeps the SAME runtime containment as the host (non-root, read-only rootfs,
# all caps dropped, no-new-privileges, seccomp + optional AppArmor, per-site
# egress) — as a docker-compose stack for local testing AND as Kubernetes
# manifests. Same PHP version, same file structure (persistent volume), same
# php_admin_* hardening. Host-only tooling (Lynis/Trivy/OpenSCAP/YARA) is NOT
# part of the container — those are host/CI scanners.
#
# It reads the site's policy state (/etc/hardening/sites/<site>/) and PROMPTS for
# the container-specific knobs (image names, replicas, namespace, Redis, volume).
# Env-overridable for non-interactive use (see prompt()).
# =============================================================================
set -euo pipefail

SELF="$(cd "$(dirname "$0")" && pwd)"
REPO="$(dirname "$SELF")"
. "$SELF/lib/common.sh"
. "$SELF/lib/policy.sh"
require_root

TPL="$REPO/templates/container"
[ -d "$TPL" ] || die "templates/container missing"

SITE="${1:-}"; shift 2>/dev/null || true
[ -n "$SITE" ] || die "usage: export-site.sh <site> [--compose|--k8s|--both] [-o outdir]"
policy_site_exists "$SITE" || die "unknown site '$SITE' (harden-vhost.sh it first)"

TARGET=both; OUTDIR=""
while [ $# -gt 0 ]; do
  case "$1" in
    --compose) TARGET=compose ;;
    --k8s) TARGET=k8s ;;
    --both) TARGET=both ;;
    -o) OUTDIR="${2:?}"; shift ;;
    *) die "unknown option: $1" ;;
  esac; shift
done

STATE="$(policy_state_dir "$SITE")"

# --- pull the site's facts from state + answers.env --------------------------
[ -f "$STATE/answers.env" ] && { set -a; . "$STATE/answers.env"; set +a; }
PHP_VERSION="$(policy_meta_get "$SITE" PHP_VERSION)"; PHP_VERSION="${PHP_VERSION:-8.1}"
DOCROOT="$(policy_meta_get "$SITE" DOCROOT)"; DOCROOT="${DOCROOT%/}"
RUNTIME_USER="$(policy_meta_get "$SITE" RUNTIME_USER)"; RUNTIME_USER="${RUNTIME_USER:-$SITE}"
RUNTIME_UID="$(policy_meta_get "$SITE" UID)"; RUNTIME_UID="${RUNTIME_UID:-10001}"
SERVER_NAME="$(awk '{print $1}' <<< "$(policy_meta_get "$SITE" SERVER_NAME)")"; SERVER_NAME="${SERVER_NAME:-$SITE.local}"
SITE_ROOT="$(dirname "$DOCROOT")"
WEB_GID=33                                   # www-data in the Debian php/nginx images
TMP_PATH="${TMP_PATH:-$SITE_ROOT/tmp}"
SESSION_PATH="${SESSION_PATH:-$SITE_ROOT/sessions}"
LOG_PATH="${LOG_PATH:-$SITE_ROOT/logs}"

# current php_admin values from the live pool (tune-vhost may have changed them)
POOL="/etc/php/${PHP_VERSION}/fpm/pool.d/${SITE}.conf"
_pv() { grep -oE "^php_admin_value\[$1\][[:space:]]*=[[:space:]]*.*" "$POOL" 2>/dev/null | sed 's/.*=[[:space:]]*//' | head -1 || true; }
_df="$(_pv disable_functions)"; DISABLE_FUNCTIONS="${_df:-exec,passthru,shell_exec,system,proc_open,popen,pcntl_exec,proc_close,proc_get_status,dl,posix_kill,posix_setuid,posix_setgid,posix_mkfifo}"
_ml="$(_pv memory_limit)"; MEMORY_LIMIT="${_ml:-${MEMORY_LIMIT:-256M}}"
UPLOAD_MAX_FILESIZE="${UPLOAD_MAX_FILESIZE:-32M}"
POST_MAX_SIZE="${POST_MAX_SIZE:-32M}"
MAX_EXECUTION_TIME="${MAX_EXECUTION_TIME:-60}"
PM_MAX_CHILDREN="${PM_MAX_CHILDREN:-10}"
PM_MAX_REQUESTS="${PM_MAX_REQUESTS:-500}"
COOKIE_SECURE="${COOKIE_SECURE:-off}"
CLIENT_MAX_BODY="$UPLOAD_MAX_FILESIZE"
FASTCGI_PASS="127.0.0.1:9000"                # nginx shares php's netns (compose) / same pod (k8s)
FPM_ALLOWED_CLIENTS="; listen.allowed_clients not set — :9000 is isolated by the network (compose netns / k8s NetworkPolicy)"

log "exporting site '$SITE' (PHP $PHP_VERSION, runtime uid $RUNTIME_UID) -> container bundle"

# --- interactive knobs (env-overridable) -------------------------------------
prompt IMAGE_PHP     "PHP-FPM image name:tag"        "${SITE}-php:latest"
prompt IMAGE_NGINX   "nginx image name:tag"          "${SITE}-nginx:latest"
prompt HOST_DATA_PATH "Host path to bind as the persistent site volume (compose)" "$SITE_ROOT"
prompt HOST_PORT     "Host port to publish nginx on (compose)" "8080"
prompt NAMESPACE     "Kubernetes namespace"          "$SITE"
prompt REPLICAS      "Kubernetes replicas"           "2"
prompt WANT_HPA      "Add a HorizontalPodAutoscaler? (yes/no)" "no"
prompt WANT_REDIS    "Add Redis (session/cache backend)? (yes/no)" "no"
prompt WANT_BASICAUTH "Protect the container with HTTP Basic auth? (yes/no)" "no"
prompt STORAGE_CLASS "k8s StorageClass for the code PVC" "standard"
prompt PVC_SIZE      "k8s PVC size" "2Gi"

case "$REPLICAS" in ''|*[!0-9]*) REPLICAS=2 ;; esac
[ "$REPLICAS" -gt 1 ] && PVC_ACCESS_MODE=ReadWriteMany || PVC_ACCESS_MODE=ReadWriteOnce
HPA_MAX=$(( REPLICAS * 3 )); [ "$HPA_MAX" -lt 3 ] && HPA_MAX=3
COMPOSE_SUBNET="172.28.$(( (RUNTIME_UID % 240) + 5 )).0/24"
SITE_CHAIN="$(printf '%s' "$SITE" | tr -c 'A-Za-z0-9' '_')"

# k8s resources: request modest, limit a bit above the PHP memory_limit
_mem_num="$(printf '%s' "$MEMORY_LIMIT" | tr -dc '0-9')"; _mem_num="${_mem_num:-256}"
MEM_REQUEST="128Mi"; MEM_LIMIT="$(( _mem_num + 128 ))Mi"
CPU_REQUEST="100m"; CPU_LIMIT="1"

is_yes() { case "$(printf '%s' "$1" | tr A-Z a-z)" in y|yes|1|true) return 0 ;; *) return 1 ;; esac; }

# --- derive the sync'd blocks from the site's policy -------------------------
mapfile -t RWP < <(cat "$STATE/reach-rw.paths" 2>/dev/null || true)
mapfile -t ROP < <(cat "$STATE/reach-ro.paths" 2>/dev/null || true)

# open_basedir = union(ro,rw), trailing slash, ':'-joined (mirror lib/policy.sh)
_seen=""; for p in "${ROP[@]}" "${RWP[@]}"; do p="$(_norm_slash "$p")"; case ":$_seen:" in *":$p:"*) continue ;; esac; _seen="${_seen:+$_seen:}$p"; done
OPEN_BASEDIR="$_seen"

# writable dirs UNDER the docroot -> nginx nophp regex ; ALL rw dirs -> init/AA
WRITABLE_REGEX=""; WRITABLE_ABS_DIRS=""
for p in "${RWP[@]}"; do
  p="${p%/}"; [ -n "$p" ] || continue
  WRITABLE_ABS_DIRS+="$p "
  case "$p/" in "$DOCROOT"/*) rel="${p#"$DOCROOT"/}"; rel="${rel//./\\.}"; WRITABLE_REGEX="${WRITABLE_REGEX:+$WRITABLE_REGEX|}$rel" ;; esac
done
[ -n "$WRITABLE_REGEX" ] || WRITABLE_REGEX="__none__"

# AppArmor rw grants + the noext write-denies
AA_RW_BLOCK=""
for p in "${RWP[@]}"; do p="${p%/}"; [ -n "$p" ] || continue; AA_RW_BLOCK+="  ${p}/ rw,"$'\n'"  ${p}/** rwk,"$'\n'; done
if [ -f "$STATE/noext.rules" ]; then
  while IFS=$'\t' read -r dir exts; do
    [ -n "$dir" ] && [ -n "$exts" ] || continue
    AA_RW_BLOCK+="  # no-write of [$exts] in ${dir}"$'\n'
    for e in ${exts//,/ }; do [ -n "$e" ] && AA_RW_BLOCK+="  deny ${dir}/**.$(_aare_ci "$e") w,"$'\n'; done
  done < "$STATE/noext.rules"
fi

# egress: DOCKER-USER rules (compose) + NetworkPolicy egress (k8s) from the allow-list
EGRESS_DOCKER_RULES=""; NETPOL_EGRESS_RULES=""
if [ -f "$STATE/egress-v4.allow" ]; then
  while IFS= read -r frag; do
    [ -n "$frag" ] || continue
    EGRESS_DOCKER_RULES+="  iptables -A \"\$CH\" $frag -j RETURN"$'\n'
    host="$(grep -oE -- '-d [0-9.]+' <<< "$frag" | awk '{print $2}' || true)"
    port="$(grep -oE -- '--dport [0-9]+' <<< "$frag" | awk '{print $2}' || true)"
    proto="$(grep -oE -- '-p [a-z]+' <<< "$frag" | awk '{print $2}' || true)"; proto="${proto:-tcp}"
    P="$(printf '%s' "$proto" | tr a-z A-Z)"
    [ -n "$port" ] || continue
    if [ -n "$host" ]; then
      NETPOL_EGRESS_RULES+="    - to: [ { ipBlock: { cidr: ${host}/32 } } ]"$'\n'"      ports: [ { port: ${port}, protocol: ${P} } ]"$'\n'
    else
      NETPOL_EGRESS_RULES+="    - ports: [ { port: ${port}, protocol: ${P} } ]"$'\n'
    fi
  done < "$STATE/egress-v4.allow"
fi
[ -n "$EGRESS_DOCKER_RULES" ] || EGRESS_DOCKER_RULES="  : # (no extra egress destinations)"
[ -n "$NETPOL_EGRESS_RULES" ] || NETPOL_EGRESS_RULES="    # (no extra egress destinations)"

# Redis (optional) --------------------------------------------------------------
REDIS_SESSION_BLOCK=""; REDIS_COMPOSE_BLOCK=""; REDIS_EXT_BLOCK=""; REDIS_HOST=""; PECL_DEPS=""; KUSTOMIZE_EXTRA=""
if is_yes "$WANT_REDIS"; then
  PECL_DEPS="\$PHPIZE_DEPS"       # pecl needs the build toolchain; apt-mark autoremoves it
  REDIS_EXT_BLOCK="    pecl install redis; docker-php-ext-enable redis; \\
"
  REDIS_SESSION_BLOCK=$'php_admin_value[session.save_handler] = redis\nphp_admin_value[session.save_path]    = tcp://redis:6379'
  REDIS_COMPOSE_BLOCK="
  redis:
    image: redis:7-alpine
    command: [\"redis-server\",\"--save\",\"\",\"--appendonly\",\"no\",\"--maxmemory\",\"128mb\",\"--maxmemory-policy\",\"allkeys-lru\"]
    user: \"999:999\"
    read_only: true
    cap_drop: [ALL]
    security_opt: [ \"no-new-privileges:true\" ]
    tmpfs: [ /data ]
    networks: [ appnet ]
    restart: unless-stopped
"
  NETPOL_EGRESS_RULES+="    - to: [ { podSelector: { matchLabels: { app: ${SITE}-redis } } } ]"$'\n'"      ports: [ { port: 6379, protocol: TCP } ]"$'\n'
  KUSTOMIZE_EXTRA+="  - redis.yaml"$'\n'
fi
is_yes "$WANT_HPA" && KUSTOMIZE_EXTRA+="  - hpa.yaml"$'\n'
[ -n "$KUSTOMIZE_EXTRA" ] || KUSTOMIZE_EXTRA="# (no optional resources)"

# HTTP Basic auth (optional) — baked into the nginx image as /etc/nginx/.htpasswd.
BA_HTPASSWD=""; BASICAUTH_BLOCK="  # basic auth: off"; BASICAUTH_COPY="# (no basic auth)"
if is_yes "$WANT_BASICAUTH"; then
  prompt BASICAUTH_USER "Basic auth username" "admin"
  ba_pass="${BASICAUTH_PASS:-}"
  if [ -z "$ba_pass" ] && [ -t 0 ]; then read -r -s -p "Basic auth password for '$BASICAUTH_USER': " ba_pass; echo; fi
  [ -n "$ba_pass" ] || die "basic auth requested but no password (set BASICAUTH_PASS or run on a terminal)"
  BA_HTPASSWD="$(printf '%s:%s' "$BASICAUTH_USER" "$(printf '%s' "$ba_pass" | openssl passwd -apr1 -stdin)")"
  BASICAUTH_BLOCK="  auth_basic \"Area riservata\";"$'\n'"  auth_basic_user_file /etc/nginx/.htpasswd;"
  BASICAUTH_COPY="COPY .htpasswd /etc/nginx/.htpasswd"
  log "container basic auth: ON (user '$BASICAUTH_USER')"
fi

# --- render ------------------------------------------------------------------
VARS=(SITE PHP_VERSION RUNTIME_USER RUNTIME_UID WEB_GID SITE_ROOT DOCROOT SERVER_NAME
      OPEN_BASEDIR DISABLE_FUNCTIONS MEMORY_LIMIT UPLOAD_MAX_FILESIZE POST_MAX_SIZE
      MAX_EXECUTION_TIME PM_MAX_CHILDREN PM_MAX_REQUESTS COOKIE_SECURE CLIENT_MAX_BODY
      TMP_PATH SESSION_PATH LOG_PATH WRITABLE_ABS_DIRS WRITABLE_REGEX
      FASTCGI_PASS FPM_ALLOWED_CLIENTS IMAGE_PHP IMAGE_NGINX HOST_DATA_PATH HOST_PORT
      COMPOSE_SUBNET SITE_CHAIN NAMESPACE REPLICAS HPA_MAX PVC_SIZE STORAGE_CLASS
      PVC_ACCESS_MODE CPU_REQUEST CPU_LIMIT MEM_REQUEST MEM_LIMIT
      AA_RW_BLOCK EGRESS_DOCKER_RULES NETPOL_EGRESS_RULES REDIS_COMPOSE_BLOCK
      REDIS_SESSION_BLOCK REDIS_EXT_BLOCK PECL_DEPS BASICAUTH_BLOCK BASICAUTH_COPY
      KUSTOMIZE_EXTRA INIT_PERMS_INDENTED)

OUT="${OUTDIR:-$REPO/export/$SITE}"
rm -rf "$OUT"; mkdir -p "$OUT"

# the image build context (shared by compose + k8s): Dockerfiles + confs
render_build() { # dest dir
  local d="$1"; mkdir -p "$d"
  render_template "$TPL/Dockerfile.php.tmpl"   "$d/Dockerfile.php"   "${VARS[@]}"
  render_template "$TPL/Dockerfile.nginx.tmpl" "$d/Dockerfile.nginx" "${VARS[@]}"
  render_template "$TPL/pool.conf.tmpl"        "$d/pool.conf"        "${VARS[@]}"
  render_template "$TPL/nginx.conf.tmpl"       "$d/nginx.conf"       "${VARS[@]}"
  render_template "$TPL/apparmor.tmpl"         "$d/hardening-${SITE}.aa" "${VARS[@]}"
  [ -n "$BA_HTPASSWD" ] && { printf '%s\n' "$BA_HTPASSWD" > "$d/.htpasswd"; chmod 644 "$d/.htpasswd"; }
}

if [ "$TARGET" = compose ] || [ "$TARGET" = both ]; then
  CDIR="$OUT/compose"; render_build "$CDIR"
  render_template "$TPL/init-perms.sh.tmpl"       "$CDIR/init-perms.sh"       "${VARS[@]}"; chmod +x "$CDIR/init-perms.sh"
  render_template "$TPL/docker-egress.sh.tmpl"    "$CDIR/docker-egress.sh"    "${VARS[@]}"; chmod +x "$CDIR/docker-egress.sh"
  render_template "$TPL/docker-compose.yml.tmpl"  "$CDIR/docker-compose.yml"  "${VARS[@]}"
  log "compose bundle -> $CDIR"
fi

if [ "$TARGET" = k8s ] || [ "$TARGET" = both ]; then
  KDIR="$OUT/k8s"; render_build "$KDIR"
  # init-perms.sh, rendered then indented into the ConfigMap
  render_template "$TPL/init-perms.sh.tmpl" "$KDIR/init-perms.sh" "${VARS[@]}"
  INIT_PERMS_INDENTED="$(sed 's/^/    /' "$KDIR/init-perms.sh")"
  VARS+=()  # INIT_PERMS_INDENTED already in VARS
  for f in namespace configmap-init pvc deployment service networkpolicy kustomization; do
    render_template "$TPL/k8s/$f.yaml.tmpl" "$KDIR/$f.yaml" "${VARS[@]}"
  done
  is_yes "$WANT_HPA"   && render_template "$TPL/k8s/hpa.yaml.tmpl"   "$KDIR/hpa.yaml"   "${VARS[@]}"
  is_yes "$WANT_REDIS" && render_template "$TPL/k8s/redis.yaml.tmpl" "$KDIR/redis.yaml" "${VARS[@]}"
  rm -f "$KDIR/init-perms.sh"   # lives in the ConfigMap, not as a loose file
  log "k8s bundle -> $KDIR"
fi

# top-level README for the bundle
render_template "$TPL/README.bundle.md.tmpl" "$OUT/README.md" "${VARS[@]}" 2>/dev/null || true

echo
log "done. Next steps:"
[ "$TARGET" != k8s ] && cat <<EOF
  COMPOSE (local test):
    cd $OUT/compose
    docker compose up -d --build
    sudo ./docker-egress.sh apply        # optional: lock egress to DNS/DB/mail/443
    curl -H 'Host: $SERVER_NAME' http://localhost:$HOST_PORT/
    # AppArmor (optional, stronger): sudo apparmor_parser -r -W hardening-${SITE}.aa
EOF
[ "$TARGET" != compose ] && cat <<EOF
  KUBERNETES:
    cd $OUT/k8s
    docker build -f Dockerfile.php   -t $IMAGE_PHP   . && docker push $IMAGE_PHP
    docker build -f Dockerfile.nginx -t $IMAGE_NGINX . && docker push $IMAGE_NGINX
    # load the AppArmor profile on every node, then:
    kubectl apply -k .
EOF
