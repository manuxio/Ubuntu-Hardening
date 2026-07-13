#!/usr/bin/env bash
# =============================================================================
# tune-vhost.sh — day-2 policy tuning for an EXISTING vhost
#
# Changes a site's runtime-user policy after setup, keeping every place a fact
# lives in sync (via lib/policy.sh):
#   * egress   -> the <SITE>_EGRESS chain in ufw before.rules / before6.rules
#   * fs reach -> pool open_basedir + AppArmor hat + systemd ReadWritePaths
#   * settings -> pool php_admin_* and per-pool systemd cgroup caps
#
# Usage:
#   tune-vhost.sh <SITE> allow  <host|any> <port> [tcp|udp] [4|6]
#   tune-vhost.sh <SITE> deny   <host|any> <port> [tcp|udp] [4|6]
#   tune-vhost.sh <SITE> grant-write <path>
#   tune-vhost.sh <SITE> grant-read  <path>
#   tune-vhost.sh <SITE> revoke      <path>
#   tune-vhost.sh <SITE> noext-add   <dir> <ext,ext,...>  # deny writing those
#                                                 # extensions in <dir> (AppArmor)
#   tune-vhost.sh <SITE> noext-del   <dir>
#   tune-vhost.sh <SITE> auth-user   <name> [pass]   # HTTP Basic auth: add user + enable
#   tune-vhost.sh <SITE> auth-deluser <name>
#   tune-vhost.sh <SITE> auth-on | auth-off
#   tune-vhost.sh <SITE> set   <key> <value>      # memory_limit, upload_max_filesize,
#                                                 # allow_url_fopen, MemoryMax, CPUQuota,
#                                                 # pm.max_children, pm.max_requests, ...
#   tune-vhost.sh <SITE> disable <func> | enable <func>
#   tune-vhost.sh <SITE> tls-on | tls-off
#   tune-vhost.sh <SITE> server-name "<domains>"    # primary + aliases (nginx + cert)
#   tune-vhost.sh <SITE> site-enable | site-disable # nginx sites-enabled on/off
#   tune-vhost.sh <SITE> show
# Add --dry-run as the last arg to preview without applying.
# =============================================================================
set -euo pipefail

SELF="$(cd "$(dirname "$0")" && pwd)"
REPO="$(dirname "$SELF")"
. "$SELF/lib/common.sh"
. "$SELF/lib/policy.sh"
require_root

# strip a trailing --dry-run
DRY=0
if [ "${*: -1}" = "--dry-run" ]; then DRY=1; set -- "${@:1:$(($#-1))}"; fi
[ $DRY -eq 1 ] && warn "DRY-RUN: showing intended changes only"

SITE="${1:-}"; ACTION="${2:-}"; shift 2 2>/dev/null || true
[ -n "$SITE" ] && [ -n "$ACTION" ] || die "usage: tune-vhost.sh <SITE> <action> ...  (see header)"
policy_site_exists "$SITE" || die "unknown site '$SITE' — run harden-vhost.sh first"

PHP_VERSION="$(policy_meta_get "$SITE" PHP_VERSION)"
POOL="/etc/php/${PHP_VERSION}/fpm/pool.d/${SITE}.conf"
LIMITS_DROPIN="/etc/systemd/system/php${PHP_VERSION}-fpm.service.d/${SITE}-limits.conf"

# port>frag helper: build an iptables fragment for allow/deny.
_frag() {                                  # host port proto
  local host="$1" port="$2" proto="${3:-tcp}"
  if [ "$host" = "any" ]; then printf -- '-p %s --dport %s' "$proto" "$port"
  else printf -- '-p %s -d %s --dport %s' "$proto" "$host" "$port"; fi
}

case "$ACTION" in
  allow|deny)
    host="${1:?host}"; port="${2:?port}"; proto="${3:-tcp}"; ipv="${4:-4}"
    frag="$(_frag "$host" "$port" "$proto")"
    log "$ACTION egress for $SITE: $frag (v$ipv)"
    if [ $DRY -eq 0 ]; then
      [ "$ACTION" = allow ] && egress_allow "$SITE" "$frag" "$ipv" || egress_deny "$SITE" "$frag" "$ipv"
      egress_rebuild
    fi
    ;;

  grant-write|grant-read)
    path="${1:?path}"; mode=rw; [ "$ACTION" = grant-read ] && mode=ro
    log "grant $mode '$path' to $SITE (pool open_basedir + AppArmor hat + systemd RWP)"
    if [ $DRY -eq 0 ]; then reach_add "$SITE" "$path" "$mode"; reach_rebuild "$SITE"; fi
    ;;

  revoke)
    path="${1:?path}"
    log "revoke '$path' from $SITE"
    if [ $DRY -eq 0 ]; then reach_remove "$SITE" "$path"; reach_rebuild "$SITE"; fi
    ;;

  noext-add)
    dir="${1:?dir}"; exts="${2:?exts (comma/space-separated, e.g. php,phtml,phar)}"
    grep -qxF "$dir" "$(policy_state_dir "$SITE")/reach-rw.paths" 2>/dev/null || \
      warn "'$dir' is not a runtime-writable dir of $SITE — the deny will have no effect until it is (grant-write)."
    log "noext $SITE: DENY writing [$exts] in $dir (AppArmor hat)"
    if [ $DRY -eq 0 ]; then noext_set "$SITE" "$dir" "$exts"; noext_rebuild "$SITE"; fi
    ;;

  noext-del)
    dir="${1:?dir}"
    log "noext $SITE: remove extension write-deny for $dir"
    if [ $DRY -eq 0 ]; then noext_unset "$SITE" "$dir"; noext_rebuild "$SITE"; fi
    ;;

  auth-user)
    user="${1:?username}"; pass="${2:-${BASICAUTH_PASS:-}}"
    if [ -z "$pass" ]; then
      [ -t 0 ] || die "no password (pass as 2nd arg, \$BASICAUTH_PASS, or run on a terminal)"
      read -r -s -p "Password for '$user': " pass; echo
      read -r -s -p "Confirm: " pass2; echo; [ "$pass" = "$pass2" ] || die "passwords differ"
    fi
    [ -n "$pass" ] || die "empty password"
    log "basic auth $SITE: set user '$user' + ENABLE"
    if [ $DRY -eq 0 ]; then
      basicauth_set_user "$SITE" "$user" "$pass"
      policy_meta_set "$SITE" BASIC_AUTH on
      basicauth_rebuild "$SITE"
    fi
    ;;

  auth-deluser)
    user="${1:?username}"
    log "basic auth $SITE: remove user '$user'"
    if [ $DRY -eq 0 ]; then basicauth_del_user "$SITE" "$user"; basicauth_rebuild "$SITE"; fi
    ;;

  auth-on|auth-off)
    val=on; [ "$ACTION" = auth-off ] && val=off
    if [ "$val" = on ] && [ ! -s "$(basicauth_file "$SITE")" ]; then
      die "no users yet — add one first: tune-vhost.sh $SITE auth-user <name>"
    fi
    log "basic auth $SITE: ${val^^}"
    if [ $DRY -eq 0 ]; then policy_meta_set "$SITE" BASIC_AUTH "$val"; basicauth_rebuild "$SITE"; fi
    ;;

  set)
    key="${1:?key}"; val="${2:?value}"
    case "$key" in
      memory_limit|max_execution_time|upload_max_filesize|post_max_size|max_input_time)
        log "pool $SITE: php_admin_value[$key] = $val"
        [ $DRY -eq 0 ] && _pool_set_directive "$POOL" "$key" "$val" && reload_service "php${PHP_VERSION}-fpm" ;;
      allow_url_fopen|allow_url_include|display_errors|expose_php)
        log "pool $SITE: php_admin_flag[$key] = $val"
        if [ $DRY -eq 0 ]; then
          local_tmp="$(mktemp)"; grep -vE "^php_admin_flag\[$key\]" "$POOL" > "$local_tmp" || true
          printf 'php_admin_flag[%s] = %s\n' "$key" "$val" >> "$local_tmp"; mv "$local_tmp" "$POOL"
          reload_service "php${PHP_VERSION}-fpm"
        fi ;;
      MemoryMax|CPUQuota|TasksMax)
        log "systemd $SITE: $key=$val (effective only with a per-pool service)"
        if [ $DRY -eq 0 ]; then
          mkdir -p "$(dirname "$LIMITS_DROPIN")"; touch "$LIMITS_DROPIN"
          grep -q '^\[Service\]' "$LIMITS_DROPIN" || echo '[Service]' > "$LIMITS_DROPIN"
          t="$(mktemp)"; grep -vE "^${key}=" "$LIMITS_DROPIN" > "$t" || true
          printf '%s=%s\n' "$key" "$val" >> "$t"; mv "$t" "$LIMITS_DROPIN"
          has_systemd && systemctl daemon-reload 2>/dev/null || true
          reload_service "php${PHP_VERSION}-fpm"
        fi ;;
      pm|pm.max_children|pm.max_requests|pm.start_servers|pm.min_spare_servers|pm.max_spare_servers)
        log "pool $SITE: $key = $val   (process-manager directive)"
        if [ $DRY -eq 0 ]; then
          kre="${key//./\\.}"; t="$(mktemp)"
          grep -vE "^${kre}[[:space:]]*=" "$POOL" > "$t" || true
          printf '%s = %s\n' "$key" "$val" >> "$t"; mv "$t" "$POOL"
          reload_service "php${PHP_VERSION}-fpm"
        fi ;;
      *) die "unknown key '$key'" ;;
    esac
    ;;

  disable|enable)
    func="${1:?function}"
    cur="$(grep -oE '^php_admin_value\[disable_functions\][[:space:]]*=[[:space:]]*.*' "$POOL" | sed 's/.*=[[:space:]]*//' || true)"
    if [ "$ACTION" = disable ]; then
      case ",$cur," in *",$func,"*) new="$cur" ;; *) new="${cur:+$cur,}$func" ;; esac
    else
      new="$(printf '%s' "$cur" | tr ',' '\n' | grep -vx "$func" | paste -sd, -)"
    fi
    log "pool $SITE: disable_functions -> $new"
    [ $DRY -eq 0 ] && _pool_set_directive "$POOL" "disable_functions" "$new" && reload_service "php${PHP_VERSION}-fpm"
    ;;

  tls-on|tls-off)
    val=on; [ "$ACTION" = tls-off ] && val=off
    log "pool $SITE: session.cookie_secure = $val"
    if [ $DRY -eq 0 ]; then
      t="$(mktemp)"; grep -vE '^php_admin_flag\[session\.cookie_secure\]' "$POOL" > "$t" || true
      printf 'php_admin_flag[session.cookie_secure] = %s\n' "$val" >> "$t"; mv "$t" "$POOL"
      reload_service "php${PHP_VERSION}-fpm"
    fi
    ;;

  server-name)
    new="${1:?domains}"                       # space-separated: primary + aliases
    case "$new" in *[/\&\\]*) die "invalid characters in domains: $new" ;; esac
    NGX_AVAIL="/etc/nginx/sites-available/${SITE}"
    log "site $SITE: server_name -> $new"
    if [ $DRY -eq 0 ]; then
      policy_meta_set "$SITE" SERVER_NAME "$new"
      if [ -f "$NGX_AVAIL" ]; then
        t="$(mktemp)"; sed -E "s/^([[:space:]]*)server_name[[:space:]].*/\1server_name ${new};/" "$NGX_AVAIL" > "$t"; mv "$t" "$NGX_AVAIL"
        nginx -t >/dev/null 2>&1 && reload_service nginx || warn "nginx -t failed after server_name change — check $NGX_AVAIL"
      fi
      grep -q 'listen 443' "$NGX_AVAIL" 2>/dev/null && \
        warn "TLS is active: the certificate still covers the OLD names — reissue with setup-tls.sh $SITE ..."
    fi
    ;;

  site-enable)
    NGX_AVAIL="/etc/nginx/sites-available/${SITE}"; NGX_EN="/etc/nginx/sites-enabled/${SITE}"
    [ -f "$NGX_AVAIL" ] || die "no nginx config for $SITE (run harden-vhost.sh first)"
    log "site $SITE: ENABLE (link into nginx sites-enabled)"
    if [ $DRY -eq 0 ]; then ln -sfn "$NGX_AVAIL" "$NGX_EN"; nginx -t >/dev/null 2>&1 && reload_service nginx || warn "nginx -t failed"; fi
    ;;

  site-disable)
    NGX_EN="/etc/nginx/sites-enabled/${SITE}"
    log "site $SITE: DISABLE (remove from nginx sites-enabled; config kept in sites-available)"
    if [ $DRY -eq 0 ]; then rm -f "$NGX_EN"; reload_service nginx; fi
    ;;

  show)
    echo "== $SITE (PHP $PHP_VERSION, uid $(policy_meta_get "$SITE" UID)) =="
    echo "-- open_basedir --";  grep 'open_basedir' "$POOL" 2>/dev/null || true
    echo "-- reach (rw) --";    cat "$(policy_state_dir "$SITE")/reach-rw.paths" 2>/dev/null || true
    echo "-- reach (ro) --";    cat "$(policy_state_dir "$SITE")/reach-ro.paths" 2>/dev/null || true
    echo "-- ext write-denies (dir -> extensions) --"
    if [ -s "$(policy_state_dir "$SITE")/noext.rules" ]; then
      sed 's/\t/  ->  /' "$(policy_state_dir "$SITE")/noext.rules"
    else echo "(none)"; fi
    echo "-- basic auth --"
    if [ "$(policy_meta_get "$SITE" BASIC_AUTH)" = on ]; then
      echo "on — users: $(basicauth_users "$SITE" | tr '\n' ' ')"
    else echo "off"; fi
    echo "-- egress v4 --";     cat "$(policy_state_dir "$SITE")/egress-v4.allow" 2>/dev/null || true
    echo "-- egress v6 --";     cat "$(policy_state_dir "$SITE")/egress-v6.allow" 2>/dev/null || true
    ;;

  *) die "unknown action '$ACTION' (see header for usage)" ;;
esac

[ $DRY -eq 0 ] && log "done." || true
