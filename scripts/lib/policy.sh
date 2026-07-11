# shellcheck shell=bash
# scripts/lib/policy.sh
# -----------------------------------------------------------------------------
# The sync engine. A single logical policy fact ("user X may write dir D",
# "user X may reach host:port") is enforced in several files at once; these
# helpers keep them consistent by REBUILDING each affected file from a small
# per-site state dir, so a re-run is always a clean no-op and nothing drifts.
#
# Per-site state lives under $STATE_ROOT/<SITE>/:
#     meta              KEY=VALUE  (SITE, RUNTIME_USER, UID, PHP_VERSION, DOCROOT)
#     reach-ro.paths    dirs the runtime user may READ   (one absolute path/line)
#     reach-rw.paths    dirs the runtime user may WRITE  (one absolute path/line)
#     egress-v4.allow   iptables rule fragments (one/line, e.g. "-p tcp -d IP --dport 3306")
#     egress-v6.allow   same for IPv6
#
# reach_rebuild()  -> pool open_basedir + AppArmor hat reach-region + systemd RWP
# egress_rebuild() -> the <SITE>_EGRESS chain(s) inside ufw before.rules / before6.rules
#
# Requires lib/common.sh to be sourced first (log/warn/die/write_region/…).
# -----------------------------------------------------------------------------

STATE_ROOT="${STATE_ROOT:-/etc/hardening/sites}"
UFW_BEFORE4="${UFW_BEFORE4:-/etc/ufw/before.rules}"
UFW_BEFORE6="${UFW_BEFORE6:-/etc/ufw/before6.rules}"
APPARMOR_D="${APPARMOR_D:-/etc/apparmor.d/php-fpm.d}"

# --- state / meta ------------------------------------------------------------

policy_state_dir() { printf '%s/%s' "$STATE_ROOT" "$1"; }

policy_meta_set() {                             # SITE KEY VALUE
  local d f; d="$(policy_state_dir "$1")"; mkdir -p "$d"; f="$d/meta"; touch "$f"
  if grep -q "^$2=" "$f"; then
    local tmp; tmp="$(mktemp)"
    grep -v "^$2=" "$f" > "$tmp"; printf '%s=%s\n' "$2" "$3" >> "$tmp"; mv "$tmp" "$f"
  else
    printf '%s=%s\n' "$2" "$3" >> "$f"
  fi
}
policy_meta_get() {                             # SITE KEY
  local f; f="$(policy_state_dir "$1")/meta"
  [ -f "$f" ] && sed -n "s/^$2=//p" "$f" | head -1
}
policy_site_exists() { [ -f "$(policy_state_dir "$1")/meta" ]; }

_norm_slash() { local p="${1%/}"; printf '%s/' "$p"; }   # ensure exactly one trailing /

# --- filesystem reach --------------------------------------------------------

reach_add() {                                   # SITE PATH ro|rw
  local site="$1" path="${2%/}" mode="$3"
  refuse_bad_path "$path" "reach path"
  local d; d="$(policy_state_dir "$site")"; mkdir -p "$d"
  ensure_line "$d/reach-${mode}.paths" "$path"
}
reach_remove() {                                # SITE PATH  (from both ro and rw)
  local site="$1" path="${2%/}" d m tmp
  d="$(policy_state_dir "$site")"
  for m in ro rw; do
    [ -f "$d/reach-${m}.paths" ] || continue
    tmp="$(mktemp)"; grep -vxF -- "$path" "$d/reach-${m}.paths" > "$tmp" || true; mv "$tmp" "$d/reach-${m}.paths"
  done
}

# Replace/insert a single `php_admin_value[KEY] = VALUE` line in a pool file.
_pool_set_directive() {                         # FILE KEY VALUE
  local file="$1" key="$2" val="$3" tmp
  [ -f "$file" ] || { warn "pool file missing: $file"; return 1; }
  tmp="$(mktemp)"
  grep -vE "^php_admin_value\[$key\][[:space:]]*=" "$file" > "$tmp" || true
  printf 'php_admin_value[%s] = %s\n' "$key" "$val" >> "$tmp"
  mv "$tmp" "$file"
}

reach_rebuild() {                               # SITE
  local site="$1" d php pool hat dropin_dir
  d="$(policy_state_dir "$site")"
  php="$(policy_meta_get "$site" PHP_VERSION)"
  pool="/etc/php/${php}/fpm/pool.d/${site}.conf"
  hat="${APPARMOR_D}/${site}"
  dropin_dir="/etc/systemd/system/php${php}-fpm.service.d"

  local ro rw
  ro="$( [ -f "$d/reach-ro.paths" ] && cat "$d/reach-ro.paths" || true )"
  rw="$( [ -f "$d/reach-rw.paths" ] && cat "$d/reach-rw.paths" || true )"

  # 1) open_basedir = union(ro, rw), each with a trailing slash, ':'-joined.
  local ob p seen=""
  for p in $ro $rw; do
    p="$(_norm_slash "$p")"
    case ":$seen:" in *":$p:"*) continue ;; esac
    seen="${seen:+$seen:}$p"
  done
  ob="$seen"
  [ -n "$ob" ] && _pool_set_directive "$pool" "open_basedir" "$ob"

  # 2) AppArmor hat reach-region: rw -> rw/rwk, ro -> r/r.
  if [ -f "$hat" ]; then
    local block=""
    for p in $rw; do block+="  ${p}/ rw,"$'\n'"  ${p}/** rwk,"$'\n'; done
    for p in $ro; do block+="  ${p}/ r,"$'\n'"  ${p}/** r,"$'\n'; done
    [ -z "$block" ] && block="  # (no tunable reach paths)"
    write_region "$hat" "reach" "${block%$'\n'}"
    # child hats load via the master (include <php-fpm.d>), so reload the master.
    apparmor_reload "/etc/apparmor.d/php-fpm"
  fi

  # 3) systemd ReadWritePaths = rw paths (ProtectSystem=strict makes the rest ro).
  if [ -n "$rw" ]; then
    mkdir -p "$dropin_dir"
    { printf '[Service]\nReadWritePaths=';
      for p in $rw; do printf '%s ' "$p"; done; printf '\n'; } > "$dropin_dir/${site}-reach.conf"
    has_systemd && systemctl daemon-reload 2>/dev/null || true
  fi

  reload_service "php${php}-fpm" 2>/dev/null || true
}

# --- egress ------------------------------------------------------------------

egress_allow() {                                # SITE FRAGMENT [4|6]
  local site="$1" frag="$2" ipv="${3:-4}" d
  d="$(policy_state_dir "$site")"; mkdir -p "$d"
  ensure_line "$d/egress-v${ipv}.allow" "$frag"
}
egress_deny() {                                 # SITE FRAGMENT [4|6]
  local site="$1" frag="$2" ipv="${3:-4}" f tmp
  f="$(policy_state_dir "$site")/egress-v${ipv}.allow"
  [ -f "$f" ] || return 0
  tmp="$(mktemp)"; grep -vxF -- "$frag" "$f" > "$tmp" || true; mv "$tmp" "$f"
}

_egress_body() {                                # SITE IPV(4|6)
  local site="$1" ipv="$2" chain="${1}_EGRESS" rej="icmp-port-unreachable"
  [ "$ipv" = 6 ] && rej="icmp6-port-unreachable"
  printf -- '-A %s -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT\n' "$chain"
  printf -- '-A %s -o lo -j ACCEPT\n' "$chain"
  printf -- '-A %s -p udp --dport 53 -j ACCEPT\n' "$chain"
  printf -- '-A %s -p tcp --dport 53 -j ACCEPT\n' "$chain"
  local f="$(policy_state_dir "$site")/egress-v${ipv}.allow" frag
  if [ -f "$f" ]; then
    while IFS= read -r frag; do
      [ -n "$frag" ] || continue
      printf -- '-A %s %s -j ACCEPT\n' "$chain" "$frag"
    done < "$f"
  fi
  printf -- '-A %s -m limit --limit 6/min -j LOG --log-prefix "%s-DROP " --log-level 6\n' "$chain" "$chain"
  printf -- '-A %s -j REJECT --reject-with %s\n' "$chain" "$rej"
}

# Insert an empty region right before the first anchor line, if absent.
_ensure_region_before_anchor() {                # FILE TAG ANCHOR_REGEX
  local file="$1" tag="$2" anchor="$3"
  local begin="# >>> hardening:${tag} >>>" end="# <<< hardening:${tag} <<<"
  [ -f "$file" ] || return 1
  grep -qF "$begin" "$file" && return 0
  local tmp; tmp="$(mktemp)"
  awk -v b="$begin" -v e="$end" -v anc="$anchor" '
    !done && $0 ~ anc { print b; print e; done=1 } { print }
  ' "$file" > "$tmp"
  cat "$tmp" > "$file"; rm -f "$tmp"
}

# Rebuild the whole egress region in a before[6].rules file from ALL sites.
_egress_rebuild_file() {                         # FILE IPV(4|6)
  local file="$1" ipv="$2"
  [ -f "$file" ] || { info "(no $file — ufw not present) skipping egress v$ipv"; return 0; }
  _ensure_region_before_anchor "$file" "egress" '^COMMIT' || return 0

  # ufw names its output chain differently per family: v4 = ufw-before-output,
  # v6 = ufw6-before-output. Hooking the wrong name makes the whole reload fail
  # (and ufw reload is disable-then-enable, so a bad rule disables the firewall).
  local outchain="ufw-before-output"
  [ "$ipv" = 6 ] && outchain="ufw6-before-output"

  local decls="" hooks="" bodies="" dir site uid
  for dir in "$STATE_ROOT"/*/; do
    [ -d "$dir" ] || continue
    site="$(basename "$dir")"
    uid="$(policy_meta_get "$site" UID)"
    [ -n "$uid" ] || continue
    decls+=":${site}_EGRESS - [0:0]"$'\n'
    hooks+="-A ${outchain} -m owner --uid-owner ${uid} -j ${site}_EGRESS"$'\n'
    bodies+="$(_egress_body "$site" "$ipv")"$'\n'
  done

  local region="# per-site egress chains (managed — do not edit by hand)"$'\n'
  region+="${decls}${hooks}${bodies}"
  write_region "$file" "egress" "${region%$'\n'}"
}

egress_rebuild() {                               # (all sites, v4 + v6)
  _egress_rebuild_file "$UFW_BEFORE4" 4
  _egress_rebuild_file "$UFW_BEFORE6" 6
  ufw_reload
}

ufw_reload() {
  if command -v ufw >/dev/null 2>&1 && has_systemd && ufw status 2>/dev/null | grep -qi active; then
    ufw reload >/dev/null 2>&1 && log "ufw reloaded" || warn "ufw reload failed — check: iptables-restore --test < $UFW_BEFORE4"
  else
    info "(container / ufw inactive) egress rules written to before[6].rules; activate with 'ufw enable && ufw reload' on the host"
  fi
}
