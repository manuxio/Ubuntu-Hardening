# shellcheck shell=bash
# scripts/lib/common.sh
# -----------------------------------------------------------------------------
# Shared helpers for the hardening scripts. Source it:
#     . "$(dirname "$0")/lib/common.sh"
#
# Design notes:
#   * Every user-facing value comes through prompt(): env-var wins (so the Docker
#     harness can pre-seed a whole run), else an interactive TTY prompt, else the
#     default. Nothing hangs when stdin is not a TTY.
#   * confirm() honours ASSUME_YES=1 for non-interactive automation.
#   * render_template() does literal @@VAR@@ substitution in pure bash, so it is
#     safe for nginx templates that contain $uri / $fastcgi_script_name.
# -----------------------------------------------------------------------------

# Colours only on a TTY.
if [ -t 1 ]; then
  _C_RED=$'\033[31m'; _C_YEL=$'\033[33m'; _C_GRN=$'\033[32m'; _C_DIM=$'\033[2m'; _C_RST=$'\033[0m'
else
  _C_RED=''; _C_YEL=''; _C_GRN=''; _C_DIM=''; _C_RST=''
fi

log()  { printf '%s[*]%s %s\n' "$_C_GRN" "$_C_RST" "$*"; }
info() { printf '%s    %s%s\n' "$_C_DIM" "$*" "$_C_RST"; }
warn() { printf '%s[!]%s %s\n' "$_C_YEL" "$_C_RST" "$*" >&2; }
err()  { printf '%s[x]%s %s\n' "$_C_RED" "$_C_RST" "$*" >&2; }
die()  { err "$*"; exit 1; }

require_root() {
  [ "$(id -u)" -eq 0 ] || die "must run as root (try: sudo $0)"
}

# is_container -> 0 if we look containerised. Used to degrade systemd/ufw/auditd/
# apparmor *activation* (files are still written) so Tier-1 tests pass.
is_container() {
  [ -n "${CONTAINER:-}" ] && return 0
  [ -f /.dockerenv ] && return 0
  grep -qaE '(docker|lxc|containerd|kubepods)' /proc/1/cgroup 2>/dev/null && return 0
  command -v systemd-detect-virt >/dev/null 2>&1 && systemd-detect-virt -c -q 2>/dev/null && return 0
  return 1
}

# has_systemd -> 0 if PID 1 is systemd and we can talk to it.
has_systemd() {
  [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1
}

# have_cmd NAME -> 0 if NAME is on PATH or is an executable in /usr/sbin:/sbin
# (root's tools often live there and may be off a stripped PATH).
have_cmd() {
  command -v "$1" >/dev/null 2>&1 && return 0
  local d; for d in /usr/sbin /sbin /usr/local/sbin; do [ -x "$d/$1" ] && return 0; done
  return 1
}

# tcp_open HOST PORT [TIMEOUT] -> 0 if a TCP connection succeeds (non-fatal probe,
# used for DB/mail reachability heads-ups). No external deps: bash /dev/tcp.
tcp_open() {
  timeout "${3:-2}" bash -c "exec 3<>/dev/tcp/$1/$2" >/dev/null 2>&1
}

# prompt VARNAME "Label" "default"
#   env override wins; then TTY prompt; then default. Result is stored in VARNAME.
prompt() {
  local __var="$1" __label="$2" __default="${3:-}"
  local __cur="${!__var:-}"
  if [ -n "$__cur" ]; then
    return 0                                   # pre-seeded (env / sourced .env)
  fi
  if [ -t 0 ]; then
    local __in
    read -r -p "$__label [${__default}]: " __in
    printf -v "$__var" '%s' "${__in:-$__default}"
  else
    printf -v "$__var" '%s' "$__default"       # non-interactive: take the default
  fi
}

# confirm "message"  -> 0 (yes) / 1 (no)
#   ASSUME_YES=1 -> always yes; non-TTY without ASSUME_YES -> no.
confirm() {
  local __msg="$1"
  if [ "${ASSUME_YES:-0}" = "1" ]; then return 0; fi
  if [ ! -t 0 ]; then return 1; fi
  local __ans
  read -r -p "$__msg [y/N]: " __ans
  case "$__ans" in [yY]|[yY][eE][sS]) return 0 ;; *) return 1 ;; esac
}

# refuse_bad_path PATH "label"  -- guard against operating on system/critical dirs.
refuse_bad_path() {
  local p="${1%/}" label="$2"
  case "$p" in
    ""|/|/bin|/sbin|/lib|/lib64|/usr|/usr/bin|/usr/sbin|/etc|/boot|/dev|/proc|/sys|/run|/var|/home|/root)
      die "refusing to use '$1' as ${label}." ;;
  esac
}

# backup_once FILE -- keep a one-time .orig copy before first modification.
backup_once() {
  local f="$1"
  [ -f "$f" ] || return 0
  [ -f "${f}.orig" ] || cp -a "$f" "${f}.orig"
}

# render_template SRC DST VAR1 VAR2 ...
#   Replaces every literal @@VARi@@ with the value of $VARi (pure bash, no sed).
render_template() {
  local src="$1" dst="$2"; shift 2
  [ -f "$src" ] || die "template not found: $src"
  local content v val
  content="$(cat "$src")"
  for v in "$@"; do
    val="${!v-}"
    content="${content//@@${v}@@/$val}"
  done
  # Warn if any placeholder was left unresolved.
  if printf '%s' "$content" | grep -q '@@[A-Z_][A-Z0-9_]*@@'; then
    warn "unresolved placeholders in $(basename "$src"):"
    printf '%s' "$content" | grep -oE '@@[A-Z_][A-Z0-9_]*@@' | sort -u | sed 's/^/      /' >&2
  fi
  printf '%s\n' "$content" > "$dst"
}

# ensure_line FILE LINE -- append LINE once (idempotent). Creates FILE if absent.
ensure_line() {
  local file="$1" line="$2"
  touch "$file"
  grep -qxF -- "$line" "$file" || printf '%s\n' "$line" >> "$file"
}

# write_region FILE TAG CONTENT
#   Idempotently replaces the block delimited by
#       # >>> hardening:TAG >>>   ...   # <<< hardening:TAG <<<
#   inserting it at EOF if the markers are absent. CONTENT is read from stdin if
#   the 3rd arg is "-", else taken literally.
write_region() {
  local file="$1" tag="$2" content="$3"
  local begin="# >>> hardening:${tag} >>>"
  local end="# <<< hardening:${tag} <<<"
  [ "$content" = "-" ] && content="$(cat)"
  touch "$file"
  local block
  block="$(printf '%s\n%s\n%s\n' "$begin" "$content" "$end")"
  if grep -qF "$begin" "$file"; then
    # Replace existing region using awk. Match markers ignoring leading
    # whitespace, so an indented marker line (e.g. inside an AppArmor profile
    # block) is still recognised.
    local tmp; tmp="$(mktemp)"
    awk -v b="$begin" -v e="$end" -v repl="$block" '
      { t=$0; sub(/^[ \t]+/,"",t) }
      t==b {print repl; skip=1; next}
      t==e {skip=0; next}
      skip {next}
      {print}
    ' "$file" > "$tmp"
    cat "$tmp" > "$file"; rm -f "$tmp"
  else
    printf '\n%s\n' "$block" >> "$file"
  fi
}

# remove_region FILE TAG -- delete a previously written region entirely.
remove_region() {
  local file="$1" tag="$2"
  local begin="# >>> hardening:${tag} >>>"
  local end="# <<< hardening:${tag} <<<"
  [ -f "$file" ] || return 0
  grep -qF "$begin" "$file" || return 0
  local tmp; tmp="$(mktemp)"
  awk -v b="$begin" -v e="$end" '
    { t=$0; sub(/^[ \t]+/,"",t) }
    t==b {skip=1; next}
    t==e {skip=0; next}
    skip {next}
    {print}
  ' "$file" > "$tmp"
  cat "$tmp" > "$file"; rm -f "$tmp"
}

# reload helpers that no-op cleanly in a container -----------------------------

reload_service() {   # reload_service <unit>
  local unit="$1"
  if has_systemd; then
    systemctl reload-or-restart "$unit" 2>/dev/null || systemctl restart "$unit" 2>/dev/null || \
      warn "could not reload $unit via systemd"
  else
    info "(container) skipping systemd reload of $unit — restart it manually if running"
  fi
}

apparmor_reload() {  # apparmor_reload <profile-path>
  local prof="$1"
  if command -v apparmor_parser >/dev/null 2>&1 && [ -w /sys/kernel/security/apparmor 2>/dev/null ]; then
    apparmor_parser -r "$prof" 2>/dev/null && return 0
  fi
  if [ -e /sys/module/apparmor/parameters/enabled ]; then
    apparmor_parser -r "$prof" 2>/dev/null && return 0
  fi
  info "(container) AppArmor not loadable here — profile written to $prof for host/Tier-2"
}
