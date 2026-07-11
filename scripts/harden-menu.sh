#!/usr/bin/env bash
# =============================================================================
# harden-menu.sh — a small, dependency-light TUI that drives the hardening
# scripts. Uses whiptail (present on every Ubuntu) for menus/prompts, and falls
# back to a plain numbered menu if whiptail is missing. It only *orchestrates*:
# every action just runs one of the existing scripts in this repo, live, in the
# terminal — nothing is reimplemented here.
#
#   sudo bash scripts/harden-menu.sh            # interactive
#   bash scripts/harden-menu.sh --check         # non-interactive self-test
#
# Force the plain backend with HARDEN_UI=text (useful for testing / no-whiptail).
# =============================================================================
set -uo pipefail

SELF="$(cd "$(dirname "$0")" && pwd)"
REPO="$(dirname "$SELF")"
SCRIPTS="$SELF"
TESTDIR="$REPO/test"
TITLE="Ubuntu Hardening"

have() { command -v "$1" >/dev/null 2>&1; }
UI=text; have whiptail && UI=whiptail
UI="${HARDEN_UI:-$UI}"

# The scripts need root. Re-exec the whole menu under sudo once, so each action
# runs as root directly (no repeated password prompts). --check needs no root.
if [ "${1:-}" != "--check" ] && [ "$(id -u)" -ne 0 ]; then
  if have sudo; then exec sudo -E bash "$0" "$@"; else echo "run as root (sudo)"; exit 1; fi
fi

# --- tiny UI abstraction: whiptail, else plain text --------------------------
ui_menu() {  # ui_menu "prompt" tag1 "label1" tag2 "label2" ...  -> echoes chosen tag
  local prompt="$1"; shift
  if [ "$UI" = whiptail ]; then
    whiptail --title "$TITLE" --notags --menu "$prompt" 22 76 13 "$@" 3>&1 1>&2 2>&3
    return $?
  fi
  { echo; echo "== $TITLE =="; echo "$prompt"; } >&2
  local -a tags=(); local i=1
  while [ $# -ge 2 ]; do tags+=("$1"); printf '  %2d) %s\n' "$i" "$2" >&2; shift 2; i=$((i+1)); done
  printf 'Scelta [1-%d] (vuoto = annulla): ' "${#tags[@]}" >&2
  local n; read -r n || return 1
  [[ "$n" =~ ^[0-9]+$ ]] && [ "$n" -ge 1 ] && [ "$n" -le "${#tags[@]}" ] || return 1
  echo "${tags[$((n-1))]}"
}
ui_input() {  # ui_input "prompt" "default"  -> echoes value
  local prompt="$1" def="${2:-}"
  if [ "$UI" = whiptail ]; then
    whiptail --title "$TITLE" --inputbox "$prompt" 10 70 "$def" 3>&1 1>&2 2>&3; return $?
  fi
  printf '%s [%s]: ' "$prompt" "$def" >&2; local v; read -r v || return 1; echo "${v:-$def}"
}
ui_msg() {  # ui_msg "text"
  if [ "$UI" = whiptail ]; then whiptail --title "$TITLE" --msgbox "$1" 12 70; else echo "-- $1" >&2; fi
}
ui_yesno() {  # ui_yesno "prompt" -> 0 yes / 1 no
  if [ "$UI" = whiptail ]; then whiptail --title "$TITLE" --yesno "$1" 14 72; return $?; fi
  printf '%s [s/N]: ' "$1" >&2; local a; read -r a || return 1
  case "$a" in s|S|y|Y) return 0 ;; *) return 1 ;; esac
}

# --- discover configured sites from the php-fpm pools ------------------------
list_sites() {
  local f s
  for f in /etc/php/*/fpm/pool.d/*.conf; do
    [ -e "$f" ] || continue
    s="$(basename "$f" .conf)"
    case "$s" in www*) continue ;; esac
    echo "$s"
  done
}
pick_site() {  # echoes chosen site, or returns 1
  local -a pairs=(); local s
  while read -r s; do [ -n "$s" ] && pairs+=("$s" "$s"); done < <(list_sites)
  if [ ${#pairs[@]} -eq 0 ]; then
    ui_msg "Nessun sito configurato. Usa prima 'Nuovo virtual host'."; return 1
  fi
  ui_menu "Scegli il sito:" "${pairs[@]}"
}

# --- run a script live in the terminal, then pause ---------------------------
runscript() {  # runscript <path> [args...]
  clear 2>/dev/null || true
  echo "==> bash $* "; echo "-------------------------------------------------------------"
  bash "$@"; local rc=$?
  echo "-------------------------------------------------------------"
  echo "[exit $rc] — premi Invio per tornare al menu"; read -r _ || true
}

# --- composite actions that need parameters ----------------------------------
# Enable TLS on a site in a chosen HTTP/HTTPS mode, then a chosen cert type.
run_tls_for() {  # run_tls_for <site> <http+https|https>
  local s="$1" mode="$2" ct email both=""
  [ "$mode" = "http+https" ] && both="--both"
  ct="$(ui_menu "Certificato per $s (modalita: $mode):" \
        self "Self-signed (staging / test)" \
        le   "Let's Encrypt (produzione, richiede DNS pubblico)")" || return 1
  if [ "$ct" = le ]; then
    email="$(ui_input "Email per Let's Encrypt:" "")" || return 1
    runscript "$SCRIPTS/setup-tls.sh" "$s" --letsencrypt --email "$email" $both
  else
    runscript "$SCRIPTS/setup-tls.sh" "$s" --self-signed $both
  fi
}
action_tls() {
  local s mode; s="$(pick_site)" || return; [ -n "$s" ] || return
  mode="$(ui_menu "Come servire '$s'?" \
    "http+https" "HTTP e HTTPS entrambi attivi (nessun redirect)" \
    "https"      "Solo HTTPS (HTTP -> redirect 301)")" || return
  run_tls_for "$s" "$mode"
}
# Read the CURRENT value of a per-site setting (pool directive or systemd cap),
# so the modify dialogs can show and pre-fill it.
pool_get() {  # pool_get <site> <key>
  local s="$1" k="$2" pool ver drop val
  pool="$(ls /etc/php/*/fpm/pool.d/${s}.conf 2>/dev/null | head -1)"
  [ -n "$pool" ] || return 0
  ver="$(printf '%s' "$pool" | sed -nE 's#/etc/php/([^/]+)/.*#\1#p')"
  drop="/etc/systemd/system/php${ver}-fpm.service.d/${s}-limits.conf"
  case "$k" in
    MemoryMax|CPUQuota|TasksMax)
      val="$(grep -shE "^${k}=" "$drop" 2>/dev/null | tail -1 | cut -d= -f2-)" ;;
    pm|pm.*)
      val="$(grep -shE "^${k//./\\.}[[:space:]]*=" "$pool" 2>/dev/null | tail -1 | sed 's/^[^=]*=[[:space:]]*//')" ;;
    *)
      val="$(grep -shE "^php_admin_(value|flag)\[${k}\][[:space:]]*=" "$pool" 2>/dev/null | tail -1 | sed 's/^[^=]*=[[:space:]]*//')" ;;
  esac
  val="${val%%;*}"                                        # drop trailing inline comment
  printf '%s' "$val" | sed 's/[[:space:]]*$//'            # trim trailing whitespace
}

# Apply a tune-vhost change, but offer a dry-run preview first (fail-safe).
tune_apply() {  # tune_apply <site> <tune-vhost args...>
  local site="$1"; shift
  if ui_yesno "Applicare questa modifica?

  tune-vhost.sh $site $*

(No = solo anteprima, dry-run)"; then
    runscript "$SCRIPTS/tune-vhost.sh" "$site" "$@"
  else
    runscript "$SCRIPTS/tune-vhost.sh" "$site" "$@" --dry-run
  fi
}

# --- current-state summaries shown at the top of each modify group ----------
egress_summary() {  # egress_summary <site> -> allowed destinations + note
  local s="$1" out
  out="$(iptables -S "${s}_EGRESS" 2>/dev/null | grep -- '-j ACCEPT' \
    | sed -E "s/^-A ${s}_EGRESS //; s/ -j ACCEPT$//; \
              s/-m conntrack --ctstate [A-Z,]+/risposte a connessioni gia' aperte/; \
              s/-m (tcp|udp) //g; s#/32##g" | sed 's/^/  /')"
  if [ -n "$out" ]; then
    printf 'CONSENTITE (uscita per uid del sito):\n%s\n  -- tutto il resto: BLOCCATO (REJECT) --' "$out"
  else
    printf 'Regole egress non attive (ufw off? esegui harden-os). Da policy:\n%s' \
      "$(sed 's/^/  /' "/etc/hardening/sites/$s/egress-v4.allow" 2>/dev/null || echo '  (nessuna)')"
  fi
}
dir_summary() {  # dir_summary <site> -> read/write reach paths with permissions
  local s="$1" p D                      # NB: D on its own line — $s isn't set yet
  D="/etc/hardening/sites/$s"           # inside a single `local` (bash expands first)
  echo "SCRIVIBILI dall'utente runtime:"
  if [ -s "$D/reach-rw.paths" ]; then
    while IFS= read -r p; do [ -n "$p" ] && printf '  %s  %s\n' \
      "$(stat -c '%A %U:%G' "$p" 2>/dev/null || echo '(assente)')" "$p"; done < "$D/reach-rw.paths"
  else echo "  (nessuna)"; fi
  echo "SOLA LETTURA:"
  if [ -s "$D/reach-ro.paths" ]; then
    while IFS= read -r p; do [ -n "$p" ] && printf '  %s  %s\n' \
      "$(stat -c '%A %U:%G' "$p" 2>/dev/null || echo '(assente)')" "$p"; done < "$D/reach-ro.paths"
  else echo "  (nessuna)"; fi
}

# --- modify groups: each loops (you stay in it) and shows current state -----
mod_egress() {  # mod_egress <site>
  local s="$1" op host port proto
  while true; do
    op="$(ui_menu "Egress di '$s':

$(egress_summary "$s")" \
      allow "APRI una destinazione (host:porta)" \
      deny  "CHIUDI una destinazione" \
      back  "<< Indietro")" || return
    case "$op" in
      allow|deny)
        host="$(ui_input "Host/IP di destinazione (o 'any'):" "any")" || continue
        port="$(ui_input "Porta:" "587")" || continue
        proto="$(ui_menu "Protocollo:" tcp "TCP" udp "UDP")" || continue
        tune_apply "$s" "$op" "$host" "$port" "$proto" ;;
      back) return ;;
    esac
  done
}
mod_dir() {  # mod_dir <site>
  local s="$1" op p
  while true; do
    op="$(ui_menu "Directory di '$s':

$(dir_summary "$s")" \
      gwrite "Concedi SCRITTURA su un path" \
      gread  "Concedi (sola) LETTURA su un path" \
      revoke "REVOCA un path" \
      back   "<< Indietro")" || return
    case "$op" in
      gwrite) p="$(ui_input "Path da rendere SCRIVIBILE:" "/srv/${s}-shared")" || continue
              [ -n "$p" ] && tune_apply "$s" grant-write "$p" ;;
      gread)  p="$(ui_input "Path da rendere LEGGIBILE:" "/srv/${s}-ro")" || continue
              [ -n "$p" ] && tune_apply "$s" grant-read "$p" ;;
      revoke) p="$(ui_input "Path da REVOCARE:" "")" || continue
              [ -n "$p" ] && tune_apply "$s" revoke "$p" ;;
      back)   return ;;
    esac
  done
}
mod_php() {  # mod_php <site> — each entry shows its CURRENT value; stays open
  local s="$1" sel v f cur fn; local -a rearr rmenu
  while true; do
    sel="$(ui_menu "PHP / Pool di '$s' — scegli cosa cambiare:" \
      memory_limit        "memory_limit         = $(pool_get "$s" memory_limit)" \
      max_execution_time  "max_execution_time   = $(pool_get "$s" max_execution_time)" \
      upload_max_filesize "upload_max_filesize  = $(pool_get "$s" upload_max_filesize)" \
      post_max_size       "post_max_size        = $(pool_get "$s" post_max_size)" \
      pm.max_children     "pm.max_children      = $(pool_get "$s" pm.max_children)" \
      pm.max_requests     "pm.max_requests      = $(pool_get "$s" pm.max_requests)" \
      allow_url_fopen     "allow_url_fopen      = $(pool_get "$s" allow_url_fopen)" \
      display_errors      "display_errors       = $(pool_get "$s" display_errors)" \
      expose_php          "expose_php           = $(pool_get "$s" expose_php)" \
      MemoryMax           "MemoryMax (cgroup)   = $(pool_get "$s" MemoryMax)" \
      CPUQuota            "CPUQuota (cgroup)    = $(pool_get "$s" CPUQuota)" \
      TasksMax            "TasksMax (cgroup)    = $(pool_get "$s" TasksMax)" \
      __disable "Disabilita una funzione PHP ..." \
      __enable  "Riabilita una funzione PHP ..." \
      __back    "<< Indietro")" || return
    case "$sel" in
      __back) return ;;
      __disable) cur="$(pool_get "$s" disable_functions)"
                 f="$(ui_input "UNA funzione da disabilitare: verra' AGGIUNTA all'elenco (non riscrivere le altre).
Gia' disabilitate: ${cur:-nessuna}" "")" || continue
                 [ -n "$f" ] && tune_apply "$s" disable "$f" ;;
      __enable)  cur="$(pool_get "$s" disable_functions)"
                 if [ -z "$cur" ]; then ui_msg "Nessuna funzione disabilitata da riabilitare."; continue; fi
                 IFS=',' read -ra rearr <<< "$cur"; rmenu=()
                 for fn in "${rearr[@]}"; do [ -n "$fn" ] && rmenu+=("$fn" "riabilita  $fn"); done
                 f="$(ui_menu "Quale RIABILITARE? (le altre restano disabilitate)" "${rmenu[@]}")" || continue
                 [ -n "$f" ] && tune_apply "$s" enable "$f" ;;
      *) cur="$(pool_get "$s" "$sel")"
         v="$(ui_input "Valore per $sel  (attuale: ${cur:-non impostato}):" "$cur")" || continue
         [ -n "$v" ] && tune_apply "$s" set "$sel" "$v" ;;
    esac
  done
}
mod_tls() {  # mod_tls <site>
  local s="$1" op cur
  while true; do
    cur="$(pool_get "$s" session.cookie_secure)"
    op="$(ui_menu "Cookie/TLS di '$s'  (session.cookie_secure attuale: ${cur:-off}):" \
      on   "cookie_secure ON  (i cookie viaggiano solo su HTTPS)" \
      off  "cookie_secure OFF (staging HTTP)" \
      back "<< Indietro")" || return
    case "$op" in
      on)   tune_apply "$s" tls-on ;;
      off)  tune_apply "$s" tls-off ;;
      back) return ;;
    esac
  done
}

# "Modify a site" — a grouped menu (Egress / Directory / PHP / TLS). Each group
# is a submenu that STAYS OPEN after a change and shows the current state, so you
# can make several edits without dropping back to the top. Drives tune-vhost.sh.
action_modify() {
  local s g
  s="$(pick_site)" || return; [ -n "$s" ] || return
  while true; do
    g="$(ui_menu "Modifica '$s' — scegli un gruppo:" \
      egress "Egress      (destinazioni consentite / bloccate)" \
      dir    "Directory   (permessi lettura / scrittura)" \
      php    "PHP / Pool  (memoria, limiti, workers, funzioni)" \
      tls    "TLS / Cookie (session.cookie_secure)" \
      show   "Mostra tutta la policy del sito" \
      back   "<< Indietro")" || return
    case "$g" in
      egress) mod_egress "$s" ;;
      dir)    mod_dir "$s" ;;
      php)    mod_php "$s" ;;
      tls)    mod_tls "$s" ;;
      show)   runscript "$SCRIPTS/tune-vhost.sh" "$s" show ;;
      back)   return ;;
    esac
  done
}
action_site() {  # action_site <script> [extra args after site]
  local script="$1"; shift
  local s; s="$(pick_site)" || return; [ -n "$s" ] || return
  runscript "$script" "$s" "$@"
}

# New-site creation as a GROUPED form (Nginx / File System / PHP / Network).
# _edit_field and _edit_group use bash dynamic scope: called from action_newvhost
# they read and modify its local parameter variables by name.
_edit_field() {  # _edit_field <VARNAME>
  local v="$1" newv
  case "$v" in
    SITE)
      newv="$(ui_input "Nome breve del sito:" "$SITE")" || return
      if [ -n "$newv" ]; then
        SITE="$newv"; SERVER_NAME="${SITE}.local"; DOCROOT="/var/www/html/${SITE}/public_html"
        RUNTIME_USER="$SITE"; TMP_PATH="/var/www/html/${SITE}/tmp"
        SESSION_PATH="/var/www/html/${SITE}/sessions"; LOG_PATH="/var/www/html/${SITE}/logs"
      fi ;;
    SERVER_NAME)
      newv="$(ui_input "Domini separati da spazio: il 1o e' il principale, gli altri gli alias (es: www.xxx.com xxx.com). Vanno in nginx server_name e nei certificati TLS." "$SERVER_NAME")" || return
      [ -n "$newv" ] && SERVER_NAME="$newv" ;;
    TLS_MODE)
      newv="$(ui_menu "Come servire il sito?" \
        http        "Solo HTTP (nessun TLS)" \
        "http+https" "HTTP e HTTPS entrambi (nessun redirect)" \
        https       "Solo HTTPS (HTTP -> redirect 301)")" || return
      [ -n "$newv" ] && TLS_MODE="$newv" ;;
    *) newv="$(ui_input "$v:" "${!v}")" || return; printf -v "$v" '%s' "$newv" ;;
  esac
}
_edit_group() {  # _edit_group "Title" VAR "Label" VAR "Label" ...
  local title="$1"; shift
  local -a spec=("$@")
  local -a items; local i var lab sel
  while true; do
    items=()
    for ((i=0; i<${#spec[@]}; i+=2)); do
      var="${spec[i]}"; lab="${spec[i+1]}"
      items+=("$var" "$(printf '%-20s = %s' "$lab" "${!var}")")
    done
    items+=("__BACK" "<< Indietro")
    sel="$(ui_menu "$title — modifica un campo:" "${items[@]}")" || return
    [ "$sel" = "__BACK" ] && return
    _edit_field "$sel"
  done
}
action_newvhost() {
  local SITE SERVER_NAME DOCROOT RUNTIME_USER WEB_USER PHP_VERSION WRITABLE_DIRS
  local TMP_PATH SESSION_PATH LOG_PATH DB_HOST DB_PORT MAIL_HOST MAIL_PORTS
  local ALLOW_HTTPS COOKIE_SECURE PM_MAX_CHILDREN PM_MAX_REQUESTS MEMORY_LIMIT
  local UPLOAD_MAX_FILESIZE POST_MAX_SIZE MAX_EXECUTION_TIME TLS_MODE ASSUME_YES sel
  SITE="$(ui_input "Nome breve del nuovo sito (pool/hat/utente):" "web_user")" || return
  [ -n "$SITE" ] || return
  # defaults (mirror harden-vhost.sh), derived from SITE
  SERVER_NAME="${SITE}.local"; DOCROOT="/var/www/html/${SITE}/public_html"
  RUNTIME_USER="$SITE"; WEB_USER="www-data"; PHP_VERSION="8.1"
  WRITABLE_DIRS="images media cache administrator/cache"
  TMP_PATH="/var/www/html/${SITE}/tmp"; SESSION_PATH="/var/www/html/${SITE}/sessions"
  LOG_PATH="/var/www/html/${SITE}/logs"
  DB_HOST="127.0.0.1"; DB_PORT="3306"; MAIL_HOST=""; MAIL_PORTS="25,465,587"
  ALLOW_HTTPS="yes"; COOKIE_SECURE="off"; TLS_MODE="http"
  PM_MAX_CHILDREN="10"; PM_MAX_REQUESTS="500"; MEMORY_LIMIT="256M"
  UPLOAD_MAX_FILESIZE="32M"; POST_MAX_SIZE="32M"; MAX_EXECUTION_TIME="60"
  while true; do
    sel="$(ui_menu "Nuovo sito '$SITE' — configura per gruppi, poi CREA:" \
      g_nginx  "Nginx / dominio     (server_name, HTTP/HTTPS)" \
      g_fs     "File System         (docroot, utenti, dir, path)" \
      g_php    "PHP / Pool          (versione, memoria, limiti, workers)" \
      g_net    "Rete / DB / Mail    (DB, SMTP, egress, cookie)" \
      __CREATE ">>> CREA IL SITO (modalita: $TLS_MODE) <<<" \
      __CANCEL "Annulla")" || return
    case "$sel" in
      __CANCEL) return ;;
      __CREATE) break ;;
      g_nginx) _edit_group "Nginx / dominio" \
                 SITE "Nome sito" SERVER_NAME "Domini" TLS_MODE "Modalita HTTP/HTTPS" ;;
      g_fs)    _edit_group "File System" \
                 DOCROOT "Docroot" RUNTIME_USER "Utente runtime" WEB_USER "Identita codice" \
                 WRITABLE_DIRS "Dir scrivibili" TMP_PATH "Temp path" \
                 SESSION_PATH "Session path" LOG_PATH "Log path" ;;
      g_php)   _edit_group "PHP / Pool" \
                 PHP_VERSION "Versione PHP" MEMORY_LIMIT "memory_limit" \
                 UPLOAD_MAX_FILESIZE "upload_max" POST_MAX_SIZE "post_max_size" \
                 MAX_EXECUTION_TIME "max_exec_time" PM_MAX_CHILDREN "pm.max_children" \
                 PM_MAX_REQUESTS "pm.max_requests" ;;
      g_net)   _edit_group "Rete / DB / Mail" \
                 DB_HOST "DB host" DB_PORT "DB port" MAIL_HOST "SMTP relay" \
                 MAIL_PORTS "SMTP porte" ALLOW_HTTPS "Egress 443" COOKIE_SECURE "cookie_secure" ;;
    esac
  done
  ui_yesno "Creare il sito '$SITE'?

  utente=$RUNTIME_USER   PHP=$PHP_VERSION   modalita=$TLS_MODE
  domini=$SERVER_NAME
  docroot=$DOCROOT
  DB=$DB_HOST:$DB_PORT   egress443=$ALLOW_HTTPS" || return
  export SITE SERVER_NAME DOCROOT RUNTIME_USER WEB_USER PHP_VERSION WRITABLE_DIRS \
         TMP_PATH SESSION_PATH LOG_PATH DB_HOST DB_PORT MAIL_HOST MAIL_PORTS \
         ALLOW_HTTPS COOKIE_SECURE PM_MAX_CHILDREN PM_MAX_REQUESTS MEMORY_LIMIT \
         UPLOAD_MAX_FILESIZE POST_MAX_SIZE MAX_EXECUTION_TIME ASSUME_YES=1
  runscript "$SCRIPTS/harden-vhost.sh"
  # apply the chosen HTTP/HTTPS mode (http => nothing else to do)
  if [ "$TLS_MODE" != http ]; then
    if [ -f "/etc/php/${PHP_VERSION}/fpm/pool.d/${SITE}.conf" ]; then
      run_tls_for "$SITE" "$TLS_MODE"
    else
      ui_msg "Creazione non riuscita: salto la configurazione TLS."
    fi
  fi
}

# --- self-test (non-interactive) ---------------------------------------------
if [ "${1:-}" = "--check" ]; then
  echo "harden-menu self-check"
  echo "  UI backend : $UI"
  echo "  privilege  : $(id -un)$([ "$(id -u)" -eq 0 ] && echo ' (root)')"
  echo "  repo root  : $REPO"
  miss=0
  for s in harden-os.sh harden-vhost.sh enforce-vhost.sh setup-tls.sh tune-vhost.sh \
           show-aa-denials.sh add-aa-permit.sh audit-os.sh scan-cve.sh audit-cis.sh; do
    if [ -f "$SCRIPTS/$s" ]; then echo "  [ok]   scripts/$s"; else echo "  [MISS] scripts/$s"; miss=$((miss+1)); fi
  done
  if [ -f "$TESTDIR/tier2-e2e.sh" ]; then echo "  [ok]   test/tier2-e2e.sh"; else echo "  [MISS] test/tier2-e2e.sh"; miss=$((miss+1)); fi
  echo "  sites      : $(list_sites | tr '\n' ' ')"
  echo "  result     : $miss missing"
  exit $([ "$miss" -eq 0 ] && echo 0 || echo 1)
fi

# --- main loop ---------------------------------------------------------------
while true; do
  choice="$(ui_menu "Server: $(hostname) · scegli un'azione:" \
    baseline "Audit: baseline sicurezza (Lynis)" \
    hardenos "Hardening del sistema operativo (una volta)" \
    verify   "Audit: verifica + delta (Lynis)" \
    cve      "Scan CVE dei pacchetti (Trivy)" \
    cis      "Audit conformità CIS (OpenSCAP)" \
    newvhost "Nuovo sito (personalizza TUTTI i parametri)" \
    enforce  "Enforce AppArmor di un sito (soak->enforce)" \
    tls      "HTTPS / TLS di un sito" \
    modify   "Modifica un sito (egress, dir, PHP/pool, cookie, ...)" \
    denials  "Mostra i denial AppArmor di un sito" \
    e2e      "Esegui il test end-to-end (Tier-2)" \
    quit     "Esci")" || break

  case "$choice" in
    baseline) runscript "$SCRIPTS/audit-os.sh" --baseline ;;
    hardenos) runscript "$SCRIPTS/harden-os.sh" ;;
    verify)   runscript "$SCRIPTS/audit-os.sh" --verify ;;
    cve)      runscript "$SCRIPTS/scan-cve.sh" ;;
    cis)      runscript "$SCRIPTS/audit-cis.sh" ;;
    newvhost) action_newvhost ;;
    enforce)  action_site "$SCRIPTS/enforce-vhost.sh" ;;
    tls)      action_tls ;;
    modify)   action_modify ;;
    denials)  action_site "$SCRIPTS/show-aa-denials.sh" ;;
    e2e)      runscript "$TESTDIR/tier2-e2e.sh" ;;
    quit)     break ;;
  esac
done
clear 2>/dev/null || true
