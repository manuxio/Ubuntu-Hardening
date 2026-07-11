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
action_tls() {
  local s mode email; s="$(pick_site)" || return; [ -n "$s" ] || return
  mode="$(ui_menu "Tipo di certificato per $s:" \
            self "Self-signed (staging/test)" \
            le   "Let's Encrypt (produzione)")" || return
  if [ "$mode" = le ]; then
    email="$(ui_input "Email per Let's Encrypt:" "")" || return
    runscript "$SCRIPTS/setup-tls.sh" "$s" --letsencrypt --email "$email"
  else
    runscript "$SCRIPTS/setup-tls.sh" "$s" --self-signed
  fi
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

# Full "modify an existing site" submenu — every entry drives tune-vhost.sh,
# which keeps pool / AppArmor / systemd / ufw in sync. Loops so several edits to
# the same site are easy; 'Indietro' returns to the main menu.
action_modify() {
  local s op host port proto k v f p
  s="$(pick_site)" || return; [ -n "$s" ] || return
  while true; do
    op="$(ui_menu "Modifica '$s' — scegli un'operazione:" \
      show    "Mostra la policy attuale (sola lettura)" \
      allow   "Egress: APRI una destinazione (host:porta)" \
      deny    "Egress: CHIUDI una destinazione" \
      gwrite  "Directory: concedi SCRITTURA" \
      gread   "Directory: concedi (sola) LETTURA" \
      revoke  "Directory: REVOCA accesso" \
      setk    "Impostazione pool (memoria / limiti / flag)" \
      disable "PHP: DISABILITA una funzione" \
      enable  "PHP: riabilita una funzione" \
      tlson   "Cookie sicuri ON (session.cookie_secure)" \
      tlsoff  "Cookie sicuri OFF (staging HTTP)" \
      back    "<< Indietro")" || return
    case "$op" in
      show)  runscript "$SCRIPTS/tune-vhost.sh" "$s" show ;;
      allow|deny)
        host="$(ui_input "Host/IP di destinazione (o 'any'):" "any")" || continue
        port="$(ui_input "Porta:" "587")" || continue
        proto="$(ui_menu "Protocollo:" tcp "TCP" udp "UDP")" || continue
        tune_apply "$s" "$op" "$host" "$port" "$proto" ;;
      gwrite) p="$(ui_input "Percorso da rendere SCRIVIBILE:" "/srv/${s}-shared")" || continue
              [ -n "$p" ] && tune_apply "$s" grant-write "$p" ;;
      gread)  p="$(ui_input "Percorso da rendere LEGGIBILE:" "/srv/${s}-ro")" || continue
              [ -n "$p" ] && tune_apply "$s" grant-read "$p" ;;
      revoke) p="$(ui_input "Percorso da REVOCARE:" "")" || continue
              [ -n "$p" ] && tune_apply "$s" revoke "$p" ;;
      setk)
        k="$(ui_menu "Quale impostazione cambiare?" \
          memory_limit        "PHP memory_limit (es. 256M)" \
          max_execution_time  "PHP max_execution_time (secondi)" \
          upload_max_filesize "PHP upload_max_filesize (es. 32M)" \
          post_max_size       "PHP post_max_size (es. 32M)" \
          allow_url_fopen     "PHP allow_url_fopen (on/off)" \
          display_errors      "PHP display_errors (on/off)" \
          expose_php          "PHP expose_php (on/off)" \
          pm.max_children     "pool pm.max_children (worker max)" \
          pm.max_requests     "pool pm.max_requests (ricicla worker)" \
          MemoryMax           "cgroup MemoryMax (es. 512M)" \
          CPUQuota            "cgroup CPUQuota (es. 50%)" \
          TasksMax            "cgroup TasksMax (es. 100)")" || continue
        v="$(ui_input "Nuovo valore per $k:" "")" || continue
        [ -n "$v" ] && tune_apply "$s" set "$k" "$v" ;;
      disable) f="$(ui_input "Funzione PHP da DISABILITARE:" "exec")" || continue
               [ -n "$f" ] && tune_apply "$s" disable "$f" ;;
      enable)  f="$(ui_input "Funzione PHP da RIABILITARE:" "")" || continue
               [ -n "$f" ] && tune_apply "$s" enable "$f" ;;
      tlson)   tune_apply "$s" tls-on ;;
      tlsoff)  tune_apply "$s" tls-off ;;
      back)    return ;;
    esac
  done
}
action_site() {  # action_site <script> [extra args after site]
  local script="$1"; shift
  local s; s="$(pick_site)" || return; [ -n "$s" ] || return
  runscript "$script" "$s" "$@"
}

# Create a new vhost with FULL parameter customization: a review menu of every
# harden-vhost parameter (identity, paths, DB, mail, PHP/pool tunables); edit any,
# then CREATE. All values are exported so harden-vhost runs non-interactively.
action_newvhost() {
  local SITE SERVER_NAME DOCROOT RUNTIME_USER WEB_USER PHP_VERSION WRITABLE_DIRS
  local TMP_PATH SESSION_PATH LOG_PATH DB_HOST DB_PORT MAIL_HOST MAIL_PORTS
  local ALLOW_HTTPS COOKIE_SECURE PM_MAX_CHILDREN PM_MAX_REQUESTS MEMORY_LIMIT
  local UPLOAD_MAX_FILESIZE POST_MAX_SIZE MAX_EXECUTION_TIME ASSUME_YES sel newv cur
  SITE="$(ui_input "Nome breve del nuovo sito (pool/hat/utente):" "web_user")" || return
  [ -n "$SITE" ] || return
  # defaults (mirror harden-vhost.sh), derived from SITE
  SERVER_NAME="${SITE}.local"; DOCROOT="/var/www/html/${SITE}/public_html"
  RUNTIME_USER="$SITE"; WEB_USER="www-data"; PHP_VERSION="8.1"
  WRITABLE_DIRS="images media cache administrator/cache"
  TMP_PATH="/var/www/html/${SITE}/tmp"; SESSION_PATH="/var/www/html/${SITE}/sessions"
  LOG_PATH="/var/www/html/${SITE}/logs"
  DB_HOST="127.0.0.1"; DB_PORT="3306"; MAIL_HOST=""; MAIL_PORTS="25,465,587"
  ALLOW_HTTPS="yes"; COOKIE_SECURE="off"
  PM_MAX_CHILDREN="10"; PM_MAX_REQUESTS="500"; MEMORY_LIMIT="256M"
  UPLOAD_MAX_FILESIZE="32M"; POST_MAX_SIZE="32M"; MAX_EXECUTION_TIME="60"
  while true; do
    sel="$(ui_menu "Nuovo sito '$SITE' — rivedi/modifica, poi CREA:" \
      SITE                "Nome sito             = $SITE" \
      SERVER_NAME         "server_name (nginx)   = $SERVER_NAME" \
      DOCROOT             "Docroot               = $DOCROOT" \
      RUNTIME_USER        "Utente runtime        = $RUNTIME_USER" \
      WEB_USER            "Identita codice/FTP   = $WEB_USER" \
      PHP_VERSION         "Versione PHP          = $PHP_VERSION" \
      WRITABLE_DIRS       "Dir scrivibili        = $WRITABLE_DIRS" \
      TMP_PATH            "Temp path             = $TMP_PATH" \
      SESSION_PATH        "Session path          = $SESSION_PATH" \
      LOG_PATH            "Log path              = $LOG_PATH" \
      DB_HOST             "DB host (egress)      = $DB_HOST" \
      DB_PORT             "DB port               = $DB_PORT" \
      MAIL_HOST           "SMTP relay (vuoto=no) = $MAIL_HOST" \
      MAIL_PORTS          "SMTP porte            = $MAIL_PORTS" \
      ALLOW_HTTPS         "Egress 443 (yes/no)   = $ALLOW_HTTPS" \
      COOKIE_SECURE       "cookie_secure (on/off)= $COOKIE_SECURE" \
      PM_MAX_CHILDREN     "pm.max_children       = $PM_MAX_CHILDREN" \
      PM_MAX_REQUESTS     "pm.max_requests       = $PM_MAX_REQUESTS" \
      MEMORY_LIMIT        "memory_limit          = $MEMORY_LIMIT" \
      UPLOAD_MAX_FILESIZE "upload_max_filesize   = $UPLOAD_MAX_FILESIZE" \
      POST_MAX_SIZE       "post_max_size         = $POST_MAX_SIZE" \
      MAX_EXECUTION_TIME  "max_execution_time    = $MAX_EXECUTION_TIME" \
      __CREATE            ">>> CREA IL SITO <<<" \
      __CANCEL            "Annulla")" || return
    case "$sel" in
      __CANCEL) return ;;
      __CREATE) break ;;
      SITE)
        newv="$(ui_input "Nome sito:" "$SITE")" || continue
        if [ -n "$newv" ]; then
          SITE="$newv"; SERVER_NAME="${SITE}.local"; DOCROOT="/var/www/html/${SITE}/public_html"
          RUNTIME_USER="$SITE"; TMP_PATH="/var/www/html/${SITE}/tmp"
          SESSION_PATH="/var/www/html/${SITE}/sessions"; LOG_PATH="/var/www/html/${SITE}/logs"
        fi ;;
      *) cur="${!sel}"; newv="$(ui_input "$sel:" "$cur")" || continue
         printf -v "$sel" '%s' "$newv" ;;
    esac
  done
  ui_yesno "Creare il sito '$SITE'?

  utente=$RUNTIME_USER   PHP=$PHP_VERSION
  docroot=$DOCROOT
  DB=$DB_HOST:$DB_PORT   egress443=$ALLOW_HTTPS" || return
  export SITE SERVER_NAME DOCROOT RUNTIME_USER WEB_USER PHP_VERSION WRITABLE_DIRS \
         TMP_PATH SESSION_PATH LOG_PATH DB_HOST DB_PORT MAIL_HOST MAIL_PORTS \
         ALLOW_HTTPS COOKIE_SECURE PM_MAX_CHILDREN PM_MAX_REQUESTS MEMORY_LIMIT \
         UPLOAD_MAX_FILESIZE POST_MAX_SIZE MAX_EXECUTION_TIME ASSUME_YES=1
  runscript "$SCRIPTS/harden-vhost.sh"
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
    tune     "Apri una destinazione di egress di un sito" \
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
    tune)     action_tune_allow ;;
    denials)  action_site "$SCRIPTS/show-aa-denials.sh" ;;
    e2e)      runscript "$TESTDIR/tier2-e2e.sh" ;;
    quit)     break ;;
  esac
done
clear 2>/dev/null || true
