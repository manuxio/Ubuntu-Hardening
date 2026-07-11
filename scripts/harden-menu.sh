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
    # adaptive box height: fit the (possibly multi-line, state-showing) prompt +
    # the items, but never exceed the terminal — otherwise whiptail truncates the
    # prompt and the "current state" summary vanishes.
    local plines items h lh maxh
    plines=$(printf '%s\n' "$prompt" | wc -l)
    items=$(( $# / 2 ))
    maxh=$(tput lines 2>/dev/null || echo 24)
    h=$(( plines + items + 8 ))
    [ "$h" -gt $(( maxh - 1 )) ] && h=$(( maxh - 1 ))
    [ "$h" -lt 12 ] && h=12
    lh=$(( h - plines - 6 )); [ "$lh" -lt 3 ] && lh=3; [ "$lh" -gt "$items" ] && lh=$items
    whiptail --title "$TITLE" --notags --menu "$prompt" "$h" 80 "$lh" "$@" 3>&1 1>&2 2>&3
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
ui_msg() {  # ui_msg "text" — fd swap so the box shows on the terminal even when
            # the caller runs inside $(...) (e.g. pick_site), not into the capture
  if [ "$UI" = whiptail ]; then whiptail --title "$TITLE" --msgbox "$1" 12 70 3>&1 1>&2 2>&3; else echo "-- $1" >&2; fi
}
ui_yesno() {  # ui_yesno "prompt" -> 0 yes / 1 no
  if [ "$UI" = whiptail ]; then whiptail --title "$TITLE" --yesno "$1" 14 72 3>&1 1>&2 2>&3; return $?; fi
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
    ui_msg "Nessun sito configurato. Crea prima un sito con 'Nuovo sito'."; return 1
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
tls_for_site() {  # tls_for_site <site> — ask HTTP/HTTPS mode, then cert type
  local s="$1" mode
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
meta_get() {  # meta_get <site> <key> — read a value from the site's policy meta
  sed -n "s/^$2=//p" "/etc/hardening/sites/$1/meta" 2>/dev/null | head -1
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
# --- reach-path pickers (so grant/revoke aren't typed blind) ----------------
pick_reach_path() {  # pick_reach_path <site> <rw|ro|all> "<title>" -> chosen path
  local s="$1" which="$2" title="$3" p D="/etc/hardening/sites/$1"; local -a items=() files=()
  case "$which" in rw) files=("$D/reach-rw.paths");; ro) files=("$D/reach-ro.paths");;
                   *)  files=("$D/reach-rw.paths" "$D/reach-ro.paths");; esac
  while IFS= read -r p; do [ -n "$p" ] && items+=("$p" "$p"); done < <(cat "${files[@]}" 2>/dev/null | awk '!seen[$0]++')
  [ ${#items[@]} -eq 0 ] && { ui_msg "Nessun path attualmente concesso."; return 1; }
  ui_menu "$title" "${items[@]}"
}
pick_grant_candidate() {  # pick_grant_candidate <site> "<VERB>" -> chosen path or __CUSTOM
  local s="$1" verb="$2" docroot p D="/etc/hardening/sites/$1"; local -a items=()
  docroot="$(meta_get "$s" DOCROOT)"
  if [ -n "$docroot" ] && [ -d "$docroot" ]; then
    while IFS= read -r p; do
      [ -n "$p" ] || continue
      grep -qxF "$p" "$D/reach-rw.paths" "$D/reach-ro.paths" 2>/dev/null && continue  # skip already granted
      items+=("$p" "$p")
    done < <(find "$docroot" -mindepth 1 -maxdepth 1 -type d 2>/dev/null | sort)
  fi
  items+=("__CUSTOM" "Altro: digita un path personalizzato...")
  ui_menu "$verb: scegli una cartella (del docroot, non ancora concessa) o 'Altro':" "${items[@]}"
}

mod_nginx() {  # mod_nginx <site> — domains (server_name+aliases) and enable/disable
  local s="$1" op cur en newv
  while true; do
    cur="$(meta_get "$s" SERVER_NAME)"
    en="DISABILITATO (non servito da nginx)"; [ -e "/etc/nginx/sites-enabled/$s" ] && en="ATTIVO (servito)"
    op="$(ui_menu "Nginx di '$s':

  domini (server_name): ${cur:-?}
  stato sites-enabled : $en" \
      domains "Cambia domini / alias (server_name)" \
      enable  "Abilita il sito (link in sites-enabled)" \
      disable "Disabilita il sito (rimuovi da sites-enabled)" \
      back    "<< Indietro")" || return
    case "$op" in
      domains) newv="$(ui_input "Domini separati da spazio: il 1o e' il principale, gli altri gli alias (es: www.sito.it sito.it):" "$cur")" || continue
               [ -n "$newv" ] && tune_apply "$s" server-name "$newv" ;;
      enable)  tune_apply "$s" site-enable ;;
      disable) tune_apply "$s" site-disable ;;
      back)    return ;;
    esac
  done
}
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
  local s="$1" op p verb act
  while true; do
    op="$(ui_menu "Directory di '$s':

$(dir_summary "$s")" \
      gwrite "Concedi SCRITTURA su una cartella" \
      gread  "Concedi (sola) LETTURA su una cartella" \
      revoke "REVOCA un path (scegli dall'elenco attuale)" \
      back   "<< Indietro")" || return
    case "$op" in
      gwrite|gread)
        verb=SCRITTURA; act=grant-write
        [ "$op" = gread ] && { verb=LETTURA; act=grant-read; }
        p="$(pick_grant_candidate "$s" "$verb")" || continue
        [ "$p" = "__CUSTOM" ] && { p="$(ui_input "Path assoluto da concedere in $verb:" "/srv/${s}-shared")" || continue; }
        [ -n "$p" ] && tune_apply "$s" "$act" "$p" ;;
      revoke)
        p="$(pick_reach_path "$s" all "Quale path REVOCARE? (scegli tra quelli concessi ora)")" || continue
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

# --- program-execution (AppArmor exec) permits ------------------------------
exec_grants_summary() {  # <site>
  local f="/etc/hardening/sites/$1/permits.rules"
  if [ -s "$f" ]; then echo "ESECUZIONI CONSENTITE ora (permessi concessi):"; grep -vE '^\s*#' "$f" | sed 's/^/  /'
  else echo "Nessun programma eseguibile: il worker non puo' avviare binari esterni (modello no-exec)."; fi
}
mod_exec() {  # mod_exec <site> — grant/revoke AppArmor exec permits, informed by soak
  local s="$1" op tsv="/etc/hardening/sites/$1/permits.rules"
  while true; do
    op="$(ui_menu "Esecuzione programmi per '$s':

$(exec_grants_summary "$s")" \
      grant   "Consenti l'esecuzione di un programma (dai denial del soak)" \
      revoke  "Revoca un permesso di esecuzione concesso" \
      denials "Mostra/aggiorna i denial del soak" \
      back    "<< Indietro")" || return
    case "$op" in
      grant)   action_grant_exec "$s" ;;
      revoke)  action_revoke_permit "$s" ;;
      denials) runscript "$SCRIPTS/show-aa-denials.sh" "$s" ;;
      back)    return ;;
    esac
  done
}
action_grant_exec() {  # <site> — pick an exec DENIAL from the soak and permit it
  local s="$1" tsv="/etc/hardening/sites/$1/denials.tsv" id cnt kind perm target rule; local -a items=()
  bash "$SCRIPTS/show-aa-denials.sh" "$s" >/dev/null 2>&1 || true   # refresh denials.tsv
  if [ ! -s "$tsv" ]; then ui_msg "Nessun denial registrato. Esercita il sito (soak in complain) e riprova."; return; fi
  while IFS=$'\t' read -r id cnt kind perm target rule; do
    [ "$kind" = exec ] && items+=("$id" "$target   (${cnt} tentativi negati)")
  done < "$tsv"
  if [ ${#items[@]} -eq 0 ]; then ui_msg "Nessun tentativo di ESECUZIONE negato nel soak (ottimo: il sito non prova a eseguire binari)."; return; fi
  id="$(ui_menu "ATTENZIONE: consentire un exec INDEBOLISCE il modello no-exec.
Scegli il programma da consentire (tra i tentativi negati):" "${items[@]}")" || return
  [ -n "$id" ] || return
  ui_yesno "Consentire davvero l'esecuzione di questo programma per '$s'?

Il worker potra' avviarlo -> riduce l'isolamento. Procedere?" || return
  runscript "$SCRIPTS/add-aa-permit.sh" "$s" "$id" --force
}
action_revoke_permit() {  # <site> — pick a granted permit and remove it
  local s="$1" f="/etc/hardening/sites/$1/permits.rules" n=0 line; local -a items=()
  if [ ! -s "$f" ]; then ui_msg "Nessun permesso concesso da revocare."; return; fi
  while IFS= read -r line; do n=$((n+1)); case "$line" in ''|\#*) ;; *) items+=("$n" "$line") ;; esac; done < "$f"
  [ ${#items[@]} -eq 0 ] && { ui_msg "Nessun permesso concesso da revocare."; return; }
  n="$(ui_menu "Quale permesso di esecuzione REVOCARE?" "${items[@]}")" || return
  [ -n "$n" ] && runscript "$SCRIPTS/add-aa-permit.sh" "$s" --remove "$n"
}

# "Modify a site" — a grouped menu (Egress / Directory / PHP / TLS). Each group
# is a submenu that STAYS OPEN after a change and shows the current state, so you
# can make several edits without dropping back to the top. Drives tune-vhost.sh.
action_modify() {  # "Gestisci siti" — pick a site, then every per-site operation
  local s g
  s="$(pick_site)" || return; [ -n "$s" ] || return
  while true; do
    g="$(ui_menu "Gestisci '$s' — scegli un'operazione:" \
      nginx   "Nginx: domini (server_name), abilita/disabilita" \
      https   "HTTPS / TLS: certificato (self-signed o Let's Encrypt)" \
      egress  "Egress: destinazioni consentite / bloccate" \
      dir     "Directory: permessi lettura / scrittura" \
      exec    "Esecuzione: permessi AppArmor exec di programmi" \
      php     "PHP / Pool: memoria, limiti, workers, funzioni" \
      cookie  "Cookie sicuri (session.cookie_secure)" \
      enforce "AppArmor: Enforce (soak -> enforce)" \
      denials "AppArmor: mostra i denial del soak" \
      probe   "Verifica isolamento del sito" \
      malware "Scansione malware del docroot (YARA-X)" \
      test    "Deploy pagina di test PHP" \
      refresh "Aggiorna config (applica gli ultimi template)" \
      show    "Mostra tutta la policy del sito" \
      destroy "DISTRUGGI il sito (rimuove config, NON i dati)" \
      back    "<< Indietro")" || return
    case "$g" in
      nginx)   mod_nginx "$s" ;;
      https)   tls_for_site "$s" ;;
      egress)  mod_egress "$s" ;;
      dir)     mod_dir "$s" ;;
      exec)    mod_exec "$s" ;;
      php)     mod_php "$s" ;;
      cookie)  mod_tls "$s" ;;
      enforce) runscript "$SCRIPTS/enforce-vhost.sh" "$s" ;;
      denials) runscript "$SCRIPTS/show-aa-denials.sh" "$s" ;;
      probe)   runscript "$SCRIPTS/probe-vhost.sh" "$s" ;;
      malware) runscript "$SCRIPTS/scan-malware.sh" "$s" ;;
      test)    runscript "$SCRIPTS/deploy-test.sh" "$s" ;;
      refresh) runscript "$SCRIPTS/refresh-vhost.sh" "$s" ;;
      show)    runscript "$SCRIPTS/tune-vhost.sh" "$s" show ;;
      destroy) runscript "$SCRIPTS/destroy-vhost.sh" "$s"
               [ -d "/etc/hardening/sites/$s" ] || return ;;   # destroyed -> leave
      back)    return ;;
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
           refresh-vhost.sh destroy-vhost.sh deploy-test.sh probe-vhost.sh \
           scan-malware.sh show-aa-denials.sh add-aa-permit.sh audit-os.sh \
           scan-cve.sh audit-cis.sh; do
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
    newvhost "Crea sito" \
    modify   "Gestisci siti" \
    e2e      "Test end-to-end (ATTENZIONE: crea site1/site2!)" \
    quit     "Esci")" || break

  case "$choice" in
    baseline) runscript "$SCRIPTS/audit-os.sh" --baseline ;;
    hardenos) runscript "$SCRIPTS/harden-os.sh" ;;
    verify)   runscript "$SCRIPTS/audit-os.sh" --verify ;;
    cve)      runscript "$SCRIPTS/scan-cve.sh" ;;
    cis)      runscript "$SCRIPTS/audit-cis.sh" ;;
    newvhost) action_newvhost ;;
    modify)   action_modify ;;
    e2e)      if ui_yesno "ATTENZIONE: il test end-to-end CREA i siti di prova site1 e site2,
applica l'hardening OS e li mette in enforce.
Sono siti REALI che restano finche' non li distruggi (voce 'Distruggi un sito').

Continuare?"; then runscript "$TESTDIR/tier2-e2e.sh"; fi ;;
    quit)     break ;;
  esac
done
clear 2>/dev/null || true
