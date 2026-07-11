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
action_tune_allow() {
  local s host port; s="$(pick_site)" || return; [ -n "$s" ] || return
  host="$(ui_input "Host/IP di destinazione egress:" "10.0.0.5")" || return
  port="$(ui_input "Porta:" "587")" || return
  runscript "$SCRIPTS/tune-vhost.sh" "$s" allow "$host" "$port"
}
action_site() {  # action_site <script> [extra args after site]
  local script="$1"; shift
  local s; s="$(pick_site)" || return; [ -n "$s" ] || return
  runscript "$script" "$s" "$@"
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
    newvhost "Nuovo virtual host (utente+pool+hat+egress)" \
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
    newvhost) runscript "$SCRIPTS/harden-vhost.sh" ;;
    enforce)  action_site "$SCRIPTS/enforce-vhost.sh" ;;
    tls)      action_tls ;;
    tune)     action_tune_allow ;;
    denials)  action_site "$SCRIPTS/show-aa-denials.sh" ;;
    e2e)      runscript "$TESTDIR/tier2-e2e.sh" ;;
    quit)     break ;;
  esac
done
clear 2>/dev/null || true
