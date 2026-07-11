#!/usr/bin/env bash
# =============================================================================
# show-aa-denials.sh <SITE> [since]
#
# Extract AppArmor denials for a pool's hat (php-fpm//<SITE>), deduplicate,
# count, and print them as a numbered list — with a ready-to-apply rule computed
# for each. The list is saved so `add-aa-permit.sh <SITE> <ID>` can grant one.
#
#   since:  today (default) | recent | this-week | boot | YYYY-MM-DD
#
# Sources denials from auditd (ausearch / audit.log) or the kernel log.
# =============================================================================
set -euo pipefail

SELF="$(cd "$(dirname "$0")" && pwd)"
. "$SELF/lib/common.sh"
. "$SELF/lib/policy.sh"
require_root

SITE="${1:-}"; SINCE="${2:-today}"
[ -n "$SITE" ] || die "usage: show-aa-denials.sh <SITE> [today|recent|this-week|boot|YYYY-MM-DD]"
LABEL="php-fpm//${SITE}"
STATE="$(policy_state_dir "$SITE")"; mkdir -p "$STATE"
TSV="$STATE/denials.tsv"

# --- collect raw AVC lines for this hat --------------------------------------
raw=""
if command -v ausearch >/dev/null 2>&1; then
  raw="$(ausearch -m AVC -ts "$SINCE" 2>/dev/null | grep -F "profile=\"$LABEL\"" || true)"
fi
if [ -z "$raw" ] && [ -f /var/log/audit/audit.log ]; then
  raw="$(grep -a 'apparmor=' /var/log/audit/audit.log 2>/dev/null | grep -F "profile=\"$LABEL\"" || true)"
fi
if [ -z "$raw" ]; then
  raw="$( { journalctl -k --no-pager 2>/dev/null; dmesg 2>/dev/null; } | grep -a 'apparmor=' | grep -F "profile=\"$LABEL\"" || true)"
fi
# keep only denials: enforce "DENIED", or complain "ALLOWED" carrying a denied_mask
denials="$(printf '%s\n' "$raw" | grep -E 'denied_mask=|apparmor="DENIED"' || true)"
if [ -z "$denials" ]; then
  : > "$TSV"
  log "no AppArmor denials for $LABEL (since=$SINCE)."
  exit 0
fi

# NB: trailing `|| true` — a missing field (e.g. no family= on a file denial)
# makes grep exit non-zero, which under pipefail+set -e would abort the script.
field()  { printf '%s' "$1" | grep -oE "$2=\"[^\"]*\"" | head -1 | sed -E "s/^$2=\"//; s/\"$//" || true; }
ufield() { printf '%s' "$1" | grep -oE "\\b$2=[^ ]+"   | head -1 | sed -E "s/^$2=//"          || true; }

# emit one canonical "RULE \t KIND \t PERM \t TARGET" per denial line
emit_one() {
  local line="$1" op name req den fam st cap mask kind perm rule p
  op="$(field "$line" operation)"; name="$(field "$line" name)"
  req="$(field "$line" requested_mask)"; den="$(field "$line" denied_mask)"
  fam="$(field "$line" family)"; st="$(field "$line" sock_type)"; cap="$(field "$line" capname)"
  mask="${req:-$den}"
  if [ -n "$cap" ]; then
    kind=capability; perm="-"; rule="capability ${cap},"; name="$cap"
  elif [ -n "$fam" ]; then
    if [ "$fam" = unix ]; then
      kind=unix; perm="${st:-stream}"; name="unix ${st:-stream}"; rule="unix (connect, send, receive) type=${st:-stream},"
    else
      kind=network; perm="${st:-stream}"; name="${fam} ${st:-stream}"; rule="network ${fam} ${st:-stream},"
    fi
  elif [ -n "$name" ]; then
    if printf '%s' "$mask" | grep -q 'x'; then
      # real rule (inherit-exec keeps confinement) but flagged exec so add-aa-permit
      # refuses it without --force — granting exec weakens the no-exec model.
      kind=exec; perm="x"; rule="\"${name}\" ix,"
    else
      p=""
      printf '%s' "$mask" | grep -q 'r'       && p="${p}r"
      printf '%s' "$mask" | grep -qE '[wacd]' && p="${p}w"
      printf '%s' "$mask" | grep -q 'k'       && p="${p}k"
      printf '%s' "$mask" | grep -q 'l'       && p="${p}l"
      printf '%s' "$mask" | grep -q 'm'       && p="${p}m"
      [ -z "$p" ] && p="r"
      kind=file; perm="$p"; rule="\"${name}\" ${p},"
    fi
  else
    kind=other; perm="-"; name="op=${op:-?}"; rule="# review (unparsed): ${line}"
  fi
  printf '%s\t%s\t%s\t%s\n' "$rule" "$kind" "$perm" "$name"
}

# --- build counted, sorted, numbered list ------------------------------------
tmp="$(mktemp)"
while IFS= read -r l; do [ -n "$l" ] && emit_one "$l"; done <<< "$denials" > "$tmp"
counted="$(sort "$tmp" | uniq -c | sort -rn)"
rm -f "$tmp"

: > "$TSV"
printf '%-3s %-6s %-11s %-5s %s\n' "ID" "COUNT" "KIND" "PERM" "TARGET"
printf '%-3s %-6s %-11s %-5s %s\n' "---" "-----" "-----------" "-----" "----------------------------------"
id=0
while IFS= read -r row; do
  [ -n "$row" ] || continue
  cnt="$(awk '{print $1}' <<< "$row")"
  rest="$(sed -E 's/^ *[0-9]+ //' <<< "$row")"     # RULE \t KIND \t PERM \t TARGET
  rule="$(cut -f1 <<< "$rest")"; kind="$(cut -f2 <<< "$rest")"
  perm="$(cut -f3 <<< "$rest")"; target="$(cut -f4 <<< "$rest")"
  id=$((id+1))
  printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$id" "$cnt" "$kind" "$perm" "$target" "$rule" >> "$TSV"
  # highlight unsafe exec rows
  if [ "$kind" = exec ]; then
    printf '%s%-3s %-6s %-11s %-5s %s%s\n' "$_C_YEL" "$id" "$cnt" "$kind" "$perm" "$target" "$_C_RST"
  else
    printf '%-3s %-6s %-11s %-5s %s\n' "$id" "$cnt" "$kind" "$perm" "$target"
  fi
done <<< "$counted"

echo
info "saved: $TSV"
info "grant one:  $SELF/add-aa-permit.sh $SITE <ID>    (exec rows need --force and are discouraged)"
