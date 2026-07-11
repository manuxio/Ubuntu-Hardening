# TODO / Backlog

## Menu: always show a site's CURRENT settings + allow targeted edits

**Problem:** when modifying a site the operator must not work blind — the menu
has to READ and DISPLAY the site's current configuration (permissions, paths,
values) *before* offering a change, so edits are informed and targeted instead
of guessed.

**Status: PARTIAL** (grouped "Modifica un sito" menu already shows a lot).

Done:
- **PHP / Pool**: every setting shows its current value inline; editing pre-fills it.
- **Egress**: shows the currently ALLOWED destinations (from the live chain) +
  "everything else BLOCKED".
- **Directory**: shows current read/write reach paths with their filesystem perms.
- **Nginx**: shows current domains (`server_name`) + `sites-enabled` status.
- **TLS / cookie**: shows current `session.cookie_secure`.
- `enforce-vhost <site> --dry-run` reports the hat's declared minimum (read code
  + write N declared paths).
- **Directory — grant/revoke pickers**: `revoke` picks from the current reach
  paths (no retyping); `grant-write`/`grant-read` offer the docroot subdirs not
  yet granted + "custom".
- **Esecuzione (AppArmor exec)** group: shows the exec permits currently granted;
  granting one is a picker of the DENIED exec attempts from the soak (+ warning),
  and revoke picks from the granted permits.

Remaining:
- **Directory group**: also show the AppArmor hat's *effective* r/rw grants (not
  only the reach state), so the operator sees exactly what the worker can touch.
- **Clone**: pre-load a new site's form from an existing site's `answers.env`.
- Audit every remaining free-text prompt so it pre-fills the current/derived value.
