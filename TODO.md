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

Remaining:
- **grant-read / grant-write / revoke**: present the CURRENT reach paths to pick
  from — especially `revoke` (choose from existing, don't retype a path).
- **Directory group**: also show the AppArmor hat's *effective* r/rw grants (not
  only the reach state), so the operator sees exactly what the worker can touch.
- **Clone**: pre-load a new site's form from an existing site's `answers.env`.
- Audit every remaining free-text prompt so it pre-fills the current/derived value.
