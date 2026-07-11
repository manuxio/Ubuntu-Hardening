# CLAUDE.md — Ubuntu multi-site hardening (nginx + PHP-FPM)

Context for any Claude Code session working in this repo. Read this first, then
`PLAN.md` for the build plan and `apache-php-hardening-runbook.md` for the full
phased rationale. **`GUIDA.md` is the operator-facing user guide (Italian)** —
install, run, tune, test, and troubleshoot.

**Status: Tier-1 (Docker) green; Tier-2 verified in ENFORCE on a real Ubuntu
22.04 VM** (`php-fpm//web_user (enforce)`, hat denies exec, systemd sandbox, ufw
egress, recursive auditd, live MariaDB). Four real bugs were found and fixed on
the VM — see the gotchas below (v6 egress chain name, `NoNewPrivileges` vs
`apparmor_hat`, non-recursive auditd watch, hat's own pool socket).

## What this project is

Replicable, **defensive** hardening scripts for an Ubuntu server that hosts
**several PHP virtual hosts** (Joomla and similar) behind **nginx + PHP-FPM**.
The whole point is to limit **horizontal blast radius**: a compromise of one
site must not be able to read, write, or execute across the other sites, and
post-exploitation moves (dropping a webshell, pulling a payload, spawning a
shell, phoning home) must be prevented, contained, and detected.

This is authorized security-hardening work. All controls here are defensive
(least privilege, sandboxing, egress control, integrity monitoring).

## Three scripts, deliberately split

The server hosts many vhosts, so responsibilities are split by lifecycle:

| Script | Runs | Scope |
|---|---|---|
| `scripts/harden-os.sh` | **once per server** | Shared/global layer: packages, nginx + php-fpm baseline, UFW default-deny + egress scaffolding, fail2ban, unattended-upgrades, SSH, auditd, AIDE, AppArmor **master** profile, systemd sandbox defaults, sysctl. Nothing site-specific. |
| `scripts/harden-vhost.sh` | **once per virtual host** | Per-site *setup*: runtime user, PHP-FPM pool, filesystem permission model, AppArmor **child hat**, nginx server block, per-uid egress chain, per-site auditd rule, per-pool systemd sandbox. |
| `scripts/tune-vhost.sh` | **day-2, per change** | Adjust an *existing* vhost's runtime-user policy: what hosts/ports it may reach (egress), what dirs it may read/write, and other pool/cgroup settings (limits, `disable_functions`, session flags). |
| `scripts/enforce-vhost.sh` | **after the soak** | Flip the site's AppArmor from complain to **enforce** safely: soak-denial advisory, health-check, and **auto-rollback** to complain if the worker breaks. `--revert`, `--with-master`, `--force`, `--dry-run`. Enforces the child hat by default (per-site); master only with `--with-master`. |

Run order: `harden-os.sh` first, then `harden-vhost.sh` per site, soak in
complain, `enforce-vhost.sh` to go enforce; `tune-vhost.sh` whenever a site's
policy needs to change.

Enforce note: a **child hat can be in enforce while the master stays complain** —
their AppArmor flags are independent. `enforce-vhost.sh` uses this for a safe
per-site enforce; enforce the shared master (`--with-master`) only once every
site is soaked. The flag helpers must anchor to the `profile …` line — a comment
in the master profile literally contains `flags=(complain,…)` and will fool a
naive grep/sed.

### The sync principle (why `tune-vhost.sh` exists)

A single logical policy fact is enforced in **several files at once**, and they
must never drift:

- **"runtime user may write dir X"** = php-fpm pool `open_basedir` **and** the
  AppArmor child hat (`X/ rw, X/** rwk,`) **and** systemd `ReadWritePaths` —
  all three, or you get an enforce-mode denial or an open_basedir error.
- **"runtime user may reach host:port"** = a rule in that site's `<SITE>_EGRESS`
  chain in `/etc/ufw/before.rules` (+`before6.rules`).

Editing any of these by hand is how the transcript's breakage happened
(open_basedir singular/plural, socket glob, missing sd_notify). `tune-vhost.sh`
is the single tool that changes **all coordinated places atomically**, validates,
reloads the right services, and keeps them consistent.

## Non-negotiable conventions for these scripts

- **Generic + interactive.** Every username, path, domain, DB/mail host is
  **prompted each run** with a sensible default and validated — never hardcoded.
  Follow the `prompt()`/validate style in `scripts/lib/common.sh`.
- **Env-overridable (test-friendly).** Each prompt reads its value from an env
  var if already set and only prompts on a TTY:
  `VAR="${VAR:-$DEFAULT}"; [ -t 0 ] && [ -z "${VAR_SET:-}" ] && read -r -p ... VAR`.
  This lets the Docker harness pre-seed a whole run non-interactively. A site's
  answers live in a `sites/<name>.env` file that can be `source`d.
- **Idempotent.** Safe to re-run; second run is a clean no-op. Detect existing
  users/dirs/rules before creating; use marker-delimited regions when editing
  shared files (e.g. `/etc/ufw/before.rules`).
- **`set -euo pipefail`** and refuse dangerous path targets (never operate on
  `/`, `/etc`, `/usr`, `/var`, `$HOME`, the docroot itself as a temp/log path).
- **Fail loud, print next steps.** End each script by printing the exact
  verification commands and any manual follow-ups (reloads, `configuration.php`
  edits, complain→enforce transition).

## Reference environment (the worked example from the transcript)

Use these as the *defaults* the scripts propose, not as hardcoded values.

- OS: Ubuntu server · Web: **nginx** · **PHP 8.1 FPM**
- Example site: Joomla, docroot `/var/www/html/web_user/public_html`
- Runtime user: **`web_user`** (a member of the **`www-data` group**)
- Web/FTP identity: **`www-data`** (FTP login `ftp_user` writes as www-data)
- DB: remote `10.0.0.10:3306` · Mail relay: TBD (`MAIL_HOST`)
- Updates: FTP / CLI only (not the Joomla web updater)

## The identity model (the crux — "web_user model")

The horizontal-risk root cause is one identity (`www-data`) on a
filesystem writable by that identity. The fix is **per-site uid + code the
runtime user cannot write**, implemented here as:

- **Code** owned `www-data:www-data`, dirs `750` / files `640`. The runtime
  user (`web_user`) reaches code **read-only via the `www-data` group** — it owns
  nothing, which is intentional.
- **Runtime-writable dirs** (Joomla `images/ media/ cache/ administrator/cache/`,
  plus tmp/log/session outside the docroot) are `2770` / `660`. The **setgid**
  bit forces new files to group `www-data`, so `web_user` (php-fpm) and `ftp_user`
  each stay able to manage the other's files.
- **`configuration.php` is `640`** — read-only to the runtime user, so a
  compromise can't rewrite paths/credentials. Saving Global Config from the
  admin UI failing is *by design*.
- Two knobs make it hold: **php-fpm `UMask=0007`** (web_user-created files stay
  group-writable) and **FTP umask `027`** (keeps code locked). Operational rule:
  upload code via FTP, manage media through the app's Media Manager.

Generalization: the per-vhost script parameterizes the runtime user and paths,
but keeps this ownership/setgid model.

## Layered controls (what each defends, in order of a compromise)

1. **PHP-FPM pool** — per-site uid; `php_admin_*` (not runtime-overridable):
   `open_basedir` (trailing slashes!), `security.limit_extensions = .php`,
   `disable_functions` (exec family), `allow_url_include/fopen = off`.
2. **Filesystem** — code not writable by runtime user; writable dirs `noexec`
   where mounted separately; PHP execution disabled in upload dirs.
3. **AppArmor** — master profile + per-pool **child hat** (`php-fpm//<site>`)
   that grants **no `x` anywhere** → worker can exec no external binary at all.
4. **Egress firewall by uid** — `-m owner --uid-owner <site>` default-REJECT,
   allowing only DNS, DB, mail relay, 443. Defeats `wget`/reverse-shell/miner.
5. **systemd sandbox / cgroup** — `ProtectSystem=strict`, `PrivateTmp`,
   `NoNewPrivileges`, `KillMode=control-group`, `TasksMax/MemoryMax/CPUQuota`.
6. **Detection** — auditd (writes under `/var/www`, execve by site uid), AIDE
   daily baseline, optional real-time watcher.
7. **Perimeter** — UFW default-deny, fail2ban, unattended-upgrades, SSH key-only,
   TLS.

No single layer is trusted to hold.

## Hard-won gotchas (from the enforce-mode troubleshooting — read before debugging)

- **AppArmor socket glob:** master must allow `@{run}/php{,-fpm}/php*.sock` — a
  pool socket `php8.1-web_user.sock` ends `-web_user.sock`, not `-fpm.sock`.
- **`Type=notify` needs sd_notify through AppArmor:** master needs
  `/run/systemd/notify w,` **and** `unix (connect, send, receive) type=dgram,` —
  a file rule alone doesn't cover the `sendmsg`; otherwise the unit times out.
- **AVC records go to auditd, not the journal.** With auditd installed,
  `journalctl -k | grep DENIED` is empty — look in `/var/log/audit/audit.log`
  (`ausearch -m AVC -ts recent -i`).
- **`open_basedir` trailing slashes are load-bearing:** without them
  `/var/www/html/web_user` prefix-matches siblings; also keep singular/plural
  path names (`logs` vs `log`) aligned with what the app actually uses, and make
  the dirs exist so the app never walks *up* the tree creating them.
- **nginx runs as `www-data`** — every parent dir of the docroot must be
  traversable by www-data (owner or group), or you get `stat() ... Permission
  denied` → 502. `chown www-data:www-data` the site parent, `chmod 750`.
- **`aa-teardown` unconfines the master** → pools with `apparmor_hat` fail with
  `unconfined//<site>`. Recover: `systemctl restart apparmor` then restart
  php-fpm so the master **re-execs confined**.
- **`pm = ondemand` means no worker until first request** — "pool not started"
  is normal; verify a request spawns a `php-fpm//<site>` worker.
- **`session.cookie_secure = on` breaks auth over plain HTTP** — keep it off on
  HTTP staging, flip on once TLS is in place.
- **UFW owns the firewall.** A manually appended OUTPUT rule lands *after*
  `ufw-track-output`, which ACCEPTs every new outbound connection → your rule
  sees 0 packets. Integrate egress into `/etc/ufw/before.rules` (and
  `before6.rules` for IPv6), not as a standalone iptables script. Don't run
  `netfilter-persistent save` alongside ufw.
- **AppArmor golden rule:** always **complain → soak → enforce**. Test the
  profile with `aa-exec -p php-fpm -- /usr/bin/wget ...`, not a shell command
  (AppArmor confines php-fpm and its children, not your shell).

## Testing (ephemeral Docker, two tiers)

Everything is validated in **ephemeral Docker Ubuntu** containers (`--rm`,
rebuilt from a Dockerfile) so runs are replicable. Docker cannot fully exercise
kernel-layer controls, so tests are split:

- **Tier 1 — plain container (implemented, green — `test/run-tests.sh`):** script
  idempotency, config syntax (`nginx -t`, `php-fpm -t`), the filesystem
  permission model, **live php-fpm behavior** (open_basedir blocked,
  disable_functions, `security.limit_extensions`, write into code fails / write
  into tmp passes, nginx script-must-exist + PHP-off-in-uploads), and a **live
  `mysqli` connect to an ephemeral MariaDB** (`mariadb:11.4`, the typical CMS DB)
  proving the hardened pool still reaches the database. This is the fast inner
  loop; scripts are bind-mounted so the container stays ephemeral.
- **Tier 2 — privileged systemd container:** adds systemd sandbox, UFW egress,
  auditd, and AppArmor *where the host kernel allows*. Flakier, host-dependent.
- **Residual → real VM** (multipass/Vagrant/cloud): SSH lockout, full AppArmor
  enforce soak, NFS, IPv6 egress. Documented, not Dockerized.

See `PLAN.md` §Test harness for the exact flow and caveats.

## Repo layout (target)

```text
scripts/       harden-os.sh, harden-vhost.sh, tune-vhost.sh, enforce-vhost.sh, setup-tls.sh,
               audit-os.sh (Lynis), scan-cve.sh (Trivy), audit-cis.sh (OpenSCAP),
               show-aa-denials.sh, add-aa-permit.sh, lib/
templates/     *.tmpl rendered per-site by harden-vhost.sh
config/        apparmor master, auditd rules, systemd/nginx global snippets
sites/         <name>.env — per-site answers (also non-interactive test input)
tools/         hardening-check.php (temp GUI/JSON self-test), hardening-report.php (Ed25519-gated persistent), hardening-token.php (keygen/sign CLI)
test/          Dockerfile(s), run-tests.{sh,ps1}, in-container.sh, checks/ (probe.php + *.sh)
```

The original hand-crafted artifacts from the transcript session (the per-site
pool conf, AppArmor profiles, the Joomla filesystem script, the egress script,
the browser self-test) have been **folded into `templates/` + `config/` +
`scripts/` and removed**; those are now canonical. `apache-php-hardening-runbook.md`
(phased rationale) remains.
