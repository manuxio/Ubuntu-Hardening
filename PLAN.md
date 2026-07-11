# PLAN.md — Build the two hardening scripts + ephemeral Docker harness

Goal: turn the transcript's hand-crafted, single-box artifacts into **two
generic, interactive, idempotent scripts** that reproduce the hardened state on
any Ubuntu server hosting several nginx + PHP-FPM virtual hosts, and validate
them in **ephemeral Docker**.

Decisions (confirmed): web server **nginx**; identity model **web_user** (runtime
user in `www-data` group, code owned by www-data); test harness **two-tier**
(plain container + privileged systemd container). Scripts are **generic** —
usernames/paths/hosts prompted each run, env-overridable for tests. **Two**
scripts because the box hosts **several** vhosts (OS layer once, site layer per
vhost).

---

## 1. Deliverables

1. `scripts/harden-os.sh` — server-wide hardening, run once.
2. `scripts/harden-vhost.sh` — per-virtual-host *setup*, run once per site.
3. `scripts/tune-vhost.sh` — day-2 *policy tuning* for an existing vhost
   (egress hosts/ports, read/write dirs, pool/cgroup settings), run per change.
4. `templates/` — per-site config templates the vhost script renders.
5. `test/` — Dockerfile(s), orchestrator, and verification checks.
6. `sites/<name>.env` — example per-site answer file (`web_user.env` matching the
   transcript) usable both as documentation and as non-interactive test input.

Scripts are the next step; this file plans their structure so they can be built
directly.

---

## 2. Repo structure to create

```text
scripts/
  harden-os.sh
  harden-vhost.sh
  tune-vhost.sh            # day-2 policy tuning (egress / fs reach / limits)
  lib/common.sh            # shared: prompt(), require_root, refuse_bad_path, log, marker-region edit
  lib/policy.sh           # shared: sync a fs/egress fact across pool+hat+systemd+ufw
templates/
  php-fpm-pool.conf.tmpl   # from php-fpm-web_user-pool.conf, variables substituted
  apparmor-child.tmpl      # from apparmor-php-fpm.d-web_user
  nginx-site.conf.tmpl     # NEW (nginx equivalent of the Apache routing rules)
  systemd-pool.conf.tmpl   # per-pool sandbox drop-in
  egress-chain.tmpl        # before.rules chain body (from web_user-egress.sh)
config/
  apparmor-php-fpm-master  # existing, installed by harden-os.sh
  auditd-hardening.rules   # global auditd rules
  nginx-hardening.conf     # global nginx snippet (server_tokens, TLS, limits)
  systemd-fpm-global.conf  # global php-fpm sandbox drop-in
sites/
  web_user.env                  # example answers (web_user / web_user / PHP 8.1)
test/
  Dockerfile.tier1         # plain ubuntu
  Dockerfile.tier2         # systemd-init ubuntu (privileged)
  run-tests.sh
  checks/
    fs-model.sh            # permission assertions
    php-behavior.sh        # curl hardening-check.php + assert verdicts
    idempotency.sh
    hardening-check.php    # existing browser self-test, driven headless
```

Existing artifact → destination mapping:

| Existing file | Becomes |
|---|---|
| `php-fpm-web_user-pool.conf` | `templates/php-fpm-pool.conf.tmpl` (values → vars) |
| `apparmor-php-fpm.d-web_user` | `templates/apparmor-child.tmpl` |
| `apparmor-php-fpm-master` | `config/apparmor-php-fpm-master` (installed as-is by OS script) |
| `joomla-filesystem.sh` | filesystem-permission section of `harden-vhost.sh` |
| `web_user-egress.sh` | `templates/egress-chain.tmpl` + before.rules integration in vhost script |
| `hardening-check.php` | `test/checks/hardening-check.php` (verification, not deploy) |
| `apache-php-hardening-runbook.md` | reference; each phase maps to a script section (below) |

---

## 3. `harden-os.sh` — server-wide, run once

Interactive prompts (all env-overridable): `PHP_VERSION` (detect default),
`SSH_HARDEN` (y/N — guarded so Docker/console isn't locked out), `ADMIN_USER`
for SSH allow-list, `ENABLE_MODSEC` (y/N), `RUN_AIDEINIT` (y/N — slow).

Sections (each idempotent, maps to runbook phases):

1. **Preflight** — root check; detect Ubuntu + PHP version; detect if running in
   a container (`/.dockerenv` or cgroup) and set a `CONTAINER=1` flag that makes
   systemd/ufw/auditd/apparmor steps *degrade graweb_userully* (configure files,
   skip live enable) so Tier-1 tests still pass.
2. **Packages** — `nginx php$V-fpm php$V-{cli,mysql,gd,xml,mbstring,...} ufw
   fail2ban unattended-upgrades auditd audispd-plugins aide apparmor-utils acl`
   (+ ModSecurity connector if `ENABLE_MODSEC`).
3. **nginx baseline** — install `config/nginx-hardening.conf` (server_tokens
   off, client_max_body_size, TLS protocol/cipher defaults, security headers
   map); remove the default site; leave per-site blocks to the vhost script.
4. **PHP-FPM baseline** — lock down / disable the stock `www` pool; set a global
   `php.ini` baseline (expose_php off, etc.) knowing per-pool `php_admin_*` wins.
   Set service `UMask=0007` default (per-pool can reaffirm).
5. **AppArmor master** (runbook Phase 4) — install
   `config/apparmor-php-fpm-master` to `/etc/apparmor.d/php-fpm`, `mkdir
   /etc/apparmor.d/php-fpm.d`, load in **complain**. Child hats are added by the
   vhost script. Keep the socket glob + sd_notify fixes from the gotchas.
6. **systemd sandbox defaults** (Phase 2) — install `config/systemd-fpm-global.conf`
   as a drop-in with the safe host-wide directives (`ProtectSystem=strict`,
   `PrivateTmp`, `ProtectHome`, `NoNewPrivileges`, `ProtectKernelTunables`,
   `ProtectControlGroups`, `RestrictSUIDSGID`, `SystemCallFilter=@system-service`).
   Per-site `ReadWritePaths` are appended by the vhost script (drop-ins stack).
7. **UFW + egress scaffolding** (Phase 5/8) — default deny incoming; allow
   OpenSSH + 80/443; enable. Add **marker-delimited regions** to
   `/etc/ufw/before.rules` and `/etc/ufw/before6.rules` where the vhost script
   inserts per-uid chains (the durable fix — no standalone iptables script).
8. **auditd global** (Phase 6) — install `config/auditd-hardening.rules`
   (`-w /var/www -p wa -k webroot_write` + execve baseline); leave the ruleset
   mutable so vhost script can add per-site rules.
9. **AIDE** (Phase 6) — configure exclusions (caches/uploads/sessions), run
   `aideinit` only if `RUN_AIDEINIT` (it's slow; default off in tests).
10. **fail2ban** — sshd + nginx jails.
11. **unattended-upgrades** — enable security channel.
12. **SSH hardening** (Phase 8) — only if `SSH_HARDEN`: key-only,
    `PermitRootLogin no`, `AllowUsers $ADMIN_USER`. **Never** applied in
    container mode (lockout guard).
13. **sysctl** — standard network/kernel hardening drop-in.
14. **Summary** — print what's in complain mode, what needs a soak, next command
    (`harden-vhost.sh`).

---

## 4. `harden-vhost.sh` — per virtual host, run once per site

The generic core. Interactive prompts (env-overridable; a `sites/<name>.env`
can pre-answer all of them). Reuses `joomla-filesystem.sh`'s validate-then-apply
approach.

### Prompts / inputs

| Var | Default | Validation |
|---|---|---|
| `SITE` | (none) | short name `[a-z0-9_-]`, used for pool/hat/socket/chain names |
| `SERVER_NAME` | `$SITE.local` | domain(s) for the nginx block |
| `DOCROOT` | `/var/www/html/<SITE>/public_html` | must exist & be a dir; warn if no `configuration.php` |
| `SITE_PARENT` | derived (`dirname DOCROOT`) | chown www-data:www-data, chmod 750 (nginx traverse fix) |
| `RUNTIME_USER` | `web_user`(first run) / `$SITE` | must exist (offer `useradd -r -s nologin`); must be in `www-data` (offer `usermod -aG`, remind to restart fpm) |
| `PHP_VERSION` | detected | pool/socket/service naming |
| `WRITABLE_DIRS` | `images media cache administrator/cache` | space-separated, relative to docroot |
| `TMP_PATH` | `/var/www/html/<SITE>/tmp` | outside docroot; refuse dangerous targets |
| `SESSION_PATH` | `/var/www/html/<SITE>/sessions` | outside docroot |
| `LOG_PATH` | `/var/www/html/<SITE>/logs` | outside docroot; align singular/plural! |
| `DB_HOST` / `DB_PORT` | `10.0.0.10` / `3306` | egress allow |
| `MAIL_HOST` / `MAIL_PORTS` | (empty) / `25,465,587` | egress allow; warn if empty |
| `ALLOW_HTTPS` | `yes` | egress allow 443 |
| `COOKIE_SECURE` | `off` until TLS | session hardening (HTTP gotcha) |

### Sections (each idempotent)

1. **Validate** all inputs; create runtime user / dirs if missing; ensure
   `www-data` group membership.
2. **Filesystem model** (runbook Phase 1) — the `joomla-filesystem.sh` logic:
   code `www-data:www-data` `750`/`640`; `WRITABLE_DIRS` `2770`/`660` **setgid**;
   `configuration.php` `640`; create `TMP/SESSION/LOG` `2770 www-data:www-data`
   setgid outside the docroot; chown+chmod `SITE_PARENT` for nginx traversal.
3. **PHP-FPM pool** — render `templates/php-fpm-pool.conf.tmpl` →
   `/etc/php/$V/fpm/pool.d/<SITE>.conf`: user/group, socket
   `/run/php/php$V-<SITE>.sock` (owner/group www-data, mode 0660),
   `open_basedir` **with trailing slashes** covering docroot+tmp+session+log,
   `security.limit_extensions=.php`, `disable_functions`,
   `allow_url_include/fopen=off`, session flags (`cookie_secure=$COOKIE_SECURE`),
   `error_log=$LOG_PATH/php-error.log`, `apparmor_hat=<SITE>`, `clear_env`,
   `request_terminate_timeout`, `rlimit_core=0`. `php-fpm -t` to validate.
4. **AppArmor child hat** — render `templates/apparmor-child.tmpl` →
   `/etc/apparmor.d/php-fpm.d/<SITE>` with this site's paths (code `r`, writable
   dirs `rw`/`rwk`, tmp/session/log `rw`, **no `x` anywhere**, audited
   exec-denies for logging). Reload master (`apparmor_parser -r`), keep
   **complain** until soak done.
5. **nginx server block** — render `templates/nginx-site.conf.tmpl` →
   `/etc/nginx/sites-available/<SITE>`, symlink-enable. Must encode the Apache
   rules' nginx equivalents:
   - `fastcgi_pass unix:/run/php/php$V-<SITE>.sock;` only for real `.php`
     (`try_files $uri =404;` inside the php location → kills the
     `photo.jpg/foo.php` mismatched-script vuln).
   - **PHP disabled in writable/upload dirs**: a `location ~ ^/(images|media|...)/`
     that does *not* pass to fastcgi (serves static or denies) — the nginx
     equivalent of `SetHandler None`.
   - `server_tokens off`, security headers, `client_max_body_size` matching
     `upload_max_filesize`. `nginx -t` to validate.
6. **systemd per-pool sandbox** — render `templates/systemd-pool.conf.tmpl` →
   `/etc/systemd/system/php$V-fpm.service.d/<SITE>.conf` adding
   `ReadWritePaths=$DOCROOT $TMP_PATH $SESSION_PATH $LOG_PATH` (stacks on the
   global drop-in). Note: a single shared fpm service means `TasksMax/MemoryMax/
   CPUQuota` are process-wide; **document** the optional upgrade to one systemd
   service per pool for a true per-site cgroup, offered behind a prompt.
7. **Egress by uid** (Phase 5) — render `templates/egress-chain.tmpl` into the
   marked region of `/etc/ufw/before.rules` (+`before6.rules`): a `<SITE>_EGRESS`
   chain (ESTABLISHED, lo, DNS, `DB_HOST:DB_PORT`, `MAIL_HOST:MAIL_PORTS`, 443,
   log+REJECT) hooked via `-m owner --uid-owner <uid> -j <SITE>_EGRESS` **before**
   the ufw ACCEPT. `ufw reload`.
8. **auditd per-site** — add `-a always,exit -F arch=b64 -S execve -F auid=<uid>
   -k <SITE>_exec` to the rules; reload.
9. **Summary** — print the `configuration.php` lines (`tmp_path`, `log_path`),
   reload commands, the **complain-mode soak checklist** (exercise front end,
   admin, article save, media upload, cache clear, scheduler), how to harvest
   denials and run `aa-logprof`, then the enforce transition (strip `complain`
   from master + child, reload, verify `ps afxZ` shows `php-fpm//<SITE>
   (enforce)`), and how to run `hardening-check.php`.

---

## 5. `tune-vhost.sh` — day-2 policy tuning, per change

Adjusts the runtime-user policy of an **already-set-up** vhost without re-running
the full setup. Its reason to exist is the **sync principle**: one logical fact
lives in several config files that must stay consistent (see `CLAUDE.md`).
Subcommand-driven (also offers an interactive menu); operates on a named `SITE`,
loading `sites/<SITE>.env` for its user/uid/paths (else prompts). Every op is
idempotent, validates input, edits **all coordinated places atomically**,
reloads only the affected services, and prints a before/after summary.

### 5.1 Egress — hosts/ports the user can reach

- `allow  <SITE> <host> <port> [tcp|udp]` / `deny <SITE> <host> <port>` /
  `list <SITE>` — edit that site's `<SITE>_EGRESS` chain inside the marked region
  of `/etc/ufw/before.rules` (+`before6.rules` for IPv4-capable hosts), then
  `ufw reload`. Rules are keyed so re-adding is a no-op; removing strips the exact
  match. Never touches other sites' chains.

### 5.2 Filesystem reach — dirs the user may read / write (the coordinated one)

- `grant-write <SITE> <path>` / `grant-read <SITE> <path>` / `revoke <SITE> <path>`.
- Each op updates **three files in lockstep** via `lib/policy.sh`:
  1. **php-fpm pool** `open_basedir` — append/remove the path (trailing slash!).
  2. **AppArmor child hat** `/etc/apparmor.d/php-fpm.d/<SITE>` — `path/ rw,` +
     `path/** rwk,` for write (or `r,`/`r,` for read); `apparmor_parser -r`.
  3. **systemd** drop-in `ReadWritePaths` (write only); `daemon-reload`.
- Then restart the pool. If the profile is in **enforce**, warn that a new
  writable path needs the hat reloaded first (else instant denial) — the script
  does them in the safe order and can drop back to complain on request.
- Refuses dangerous targets (`/`, `/etc`, docroot-as-scratch, another site's tree).

### 5.3 Other settings

- **Resource caps (pool):** `set <SITE> memory_limit|max_execution_time|
  upload_max_filesize|post_max_size <value>` → `php_admin_value` in the pool.
- **cgroup caps (systemd):** `set <SITE> MemoryMax|CPUQuota|TasksMax <value>` →
  the per-pool systemd drop-in (meaningful only with a per-pool service; warn if
  the pool shares the global fpm service).
- **`disable_functions`:** `disable <SITE> <func>` / `enable <SITE> <func>` —
  add/remove from the pool list.
- **Session/TLS flip:** `tls-on <SITE>` / `tls-off <SITE>` → toggle
  `session.cookie_secure` (the HTTP↔HTTPS gotcha) and any HSTS header in the
  nginx block.
- **`allow_url_fopen`:** `set <SITE> allow_url_fopen on|off` — for the occasional
  extension that needs it.

### 5.4 Guardrails

- `--dry-run` prints the exact edits + reloads without applying.
- Reads current state before writing so a re-run is a clean no-op.
- Every mutation of a shared file (`before.rules`, master profile) stays inside
  this site's marker region — never disturbs sibling sites.

---

## 6. Test harness — ephemeral Docker, two tiers

All containers run `--rm` and are rebuilt from a Dockerfile → replicable. A
site's `sites/<name>.env` pre-seeds every prompt so scripts run non-interactive.

### Tier 1 — plain container (fast inner loop)  ✅ IMPLEMENTED, GREEN

`test/Dockerfile.tier1` on `ubuntu:22.04` (nginx + PHP 8.1-FPM + AppArmor
userspace pre-baked, ~414 MB). `test/run-tests.sh` (host) also starts a small
**ephemeral MariaDB** container (`mariadb:11.4` — the typical Joomla/WordPress
DB) on a throwaway docker network, torn down on exit. Scripts are **bind-mounted**
at `/work` (not copied) so the container stays ephemeral. `test/in-container.sh`:

1. Builds a throwaway Joomla-ish docroot (configuration.php, index.php, writable
   dirs, a dropped `images/shell.php`, a PHP-smuggled `images/photo.jpg`).
2. `harden-os.sh` in `CONTAINER=1` mode (writes files; skips live
   ufw/auditd/systemd/apparmor enable) then `harden-vhost.sh` from `sites/web_user.env`
   (non-interactive; `apparmor_hat` auto-disabled in-container).
3. Starts php-fpm + nginx **manually** (no systemd) and runs `checks/`:
   - `fs-model.sh` — code owned www-data 750 not writable by runtime user;
     writable dirs 2770 setgid; `configuration.php` 640; `SITE_PARENT`
     traversable by www-data; runtime user writes media, not code/config.
   - `php-behavior.sh` — curls `probe.php`: `open_basedir` blocks `/etc/passwd`;
     `disable_functions` + live `exec()` blocked; **write code FAILS, write
     images PASSES**; `allow_url_fopen`/`expose_php` off; worker runs as `web_user`.
     Then via nginx: nonexistent `.php` → 404 (script-must-exist);
     `images/shell.php` → 403 (PHP off in upload dir); `photo.jpg` served inert;
     and a **live `mysqli` connect + `SELECT 1` to MariaDB** (CMS DB works
     through the hardened pool).
   - `idempotency.sh` — re-run both scripts: generated state byte-identical;
     plus `tune-vhost.sh grant-write` lands in pool `open_basedir` **+** AppArmor
     hat **+** systemd `ReadWritePaths` together.

   Result: **27 checks pass, exit 0.**

What Tier 1 **cannot** prove: AppArmor enforcement, auditd capture, systemd
sandbox, ufw egress (all kernel/PID1-dependent). It validates config generation,
the filesystem model, live php-fpm hardening behavior, and DB connectivity — the
majority of the surface.

### Tier 2 — real VM  ✅ DONE, VERIFIED IN ENFORCE

Rather than a privileged systemd container, Tier-2 was validated on a **real
Ubuntu 22.04 LTS VM** (PHP 8.1, MariaDB 10.6) — the highest fidelity. Verified
with AppArmor in **enforce**:

- master `php-fpm (enforce)`, worker `php-fpm//web_user (enforce)`;
- the hat **denies exec** of `cat`/`wget`/`id` (audit `denied_mask="x"`);
- systemd sandbox active (`ProtectSystem=strict`, per-site `ReadWritePaths`);
- ufw egress by uid: web_user→:80 REJECT, web_user→:443 + DB ACCEPT;
- auditd recursive `webroot_write` tree rule captures deep writes;
- nginx routing (404/403/inert) + live MariaDB connect through the pool.

**Four real bugs surfaced only on the VM (all fixed in-repo):** (1) v6 egress
hook used `ufw-before-output` instead of `ufw6-before-output` — disabled the
firewall on reload; (2) `NoNewPrivileges=yes` blocked the `apparmor_hat`
transition (EPERM, no AVC) — removed from the systemd sandbox; (3) `-w /var/www`
is non-recursive — switched to an `-F dir=` audit tree rule; (4) the hat lacked
its own pool socket rule — 0 requests under enforce until added. See the
operator guide `GUIDA.md` §9 and `CLAUDE.md` gotchas.

The alternative privileged-container Tier-2 below remains a documented option
for CI where a VM isn't available.

`Dockerfile.tier2` on a systemd-init image (e.g. `jrei/systemd-ubuntu:22.04`),
run `--privileged` with cgroup mounts. Full run via systemd; then verify where
the host kernel permits:

- `ps afxZ | grep php-fpm` → worker shows `php-fpm//<SITE>` (AppArmor hat active).
- `aa-exec -p php-fpm -- /usr/bin/wget http://example.com` → Permission denied.
- `ufw status` active; per-uid egress chain present; `sudo -u <RUNTIME_USER>`
  outbound to a non-allowed host is REJECTed.
- auditd rules loaded (`auditctl -l`); a write under `/var/www` shows in
  `ausearch -k webroot_write`.
- systemd sandbox active (`systemctl show php$V-fpm -p ProtectSystem`).

**Caveats to document, not fight:** loading an AppArmor profile touches the host
kernel and needs host AppArmor support + privilege; auditd needs
`CAP_AUDIT_CONTROL`; ufw/iptables needs `NET_ADMIN` and can clash with Docker's
own iptables. CI without these skips Tier 2 with a clear message rather than
failing.

### Residual — real VM (documented, not Dockerized)

SSH key-only lockout behavior, full AppArmor **enforce** soak, NFS-backed
docroots (runbook Phase 1b), IPv6 egress end-to-end. Use multipass / Vagrant /
a throwaway cloud VM.

---

## 7. Build milestones

1. **Scaffolding** — repo structure, `lib/common.sh` (`prompt`, `require_root`,
   `refuse_bad_path`, marker-region file edit, container detection) and
   `lib/policy.sh` (the sync helper `tune-vhost.sh` and `harden-vhost.sh` share).
2. **`harden-vhost.sh` + templates** — port the existing artifacts; get Tier-1
   green for `sites/web_user.env` first (highest value, fully Dockerable).
3. **`harden-os.sh`** — the shared layer; get a plain-container run clean and
   idempotent.
4. **`tune-vhost.sh`** — build on `lib/policy.sh`; verify a grant-write /
   allow-egress round-trips through all coordinated files and re-runs as a no-op.
5. **Tier-1 harness** — `Dockerfile.tier1`, `run-tests.sh`, all `checks/`
   (include a tune-then-recheck case: grant a writable dir, assert it appears in
   pool + hat + systemd and the FS check still passes).
6. **Tier-2 harness** — systemd image; wire the kernel-layer verifications with
   graweb_userul skips.
7. **Second sample site** — add a non-Joomla `sites/<other>.env` to prove the
   scripts are genuinely generic (different user, docroot, writable dirs).
8. **Docs** — update `CLAUDE.md` pointers; short `README` on running the harness.

---

## 8. Verification checklist (maps to runbook §"Verification pass")

- [ ] As runtime user, cannot read another site's docroot (perms + open_basedir).
- [ ] `wget` as runtime user → AppArmor denies exec **and** egress REJECTs (T2).
- [ ] Benign `test.php` in an upload dir → served inert, not interpreted.
- [ ] `photo.jpg/foo.php` → 404, not executed.
- [ ] Write under `/var/www` → `ausearch -k webroot_write` shows it (T2).
- [ ] `aide --check` → test file under **Added** (VM/T2).
- [ ] Restart pool → spawned children killed (`KillMode=control-group`, T2).
- [ ] Runtime user **cannot** write code / `configuration.php`; **can** write
      writable dirs + tmp (T1).
- [ ] Scripts re-run cleanly (idempotency, T1).
- [ ] Worker confined as `php-fpm//<SITE>` in enforce (T2/VM).
- [ ] `tune-vhost.sh grant-write` lands in pool `open_basedir` **+** AppArmor hat
      **+** systemd `ReadWritePaths` together, and re-running is a no-op (T1).
- [ ] `tune-vhost.sh allow` opens exactly one destination in `<SITE>_EGRESS` and
      leaves sibling sites' chains untouched (T2).

---

## 9. Open parameters to confirm at build time

- `MAIL_HOST` (SMTP relay IP) — still TBD in the transcript.
- Per-pool **separate systemd service** vs shared service (affects whether
  `MemoryMax/CPUQuota/TasksMax` are per-site) — default shared, offer opt-in.
- ModSecurity for nginx (libmodsecurity + CRS) — include in OS script or defer.
- TLS provisioning (Let's Encrypt) — in `harden-vhost.sh` or a separate step;
  gates flipping `session.cookie_secure` back on.
- NFS-backed docroots (runbook Phase 1b) — is `/var/www` local or NFS here? If
  NFS, the vhost filesystem section needs the ro-code / rw-data mount split and
  sessions/tmp on local disk.
