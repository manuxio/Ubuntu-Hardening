# Ubuntu Hardening

Replicable, **defensive** hardening for an Ubuntu server that hosts **several PHP
virtual hosts** (Joomla / WordPress and similar) behind **nginx + PHP-FPM**. The
goal is to limit **horizontal blast radius**: a compromise of one site cannot
read, write, or execute across the others, and post-exploitation moves (dropping
a webshell, pulling a payload, spawning a shell, phoning home) are prevented,
contained, and detected. A hardened site can also be **exported to a container**
(docker-compose + Kubernetes) that keeps the same runtime containment.

Verified end-to-end on a real Ubuntu 22.04 VM: sites under AppArmor **enforce**, a
green cross-site isolation matrix (`test/tier2-e2e.sh`), and a Lynis hardening
index raised **65 → 84** — plus config/filesystem/PHP checks in ephemeral Docker.

> 📖 **Full operator guide (Italian):** [`GUIDA.md`](GUIDA.md) ·
> 🧪 **Menu walkthrough with real screenshots:** [`example.md`](example.md) ·
> 🐳 **Containerize a site:** [`dockerize.md`](dockerize.md)

---

## What it sets up (defence in depth)

| Layer | Control |
|---|---|
| Identity | one Unix user + PHP-FPM pool **per site** |
| Filesystem | code **not writable** by the runtime user; setgid writable dirs; `configuration.php` read-only |
| PHP pool | `open_basedir`, `security.limit_extensions=.php`, `disable_functions`, `allow_url_*=off`, `cgi.fix_pathinfo=0` (all `php_admin_*`) |
| AppArmor | per-pool **hat** (`php-fpm//<site>`) that grants **no exec** anywhere; optional **granular per-dir extension write-deny** (`noext`) |
| systemd | sandbox (`ProtectSystem=strict`, `ReadWritePaths`, `PrivateTmp`, cgroup caps) |
| Network | **egress firewall by uid** (ufw) — allow only DNS/DB/mail/443 |
| Web | nginx script-must-exist, **no PHP execution in writable/upload dirs** (webshell block, kept in sync), per-site logs, **TLS**, optional **HTTP Basic auth** |
| Detection | auditd (webroot writes + per-site `execve`), AIDE, **YARA-X** webshell scan |
| Perimeter | UFW default-deny, fail2ban, unattended-upgrades, SSH, sysctl |

No single layer is trusted to hold.

## Requirements

- **Ubuntu 22.04 LTS** (ships PHP 8.1) — the scripts are generic but default to 8.1.
- root / sudo on the target server.
- PHP-FPM built with AppArmor support (Ubuntu's is): `ldd /usr/sbin/php-fpm8.1 | grep apparmor`.
- For testing without a server: **Docker** (fast) or a throwaway **VM**.

## Download

```bash
git clone git@github.com:manuxio/Ubuntu-Hardening.git
cd Ubuntu-Hardening
# or: download the ZIP from the GitHub page
```

## Quick start — the menu

The easiest path is the interactive TUI, which drives every operation below and
**shows each site's current state** before you change it:

```bash
sudo bash scripts/harden-menu.sh
```

Main menu: audit (Lynis / Trivy / OpenSCAP), **harden the OS**, **Create site**,
**Manage sites**, end-to-end test. Under **Manage sites** you get every per-site
op — nginx/domains, TLS, egress, read/write dirs, per-extension write-deny,
PHP/pool, cookies, **Basic auth**, AppArmor enforce, isolation probe, **YARA-X
malware scan**, test page, **Containerize**, show policy, destroy.

## Quick start — the command line

```bash
# 0) copy this repo to the server (e.g. rsync/scp/tar), then cd into it

# 1) OS layer — run ONCE per server (installs nginx/php baseline, AppArmor master,
#    UFW default-deny + egress, auditd, AIDE, fail2ban, YARA-X, sysctl…)
sudo bash scripts/harden-os.sh

# 2) per site: create the docroot + database, fill a sites/<name>.env, then:
sudo bash -c 'set -a; . sites/site1.env; set +a; bash scripts/harden-vhost.sh'

# 3) restart php-fpm, exercise the site (complain-mode soak), then enforce:
sudo systemctl restart php8.1-fpm
sudo bash scripts/enforce-vhost.sh site1        # AppArmor complain -> enforce (auto-rollback if it breaks)

# 4) HTTPS (optional):
sudo bash scripts/setup-tls.sh site1 --self-signed                       # staging
sudo bash scripts/setup-tls.sh site1 --letsencrypt --email you@dom.tld   # real cert + auto-renew
```

Measure it (run `audit-os.sh --baseline` *before* step 1 to compare):

```bash
sudo bash scripts/audit-os.sh --verify     # Lynis hardening index (measured 65 -> 84)
sudo bash scripts/scan-cve.sh              # Trivy: CVEs in installed packages
sudo bash scripts/audit-cis.sh             # OpenSCAP: CIS benchmark score + HTML report
```

Everything is **interactive with sensible defaults** and **env-overridable**
(pre-seed a `sites/<name>.env`), **idempotent**, and prints the verification
commands at the end. See [`example.md`](example.md) for a full run with screenshots.

## Day-2 operations

```bash
sudo bash scripts/tune-vhost.sh site1 allow 10.0.0.5 587           # open an egress destination
sudo bash scripts/tune-vhost.sh site1 grant-write /srv/shared      # pool + AppArmor + systemd + nginx, in sync
sudo bash scripts/tune-vhost.sh site1 noext-add .../images php,phtml,phar  # deny writing those exts (AppArmor)
sudo bash scripts/tune-vhost.sh site1 auth-user admin              # HTTP Basic auth: add user + enable
sudo bash scripts/scan-malware.sh    site1                         # YARA-X webshell scan of the docroot
sudo bash scripts/probe-vhost.sh     site1                         # isolation matrix against a real site
sudo bash scripts/show-aa-denials.sh site1                         # list AppArmor denials to resolve
sudo bash scripts/add-aa-permit.sh   site1 <id>                    # grant one (exec refused by default)
```

## Containerize a site

Turn a hardened vhost into a minimal container bundle that keeps the same runtime
containment (non-root, read-only rootfs, cap-drop ALL, no-new-privileges, seccomp,
per-site AppArmor, egress, shell-less images, identical file structure on a
persistent volume) — as **docker-compose** (local testing) and **Kubernetes**:

```bash
sudo bash scripts/export-site.sh site1 --both     # prompts: images, replicas, namespace, Redis, Basic auth, PVC…
```

See [`dockerize.md`](dockerize.md) (how-to) and [`docs/CONTAINERS.md`](docs/CONTAINERS.md)
(security mapping + user/uid logic).

## Test without touching production

```bash
# Docker (Linux / macOS / Git-Bash) — config generation, filesystem model,
# live php-fpm behaviour, and a live MariaDB connectivity check:
bash test/run-tests.sh
# Windows PowerShell:
powershell -ExecutionPolicy Bypass -File test\run-tests.ps1
```

Docker can't exercise kernel-layer controls (AppArmor enforce, auditd, ufw,
systemd) — those are validated on a real VM with the **Tier-2 end-to-end
harness**, which provisions two sites, enforces AppArmor, adds TLS, then proves
cross-site isolation both directions:

```bash
# on a throwaway VM that already has scripts/harden-os.sh applied, run as root:
sudo bash test/tier2-e2e.sh        # 32 assertions incl. the isolation matrix
```

See [`PLAN.md`](PLAN.md) §Test.

## Scripts

| Script | Purpose |
|---|---|
| `scripts/harden-menu.sh` | **interactive whiptail menu** that drives everything below |
| `scripts/harden-os.sh` | server-wide layer (once) |
| `scripts/harden-vhost.sh` | per-site setup (user, pool, hat, nginx, egress, auditd) |
| `scripts/tune-vhost.sh` | day-2 policy (egress / reach dirs / noext / basic auth / limits), kept in sync |
| `scripts/enforce-vhost.sh` | complain → enforce, with soak check + auto-rollback |
| `scripts/refresh-vhost.sh` | re-render a site from the current templates (apply fixes) |
| `scripts/setup-tls.sh` | HTTPS: self-signed or Let's Encrypt (+ auto-renew) |
| `scripts/export-site.sh` | export a site to a container bundle (compose + Kubernetes) |
| `scripts/scan-malware.sh` | YARA-X webshell/malware scan of a site's docroot |
| `scripts/probe-vhost.sh` / `deploy-test.sh` | isolation probe / deploy the PHP self-test page |
| `scripts/destroy-vhost.sh` | remove a site's config (keeps the data + database) |
| `scripts/audit-os.sh` · `scan-cve.sh` · `audit-cis.sh` | Lynis index · Trivy CVEs · OpenSCAP/CIS |
| `scripts/show-aa-denials.sh` · `add-aa-permit.sh` | soak workflow: list denials, grant one |
| `tools/hardening-check.php` · `hardening-report.php` | GUI/JSON hardening self-test (temporary / gated) |

## Documentation

- [`GUIDA.md`](GUIDA.md) — full operator guide (Italian): menu, install, tune, TLS, where data lives, troubleshooting
- [`example.md`](example.md) — menu-driven walkthrough from a clean VM to an enforced site (with a day-2 change), real screenshots
- [`dockerize.md`](dockerize.md) · [`docs/CONTAINERS.md`](docs/CONTAINERS.md) — containerize a site (compose + k8s)
- [`apache-php-hardening-runbook.md`](apache-php-hardening-runbook.md) — phased rationale
- [`PLAN.md`](PLAN.md) — build plan & test strategy · [`CLAUDE.md`](CLAUDE.md) — project context

## Security note

This is **authorized, defensive** security tooling (least privilege, sandboxing,
egress control, integrity monitoring). Review the scripts before running them on
your systems.
