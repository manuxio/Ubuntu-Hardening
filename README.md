# Ubuntu Hardening

Replicable, **defensive** hardening for an Ubuntu server that hosts **several PHP
virtual hosts** (Joomla / WordPress and similar) behind **nginx + PHP-FPM**. The
goal is to limit **horizontal blast radius**: a compromise of one site cannot
read, write, or execute across the others, and post-exploitation moves (dropping
a webshell, pulling a payload, spawning a shell, phoning home) are prevented,
contained, and detected.

Verified end-to-end on a real Ubuntu 22.04 VM: two isolated sites under AppArmor
**enforce**, a 32/32-green cross-site isolation matrix (`test/tier2-e2e.sh`), and
a Lynis hardening index raised **65 → 84** — plus config/filesystem/PHP checks in
ephemeral Docker.

> 📖 **Full operator guide (Italian):** [`GUIDA.md`](GUIDA.md) ·
> 🧪 **Complete walkthrough with real outputs:** [`example.md`](example.md)

---

## What it sets up (defence in depth)

| Layer | Control |
|---|---|
| Identity | one Unix user + PHP-FPM pool **per site** |
| Filesystem | code **not writable** by the runtime user; setgid writable dirs; `configuration.php` read-only |
| PHP pool | `open_basedir`, `security.limit_extensions=.php`, `disable_functions`, `allow_url_*=off` (all `php_admin_*`) |
| AppArmor | per-pool **hat** (`php-fpm//<site>`) that grants **no exec** anywhere |
| systemd | sandbox (`ProtectSystem=strict`, `ReadWritePaths`, `PrivateTmp`, cgroup caps) |
| Network | **egress firewall by uid** (ufw) — allow only DNS/DB/mail/443 |
| Detection | auditd (webroot writes + per-site `execve`), AIDE |
| Web | nginx script-must-exist, PHP-off in upload dirs, per-site logs, **TLS** |
| Perimeter | UFW default-deny, fail2ban, unattended-upgrades, sysctl |

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

## Quick start (on the server)

> **Prefer a menu?** `sudo bash scripts/harden-menu.sh` opens a small
> whiptail TUI that drives every step below (audit, harden OS, add a site,
> enforce, TLS, tune, run the E2E test) — no commands to memorise.

```bash
# 0) copy this repo to the server (e.g. rsync/scp/tar), then cd into it

# 1) OS layer — run ONCE per server
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

Measure it (optional but recommended — run `audit-os.sh --baseline` *before* step 1
to compare):

```bash
sudo bash scripts/audit-os.sh --verify     # Lynis hardening index (measured 65 -> 84)
sudo bash scripts/scan-cve.sh              # Trivy: CVEs in installed packages
sudo bash scripts/audit-cis.sh             # OpenSCAP: CIS benchmark score + HTML report
```

Repeat step 2–4 for each site. Everything is **interactive with sensible
defaults** and **env-overridable** (pre-seed a `sites/<name>.env`), **idempotent**,
and prints the verification commands at the end. See [`example.md`](example.md)
for a full two-site run with real command output.

## Day-2 operations

```bash
sudo bash scripts/tune-vhost.sh   site1 allow 10.0.0.5 587      # open an egress destination
sudo bash scripts/tune-vhost.sh   site1 grant-write /srv/shared  # pool + AppArmor + systemd, in sync
sudo bash scripts/show-aa-denials.sh site1                       # list AppArmor denials to resolve
sudo bash scripts/add-aa-permit.sh   site1 <id>                  # grant one (exec refused by default)
```

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
cross-site isolation (site1's pool trying to read/write/exec into site2 and the
host — every attempt denied, both directions):

```bash
# on a throwaway VM that already has scripts/harden-os.sh applied, run as root:
sudo bash test/tier2-e2e.sh        # 32 assertions incl. the isolation matrix
```

See [`PLAN.md`](PLAN.md) §Test.

## Scripts

| Script | Purpose |
|---|---|
| `scripts/harden-menu.sh` | **interactive whiptail menu** that drives all the scripts below |
| `scripts/harden-os.sh` | server-wide layer (once) |
| `scripts/harden-vhost.sh` | per-site setup (user, pool, hat, nginx, egress, auditd) |
| `scripts/enforce-vhost.sh` | complain → enforce, with soak check + auto-rollback |
| `scripts/setup-tls.sh` | HTTPS: self-signed or Let's Encrypt (+ auto-renew) |
| `scripts/tune-vhost.sh` | day-2 policy (egress / reach dirs / limits), kept in sync |
| `scripts/audit-os.sh` | Lynis audit + hardening index (baseline/verify bracket) |
| `scripts/scan-cve.sh` | Trivy — CVE scan of installed packages (patching axis) |
| `scripts/audit-cis.sh` | OpenSCAP — CIS benchmark evaluation (+ opt-in remediate) |
| `scripts/show-aa-denials.sh` + `add-aa-permit.sh` | soak workflow: list denials, grant one |
| `tools/hardening-check.php` / `hardening-report.php` | GUI/JSON hardening self-test (temporary / gated) |

## Documentation

- [`GUIDA.md`](GUIDA.md) — full operator guide (Italian): install, tune, TLS, logs, troubleshooting
- [`example.md`](example.md) — 2 users / 2 docroots, from a clean VM to enforced isolation, real outputs
- [`apache-php-hardening-runbook.md`](apache-php-hardening-runbook.md) — phased rationale
- [`PLAN.md`](PLAN.md) — build plan & test strategy · [`CLAUDE.md`](CLAUDE.md) — project context

## Security note

This is **authorized, defensive** security tooling (least privilege, sandboxing,
egress control, integrity monitoring). Review the scripts before running them on
your systems.
