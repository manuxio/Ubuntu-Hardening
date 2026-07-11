# Ephemeral test harness

Fast, replicable validation of the hardening scripts in throwaway Docker
containers. The scripts are **bind-mounted** from the host (they live in the
repo, not the image) so every run starts clean.

## Tier 1 (implemented, green)

**Linux / macOS / Git-Bash:**

```bash
bash test/run-tests.sh
```

**Windows PowerShell** (use this if `bash` on your host routes to a broken WSL
stub — `execvpe(/bin/bash) failed`). No host bash is needed; bash only runs
inside the container:

```powershell
powershell -ExecutionPolicy Bypass -File test\run-tests.ps1
```

> `test/in-container.sh` is the *inside-the-container* script — never run it on
> the host. The runners above hand it to `bash` **inside** the container.

### Interactive shell (poke around by hand)

```powershell
# build once
docker build -t ubuntu-harden-tier1 -f test/Dockerfile.tier1 test/
# open a shell in an ephemeral container with the repo mounted
docker run --rm -it -v "${PWD}:/work" -w /work ubuntu-harden-tier1 bash
```

Then inside the container:

```bash
bash test/in-container.sh          # full setup + checks, then stay in the shell
# or inspect the generated (but not-activated) configs:
cat /etc/php/8.1/fpm/pool.d/web_user.conf
cat /etc/apparmor.d/php-fpm.d/web_user
iptables-restore --test < /etc/ufw/before.rules && echo "egress rules parse OK"
```

What it does:

1. Builds `ubuntu-harden-tier1` from `Dockerfile.tier1` — Ubuntu 22.04 with
   nginx + PHP 8.1-FPM + AppArmor userspace + auditd/ufw/aide **pre-baked** so
   runs are fast and offline (~414 MB, built once and cached).
2. Starts a small **ephemeral MariaDB** (`mariadb:11.4`, the usual
   Joomla/WordPress DB) on a throwaway network; removed on exit.
3. Runs `in-container.sh`, which builds a throwaway Joomla-ish docroot, runs
   `harden-os.sh` + `harden-vhost.sh` (from `../sites/web_user.env`, non-interactive),
   starts php-fpm + nginx by hand, and runs the `checks/`:
   - `fs-model.sh` — the web_user permission model (code read-only to runtime user,
     setgid writable dirs, config 640, www-data traversal).
   - `php-behavior.sh` — live php-fpm hardening via nginx: open_basedir,
     disable_functions, code-write-denied/data-write-ok, script-must-exist (404),
     PHP-off-in-uploads (403), inert static serving, **+ live MariaDB connect**.
   - `idempotency.sh` — re-run is byte-identical; `tune-vhost.sh grant-write`
     lands in pool + AppArmor hat + systemd RWP together.

Everything is `--rm` / torn down on exit. Exit code 0 = all checks passed.

## What Tier 1 can't cover (needs Tier 2 / a VM)

Kernel/PID-1-dependent layers: AppArmor **enforcement** (`php-fpm//<site>`),
auditd capture, systemd sandbox, and ufw egress. In a container the scripts
**write** those configs (inspect them under `/etc/…`) but skip live activation
(`CONTAINER=1`). Tier 2 (a privileged `systemd`-init image) and a real VM cover
the rest — see `../PLAN.md` §Test harness.

## Requirements

Docker with a Linux engine (Docker Desktop on Windows works; `run-tests.sh`
handles the Git-Bash mount-path translation). First run pulls `mariadb:11.4`.
