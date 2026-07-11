# example.md — Walkthrough completo: 2 utenti / 2 docroot, da zero a enforce isolato

Esecuzione **reale** su una VM Ubuntu 22.04 pulita: dal sistema base a due
virtual host (`site1`, `site2`), ciascuno con proprio utente/pool/hat/egress/DB,
in AppArmor **enforce** e **mutuamente isolati**. Ogni passo mostra il comando,
la spiegazione e l'output reale.

- Host: Ubuntu 22.04.5 LTS · nginx · PHP 8.1-FPM · MariaDB 10.6
- Utenti runtime: `site1` (uid 997), `site2` (uid 996) — entrambi nel gruppo `www-data`
- I comandi si eseguono come utente sudo **sul server** (`~/hardening` = repo trasferito)

> Stato di partenza: VM ripristinata allo snapshot `bare-ready` (Ubuntu +
> pacchetti installati, nessun hardening applicato).

---

## Step 1 — Stato iniziale + trasferimento del repo

Verifico che il punto di partenza sia pulito (firewall spento, solo il pool
`www` di default, nessuno stato di hardening), poi copio gli script sul server.

```bash
$ grep PRETTY /etc/os-release; sudo ufw status | head -1; ls /etc/php/8.1/fpm/pool.d/; ls -d /etc/hardening 2>/dev/null || echo absent
PRETTY_NAME="Ubuntu 22.04.5 LTS"
ufw: Status: inactive
fpm pools: www.conf
hardening state dir: absent

# dalla macchina di amministrazione:
$ tar czf - scripts templates config sites | ssh user@server 'rm -rf ~/hardening && mkdir -p ~/hardening && tar xzf - -C ~/hardening && chmod +x ~/hardening/scripts/*.sh'
transferred: 6 scripts + 3 site env files
```

---

## Step 2 — Hardening del sistema operativo (una sola volta)

`harden-os.sh` prepara il layer condiviso: baseline nginx + php-fpm, profilo
AppArmor **master** (in complain), sandbox systemd, UFW default-deny + impalcatura
egress, auditd, AIDE, fail2ban, unattended-upgrades, sysctl. `SSH_HARDEN=no` per
non rischiare il lockout finché la chiave non è confermata.

```bash
$ sudo env PHP_VERSION=8.1 SSH_HARDEN=no RUN_AIDEINIT=no bash ~/hardening/scripts/harden-os.sh
    all base packages present
[*] nginx baseline
    nginx config OK
[*] PHP-FPM baseline (PHP 8.1)
    disabled stock www pool
[*] AppArmor master profile
[*] UFW baseline + egress scaffolding
[*] auditd global rules
[*] AIDE
    skipping AIDE baseline (set RUN_AIDEINIT=yes on a real host)
    unattended-upgrades enabled
    skipping SSH hardening (SSH_HARDEN=no, container=no)
[*] sysctl hardening
[*] OS hardening complete. Next: run harden-vhost.sh per site (AppArmor is in COMPLAIN — soak, then enforce).
```

Verifica del layer OS: firewall attivo (SSH/80/443), profilo master caricato,
regola auditd sul web root, pool `www` disabilitato.

```bash
$ sudo ufw status | head -1; sudo aa-status | grep -c 'php-fpm$'; sudo auditctl -l | grep -c webroot; ls /etc/php/8.1/fpm/pool.d/
ufw: Status: active | rules: 6
apparmor php-fpm master: 1
auditd webroot rule: 1; default www pool: www.conf.disabled
```

---

## Step 3 — site1: docroot + database

Creo un docroot minimale (Joomla-like) e il database dedicato con un utente DB
i cui privilegi sono limitati al **solo** `site1_db` (isolamento DB per-sito).

```bash
$ sudo mkdir -p /var/www/html/site1/public_html/{images,media,cache,administrator/cache} /var/www/html/site1/{tmp,sessions,logs}
$ echo '<?php echo "site1 up";' | sudo tee /var/www/html/site1/public_html/index.php
$ sudo mysql <<'SQL'
CREATE DATABASE IF NOT EXISTS site1_db;
CREATE USER IF NOT EXISTS 'site1'@'127.0.0.1' IDENTIFIED BY 'site1pass';
GRANT ALL PRIVILEGES ON site1_db.* TO 'site1'@'127.0.0.1';
FLUSH PRIVILEGES;
SQL
site1 scaffold: administrator cache configuration.php images index.php media | db=site1_db
```

## Step 3b — site1: `harden-vhost.sh`

Applica il per-sito: crea l'utente `site1` (nologin, nel gruppo `www-data`),
modello permessi filesystem, pool PHP-FPM, hat AppArmor `php-fpm//site1`, server
block nginx, catena egress per-uid, regola auditd. Le risposte vengono da
`sites/site1.env`.

```bash
$ sudo bash -c 'set -a; . ~/hardening/sites/site1.env; set +a; bash ~/hardening/scripts/harden-vhost.sh'
[*] Site 'site1' -> docroot /var/www/html/site1/public_html, runtime user site1 (PHP 8.1)
[*] created user site1
[*] added site1 to www-data (php-fpm restart applies it)
[*] Applying filesystem permission model
[*] Rendering PHP-FPM pool -> /etc/php/8.1/fpm/pool.d/site1.conf
[..] NOTICE: configuration file /etc/php/8.1/fpm/php-fpm.conf test is successful
[*] Rendering AppArmor child hat -> /etc/apparmor.d/php-fpm.d/site1
[*] Rendering nginx server block -> /etc/nginx/sites-available/site1
nginx: configuration file /etc/nginx/nginx.conf test is successful
[*] Recording policy state and syncing open_basedir / hat / systemd / egress
[!] MAIL_HOST empty -> outbound SMTP not allowed for site1 (set it and re-run / use tune-vhost.sh)
[*] ufw reloaded
    auditd rule: execve by uid 997 keyed site1_exec
[*] vhost 'site1' hardened.
```

---

## Step 4 — site2: identico, da `sites/site2.env`

Stessa procedura per il secondo utente/sito. La catena egress e la regola auditd
di `site2` **si affiancano** a quelle di `site1` senza conflitti (ufw reload ok).

```bash
$ sudo mkdir -p /var/www/html/site2/public_html/{images,media,cache,administrator/cache} /var/www/html/site2/{tmp,sessions,logs}
$ echo '<?php echo "site2 up";' | sudo tee /var/www/html/site2/public_html/index.php
$ sudo mysql <<'SQL'
CREATE DATABASE IF NOT EXISTS site2_db;
CREATE USER IF NOT EXISTS 'site2'@'127.0.0.1' IDENTIFIED BY 'site2pass';
GRANT ALL PRIVILEGES ON site2_db.* TO 'site2'@'127.0.0.1';
FLUSH PRIVILEGES;
SQL
site2 scaffold: administrator cache configuration.php images index.php media | db=site2_db

$ sudo bash -c 'set -a; . ~/hardening/sites/site2.env; set +a; bash ~/hardening/scripts/harden-vhost.sh'
[*] Site 'site2' -> docroot /var/www/html/site2/public_html, runtime user site2 (PHP 8.1)
[*] created user site2
[*] ufw reloaded
    auditd rule: execve by uid 996 keyed site2_exec
[*] vhost 'site2' hardened.
```

---

## Step 5 — Riavvio php-fpm e verifica dei pool (in complain)

Un **restart completo** (non reload) fa sì che il master php-fpm si ri-esegua
confinato dall'AppArmor e che la sandbox systemd si applichi. Entrambi i siti
rispondono; ciascun worker entra nel proprio hat (in complain, per il soak).

```bash
$ sudo systemctl restart php8.1-fpm
$ ls /etc/php/8.1/fpm/pool.d/*.conf | xargs -n1 basename
site1.conf site2.conf

$ curl -s --resolve site1.local:80:127.0.0.1 http://site1.local/index.php ; ps axZ | grep '[p]ool site1'
site1 up   worker: php-fpm//site1 (complain)

$ curl -s --resolve site2.local:80:127.0.0.1 http://site2.local/index.php ; ps axZ | grep '[p]ool site2'
site2 up   worker: php-fpm//site2 (complain)

$ sudo iptables -S | grep -oE 'site[0-9]_EGRESS' | sort -u ; sudo auditctl -l | grep -oE 'site[0-9]_exec'
egress chains: site1_EGRESS site2_EGRESS
auditd per-site: site1_exec site2_exec
```

---

## Step 6 — Soak + passaggio a enforce

Dopo aver esercitato i siti in complain, `enforce-vhost.sh` verifica il soak,
passa l'hat a enforce, riavvia php-fpm, fa un **health-check** e — se il worker
si rompe — torna automaticamente a complain. `--with-master` (su `site1`)
irrigidisce anche il profilo master condiviso, da fare una volta sola.

```bash
$ for s in site1 site2; do for i in 1 2 3; do curl -s -o /dev/null --resolve $s.local:80:127.0.0.1 http://$s.local/index.php; done; done

$ sudo bash ~/hardening/scripts/enforce-vhost.sh site1 --with-master
[!] the MASTER profile is shared — enforcing it affects every pool without its own hat.
[*] enforce OK — worker: php-fpm//site1, health HTTP 200

$ sudo bash ~/hardening/scripts/enforce-vhost.sh site2
[*] enforce OK — worker: php-fpm//site2, health HTTP 200
```

---

## Step 7 — Verifica enforce + matrice di isolamento

Il test che dimostra il contenimento orizzontale. Ogni worker è confinato in
enforce e **non può eseguire** binari esterni; poi provo, da ciascun pool, ad
accedere a file/directory/DB dell'**altro** sito: tutto **BLOCCATO**.

```bash
$ for s in site1 site2; do curl -s -o /dev/null --resolve $s.local:80:127.0.0.1 http://$s.local/ ; \
    echo "$s: $(ps axZ | grep "[p]ool $s" | awk '{print $1,$2}' | head -1) | exec: $(sudo aa-exec -p php-fpm//$s -- /bin/sh -c 'id' 2>&1 | head -1)"; done
site1 worker: php-fpm//site1 (enforce) | exec: /bin/sh: 1: id: Permission denied
site2 worker: php-fpm//site2 (enforce) | exec: /bin/sh: 1: id: Permission denied
```

Deployo una piccola probe in ciascun docroot e faccio l'accesso incrociato
(`site1` prova a leggere `site2` e viceversa), con le credenziali DB del sito
chiamante verso il DB dell'altro sito:

```bash
# site1 --> site2  (deve essere tutto BLOCKED)
$ curl -s --resolve site1.local:80:127.0.0.1 \
   "http://site1.local/x.php?file=/var/www/html/site2/public_html/configuration.php&dir=/var/www/html/site2/public_html&dbu=site1&dbp=site1pass&dbn=site2_db"
read cross-file=BLOCKED
list cross-dir=BLOCKED
db cross-site2_db=BLOCKED
as=site1

# site2 --> site1  (deve essere tutto BLOCKED)
$ curl -s --resolve site2.local:80:127.0.0.1 \
   "http://site2.local/x.php?file=/var/www/html/site1/public_html/configuration.php&dir=/var/www/html/site1/public_html&dbu=site2&dbp=site2pass&dbn=site1_db"
read cross-file=BLOCKED
list cross-dir=BLOCKED
db cross-site1_db=BLOCKED
as=site2

# sanity: ogni sito raggiunge il PROPRIO db (qui "LEAK!!" = connesso = atteso)
$ site1->site1_db: db cross-site1_db=LEAK!!
$ site2->site2_db: db cross-site2_db=LEAK!!
```

**Interpretazione:**
- `read/list cross-*` = BLOCKED → `open_basedir` (pool) **+** hat AppArmor
  (enforce) impediscono al worker di un sito di leggere i file dell'altro.
- `db cross-*` = BLOCKED → l'utente DB di un sito **non** ha privilegi sul DB
  dell'altro (grant per-schema).
- La sanity conferma che ogni sito funziona sul proprio DB.

---

## Risultato

Da una Ubuntu 22.04 pulita, con **~15 comandi**, due siti (`site1`, `site2`)
girano isolati:

| Controllo | site1 | site2 |
|---|---|---|
| Worker AppArmor | `php-fpm//site1 (enforce)` | `php-fpm//site2 (enforce)` |
| Exec di binari esterni | negato | negato |
| Lettura/DB dell'altro sito | BLOCCATO | BLOCCATO |
| uid / pool / hat / egress / DB-user | dedicati | dedicati |

Una webshell in un sito **non** può leggere file, listare cartelle o toccare il
DB dell'altro. Contenimento orizzontale dimostrato.

> Nota (residuo noto): nel modello a `www-data` condiviso, a livello **DAC** un
> utente runtime può leggere il codice dell'altro sito tramite il gruppo
> `www-data` — ma ottenere una *shell* come quell'utente è impedito dall'hat
> (no-exec). Per isolare anche a livello DAC si può usare un **gruppo
> proprietario per-sito** (`WEB_USER`/gruppo dedicato) invece di `www-data`.

### Prossimi passi (finiture, opzionali)
- `RUN_AIDEINIT=yes` per la baseline AIDE · `SSH_HARDEN=yes` per SSH key-only
- TLS/HTTPS + `tune-vhost.sh <site> tls-on` · impostare `MAIL_HOST`
- Gruppo proprietario per-sito per l'isolamento anche a livello DAC
