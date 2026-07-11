# example.md — Walkthrough completo: da OS appena installato a due siti isolati in enforce

Esecuzione **reale**, comando per comando, su una VM Ubuntu 22.04 pulita: dal
sistema appena installato fino a due virtual host (`site1`, `site2`) — ciascuno
con proprio utente, pool PHP-FPM, hat AppArmor, catena di egress e database — in
AppArmor **enforce** e **mutuamente isolati**. Ogni passo mostra il comando, una
riga o due di spiegazione e l'output reale (ripulito dal rumore di `apt`).

| Parametro | Valore |
|---|---|
| **Host** | Ubuntu 22.04.5 LTS · nginx 1.18 · PHP 8.1-FPM · MariaDB 10.6 |
| **Utenti runtime** | `site1` (uid 997), `site2` (uid 996), entrambi nel gruppo `www-data` |
| **Punto di partenza** | snapshot `bare-ready`: OS + pacchetti base, **nessun hardening** |
| **Come si eseguono** | come utente sudo **sul server**; `~/hardening` = questo repo trasferito |

**Risultati misurati in questa run:** Lynis hardening index **65 → 83**
(65→73 controlli OS, 73→83 estensioni), Trivy **531 CVE** HIGH/CRITICAL,
OpenSCAP **CIS 70%**, matrice d'isolamento cross-site **tutta verde** nei due
versi.

## Indice

- [Cap. 0 — Punto di partenza (OS appena installato)](#cap-0--punto-di-partenza-os-appena-installato)
- [Cap. 1 — Misura di base (Lynis baseline)](#cap-1--misura-di-base-lynis-baseline)
- [Cap. 2 — Hardening del sistema operativo (`harden-os.sh`)](#cap-2--hardening-del-sistema-operativo-harden-ossh)
- [Cap. 3 — Verifica dell'hardening OS (Lynis 65 → 83)](#cap-3--verifica-dellhardening-os-lynis-65--83)
- [Cap. 4 — Primo virtual host: `site1`](#cap-4--primo-virtual-host-site1)
- [Cap. 5 — Secondo virtual host: `site2`](#cap-5--secondo-virtual-host-site2)
- [Cap. 6 — Da complain a enforce (`enforce-vhost.sh`)](#cap-6--da-complain-a-enforce-enforce-vhostsh)
- [Cap. 7 — HTTPS (`setup-tls.sh`)](#cap-7--https-setup-tlssh)
- [Cap. 8 — Prova d'isolamento (la matrice cross-site)](#cap-8--prova-disolamento-la-matrice-cross-site)
- [Cap. 9 — Altri assi di audit: CVE (Trivy) e CIS (OpenSCAP)](#cap-9--altri-assi-di-audit-cve-trivy-e-cis-openscap)
- [Cap. 10 — Operazioni day-2 (`tune-vhost`, denials)](#cap-10--operazioni-day-2-tune-vhost-denials)
- [Cap. 11 — Riepilogo](#cap-11--riepilogo)

---

## Cap. 0 — Punto di partenza (OS appena installato)

Verifico che il punto di partenza sia davvero pulito: solo il pool `www` di
default, firewall spento, nessuno stato di hardening. Poi trasferisco il repo.

```bash
$ lsb_release -d; uname -srm; nginx -v; php -v | head -1
Description:    Ubuntu 22.04.5 LTS
Linux 5.15.0-185-generic x86_64
nginx version: nginx/1.18.0 (Ubuntu)
PHP 8.1.2-1ubuntu2.24 (cli) (built: May 25 2026 15:08:06) (NTS)

$ systemctl is-active nginx mariadb ssh; ls /etc/php/8.1/fpm/pool.d/; df -h / | awk 'NR==2{print $2,$4}'
active            # nginx
active            # mariadb
active            # ssh
www.conf          # <- unico pool: una sola identità condivisa (il problema da risolvere)
4.7G 2.3G         # disco: 2.3G liberi
```

```bash
# dalla macchina di amministrazione: copia il repo sul server
$ tar czf - scripts templates config sites | ssh user@server \
    'mkdir -p ~/hardening && tar xzf - -C ~/hardening && chmod +x ~/hardening/scripts/*.sh'
```

> Lo stato iniziale è un classico server LAMP: **un'unica identità** (`www-data`)
> per tutti i siti. Tutto il resto del walkthrough serve a spezzare quell'identità
> per-sito e a contenere il raggio d'azione di una compromissione.

---

## Cap. 1 — Misura di base (Lynis baseline)

Prima di toccare qualcosa, misuro il livello di partenza con Lynis. Serve come
**baseline** per il confronto “prima/dopo”. È read-only.

```bash
$ sudo bash scripts/audit-os.sh --baseline
[*] installing lynis
    HARDENING INDEX : 65/100
    warnings        : 2
    suggestions     : 50
    full report     : /var/log/hardening-audit/lynis-baseline.txt
```

> Indice **65/100**: un Ubuntu server “nudo”. È il numero da battere.

---

## Cap. 2 — Hardening del sistema operativo (`harden-os.sh`)

Lo strato condiviso, **una volta per server**: baseline di nginx/PHP-FPM, UFW
default-deny + impalcatura egress, fail2ban, unattended-upgrades, auditd, AIDE,
profilo AppArmor **master**, sandbox systemd, sysctl, e i controlli OS
(login.defs, pam_pwquality, blacklist moduli, banner) più gli strumenti di
integrità/accounting. Nulla di specifico per sito.

```bash
$ sudo ASSUME_YES=1 SSH_HARDEN=yes bash scripts/harden-os.sh
[*] installing: certbot
    certbot.timer enabled (LE auto-renewal)
[*] nginx baseline            -> nginx config OK
[*] PHP-FPM baseline (PHP 8.1)
[*] AppArmor master profile
[*] UFW baseline + egress scaffolding
[*] auditd global rules
[*] AIDE
    unattended-upgrades enabled
[*] SSH hardening
[*] sysctl hardening
[*] OS baseline: login.defs, pam_pwquality, core dumps, module blacklist, banner
[*] OS baseline (extended): SSH hardening, integrity/accounting tools, compilers
    installed: debsums
    installed: libpam-tmpdir
    installed: apt-listchanges
    installed: apt-show-versions
    installed: sysstat
    installed: acct
    installed: rkhunter
[*] OS hardening complete. Measure with:  audit-os.sh --verify
```

L'hardening SSH usa un drop-in (`00-hardening.conf`) letto **prima** dei default
cloud-image, validato con `sshd -t` e applicato con un `reload` (le sessioni
attive non cadono). Verifico subito una connessione **nuova** — nessun lockout:

```bash
$ ssh user@server 'whoami; systemctl is-active ssh'
Authorized access only. All connections are monitored and logged.   # <- banner legale
manu
active
```

> Il firewall passa a **default-deny**, php-fpm gira sotto il profilo AppArmor
> **master** in complain, e l'egress è pronto ma ancora senza regole per-sito.

---

## Cap. 3 — Verifica dell'hardening OS (Lynis 65 → 83)

Rimisuro con Lynis: lo script calcola anche il **delta** rispetto al baseline.

```bash
$ sudo bash scripts/audit-os.sh --verify
    HARDENING INDEX : 83/100
    warnings        : 1
    suggestions     : 20
[*] delta vs baseline: 65 -> 83  (index change: 18)
```

> **65 → 83** (+18). Le voci ancora aperte richiedono scelte con impatto
> operativo (password GRUB, partizioni separate, porta SSH non standard) o
> infrastruttura esterna (syslog remoto): 83–84 è il tetto pratico “senza
> compromessi”. Il punteggio sale di un altro punto quando `sysstat` ha raccolto
> i primi dati. Lynis però **non misura** la cosa che conta di più qui —
> l'isolamento orizzontale — che si dimostra al [Cap. 8](#cap-8--prova-disolamento-la-matrice-cross-site).

---

## Cap. 4 — Primo virtual host: `site1`

Il setup **per sito**. Prima preparo docroot, database e alcuni file realistici
(una `configuration.php` con un “segreto”, un `SECRET.txt`), poi lancio
`harden-vhost.sh` leggendo le risposte da `sites/site1.env`.

```bash
$ sudo bash -c 'set -a; . sites/site1.env; set +a; bash scripts/harden-vhost.sh'
[*] Site 'site1' -> docroot /var/www/html/site1/public_html, runtime user site1 (PHP 8.1)
[*] created user site1
[*] added site1 to www-data (php-fpm restart applies it)
[*] Applying filesystem permission model
    creating declared writable dir: media
    creating declared writable dir: cache
    creating declared writable dir: administrator/cache
[*] Rendering PHP-FPM pool -> /etc/php/8.1/fpm/pool.d/site1.conf
    NOTICE: configuration file php-fpm.conf test is successful
[*] Rendering AppArmor child hat -> /etc/apparmor.d/php-fpm.d/site1
[*] Rendering nginx app snippet + HTTP server block
    nginx: configuration file test is successful
[*] Recording policy state and syncing open_basedir / hat / systemd / egress
[!] MAIL_HOST empty -> outbound SMTP not allowed for site1 (set it / use tune-vhost.sh)
[*] ufw reloaded
    auditd rule: execve by uid 997 keyed site1_exec
[*] vhost 'site1' hardened.
```

### 4.1 — Il modello “web_user”: il codice non è scrivibile dall'utente runtime

Il codice è di `www-data` (750/640); l'utente runtime `site1` lo legge **via
gruppo** e non possiede nulla. Le dir scrivibili sono `2770` **setgid**. La
`configuration.php` è `640` → sola lettura per il runtime.

```bash
$ sudo stat -c '%A  %U:%G  %n' public_html public_html/index.php public_html/configuration.php public_html/images
drwxr-x---  www-data:www-data  public_html                  # codice: gruppo r-x, altri nulla
-rw-r-----  www-data:www-data  public_html/index.php         # 640
-rw-r-----  www-data:www-data  public_html/configuration.php # 640 -> runtime NON riscrive path/credenziali
drwxrws---  www-data:www-data  public_html/images            # 2770 setgid -> scrivibile

$ sudo -u site1 bash -c 'test -w public_html/images && echo "images: WRITABLE (ok)";
                         test -w public_html/configuration.php || echo "configuration.php: read-only (ok)"'
images: WRITABLE (ok)
configuration.php: read-only (ok)
```

### 4.2 — Il pool PHP-FPM: i `php_admin_*` non sovrascrivibili

```bash
$ sudo grep -E 'group =|apparmor_hat|clear_env|limit_extensions|disable_functions|allow_url|open_basedir' \
       /etc/php/8.1/fpm/pool.d/site1.conf
group = site1
apparmor_hat = site1
clear_env                 = yes
security.limit_extensions = .php     ; FPM esegue SOLO *.php -> evil.jpg non parte
php_admin_value[disable_functions] = exec,passthru,shell_exec,system,proc_open,popen,pcntl_exec,...
php_admin_flag[allow_url_include] = off
php_admin_flag[allow_url_fopen]   = off
php_admin_value[open_basedir] = /var/www/html/site1/public_html/:.../images/:.../cache/:.../tmp/:...
```

### 4.3 — L'hat AppArmor: nessun `x` da nessuna parte

```bash
$ sudo sed -n '13,20p' /etc/apparmor.d/php-fpm.d/site1
profile site1 flags=(complain,attach_disconnected) {
  include <abstractions/base>
  include <abstractions/nameservice>
  include <abstractions/php>
  signal (receive) peer=php-fpm,
  /etc/php{,5,7,8}/** r,
  /var/www/html/site1/ r,
  ...                                  # NESSUNA regola con 'x' -> il worker non può eseguire binari
```

### 4.4 — La catena di egress per-uid

```bash
$ sudo grep -A8 'site1_EGRESS' /etc/ufw/before.rules
-A ufw-before-output -m owner --uid-owner 997 -j site1_EGRESS   # tutto l'uid 997 -> chain dedicata
-A site1_EGRESS -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
-A site1_EGRESS -o lo -j ACCEPT
-A site1_EGRESS -p udp --dport 53 -j ACCEPT                     # DNS
-A site1_EGRESS -p tcp --dport 53 -j ACCEPT
-A site1_EGRESS -p tcp -d 127.0.0.1 --dport 3306 -j ACCEPT      # DB
-A site1_EGRESS -p tcp --dport 443 -j ACCEPT                    # HTTPS
-A site1_EGRESS -m limit --limit 6/min -j LOG --log-prefix "site1_EGRESS-DROP "
-A site1_EGRESS -j REJECT --reject-with icmp-port-unreachable   # tutto il resto: NEGATO
```

> Quattro fatti di policy (permessi FS, pool, hat, egress) resi coerenti da un
> unico comando. Modificarli a mano è come si rompe l'isolamento — per questo
> esiste `tune-vhost.sh` ([Cap. 10](#cap-10--operazioni-day-2-tune-vhost-denials)).

---

## Cap. 5 — Secondo virtual host: `site2`

Identico, con un secondo utente/uid. Ora il server ospita due identità distinte.

```bash
$ sudo bash -c 'set -a; . sites/site2.env; set +a; bash scripts/harden-vhost.sh'
[*] Site 'site2' -> docroot /var/www/html/site2/public_html, runtime user site2 (PHP 8.1)
[*] created user site2
[*] Rendering PHP-FPM pool -> /etc/php/8.1/fpm/pool.d/site2.conf
[*] Rendering AppArmor child hat -> /etc/apparmor.d/php-fpm.d/site2
    auditd rule: execve by uid 996 keyed site2_exec
[*] vhost 'site2' hardened.
```

---

## Cap. 6 — Da complain a enforce (`enforce-vhost.sh`)

Ora che ci sono due pool, riavvio php-fpm e “scaldo” i siti (una richiesta fa
nascere il worker con l'hat attaccato). Poi passo l'hat da **complain** a
**enforce** con `enforce-vhost.sh`, che fa un health-check e in caso di rottura
**ritorna automaticamente a complain**.

```bash
$ sudo systemctl restart php8.1-fpm            # php8.1-fpm: active (ora ha 2 pool)
$ curl -s -o /dev/null -H 'Host: site1.local' http://127.0.0.1/index.php   # warm-up

$ sudo bash scripts/enforce-vhost.sh site1
[*] enforcing /etc/apparmor.d/php-fpm.d/site1
[*] enforce OK — worker: php-fpm//site1, health HTTP 200
[*] 'site1' is now ENFORCED. Verify:
    sudo aa-exec -p php-fpm//site1 -- /bin/sh -c 'wget -V'   # Permission denied
    revert with:  scripts/enforce-vhost.sh site1 --revert
```

I worker girano ora sotto i rispettivi hat in **enforce**:

```bash
$ ps -eZ | grep 'php-fpm//' | awk '{print $1, $NF}'
php-fpm//site1 php-fpm8.1
php-fpm//site2 php-fpm8.1

$ sudo aa-status | grep -E 'profiles are in (enforce|complain)'
37 profiles are in enforce mode.
3 profiles are in complain mode.
```

> Un hat figlio può essere in enforce mentre il master resta in complain: i flag
> AppArmor sono indipendenti. Così l'enforce è **per-sito** e sicuro. Per
> irrigidire anche il master condiviso: `enforce-vhost.sh site1 --with-master`
> (una volta sola, dopo il soak di tutti i siti).

---

## Cap. 7 — HTTPS (`setup-tls.sh`)

Abilito TLS per `site1`. In staging basta `--self-signed`; in produzione
`--letsencrypt --email ...` ottiene un certificato valido e installa il rinnovo.

```bash
$ sudo bash scripts/setup-tls.sh site1 --self-signed
[*] generating self-signed cert for site1.local (365d)
[*] rendering HTTPS server block -> /etc/nginx/sites-available/site1
[*] TLS enabled for 'site1' (self-signed).
    https://site1.local/    (HTTP now 301-redirects here)

$ curl -s -o /dev/null -w '%{http_code} -> %{redirect_url}\n' --resolve site1.local:80:127.0.0.1 http://site1.local/
301 -> https://site1.local/                       # HTTP reindirizza a HTTPS

$ curl -sk --resolve site1.local:443:127.0.0.1 https://site1.local/index.php
site=site1 ok
user=site1                                         # HTTPS serve l'app (200)
```

---

## Cap. 8 — Prova d'isolamento (la matrice cross-site)

Il cuore del progetto. Deposito nel docroot di `site1` una probe PHP servita da
nginx (gira quindi sotto il pool/hat/egress di `site1`) che **tenta di sfondare**
verso `site2` e verso l'host — questo è il percorso d'attacco realistico: una
webshell. Ogni chiave `*_denied` deve essere `PASS`; le capacità legittime del
sito (proprio DB, propria dir scrivibile) devono restare `PASS` anch'esse.

```bash
$ curl -sk "https://site1.local/probe.php?other=/var/www/html/site2&db_host=127.0.0.1&db_user=site1&db_pass=site1pass&db_name=site1db"
xsite_read_config=PASS      # leggere la configuration.php di site2 -> NEGATO
xsite_list_dir=PASS         # elencare il docroot di site2         -> NEGATO
xsite_read_secret=PASS      # leggere il SECRET.txt di site2        -> NEGATO
xsite_write=PASS            # scrivere in site2/images              -> NEGATO
read_etc_shadow=PASS        # leggere /etc/shadow                   -> NEGATO
exec_denied=PASS            # exec('id')                            -> NEGATO
shell_spawn_denied=PASS     # proc_open('/bin/sh')                  -> NEGATO
egress_80_denied=PASS       # connessione uscente a 1.1.1.1:80      -> NEGATO
own_write_ok=PASS           # scrivere nella PROPRIA images/        -> OK
own_db_connect=PASS         # connettersi al PROPRIO DB             -> OK
db_server=5.5.5-10.6.23-MariaDB
egress_443_allowed=PASS     # 443 in allow-list                    -> OK
whoami=site1
open_basedir=/var/www/html/site1/public_html/:...   # ristretto SOLO a site1
```

Simmetrico nell'altro verso (`site2` → `site1`):

```bash
$ curl -sk "https://site2.local/probe.php?other=/var/www/html/site1&db_user=site2&db_pass=site2pass&db_name=site2db"
xsite_read_config=PASS  xsite_list_dir=PASS  xsite_read_secret=PASS  xsite_write=PASS
exec_denied=PASS  shell_spawn_denied=PASS  egress_80_denied=PASS  own_db_connect=PASS
whoami=site2
```

> Una compromissione di `site1` **non** può leggere, scrivere o eseguire dentro
> `site2` o l'host, non può ottenere una shell, non può telefonare a casa. Ma il
> sito funziona: raggiunge il proprio DB e scrive nelle proprie cartelle. Questo,
> non l'indice Lynis, è ciò che il progetto garantisce.

### 8.1 — Nota onesta: il residuo a livello DAC (e perché non conta)

Con `WEB_USER=www-data`, `site1` e `site2` **condividono il gruppo** `www-data`.
A puro livello DAC (Unix), quindi, una *shell* come `site1` potrebbe leggere il
codice di `site2` tramite il gruppo:

```bash
$ sudo -u site1 cat /var/www/html/site2/public_html/configuration.php
DB_PASSWORD_OF_site2=site2pass   # <- a livello DAC il gruppo www-data lo consente
```

Perché allora la matrice sopra è tutta `PASS`? Perché il percorso d'attacco
reale — una webshell — **non arriva mai** a quel `cat`:

1. Il worker PHP gira sotto **`open_basedir`** ristretto a `site1` → non può
   nemmeno *nominare* i path di `site2` (bloccato prima del DAC).
2. **AppArmor no-exec** → non si può ottenere una shell come `site1` per sfruttare
   il DAC.

L'isolamento efficace regge quindi su open_basedir + no-exec (difesa in
profondità), **non** sulla separazione DAC. Se serve isolare anche a livello DAC
— utile in ambienti multi-tenant non fidati — si imposta un **gruppo proprietario
per-sito** al posto di `www-data` (parametro `WEB_USER`), così `site1` non è più
membro del gruppo di `site2`.

---

## Cap. 9 — Altri assi di audit: CVE (Trivy) e CIS (OpenSCAP)

L'hardening di configurazione è un asse; “sei patchato?” e “sei conforme a CIS?”
sono altri due, complementari.

```bash
$ sudo bash scripts/scan-cve.sh                 # Trivy: CVE dei pacchetti installati
[*] scanning installed packages for CVEs (severity: HIGH,CRITICAL)
[*] CVE summary:
    Total: 531 (HIGH: 510, CRITICAL: 21)
    remediation = apply security updates:  apt-get update && apt-get upgrade
```

```bash
$ sudo bash scripts/audit-cis.sh                # OpenSCAP: benchmark CIS level1_server
[*] OpenSCAP eval — profile: cis_level1_server  (datastream: ssg-ubuntu2204-ds.xml)
[*] ===== CIS (cis_level1_server) =====
    pass  : 168
    fail  : 71
    score : 70%
    report: /var/log/hardening-audit/cis-report.html
```

> I 531 CVE sono il **debito di patch** dell'immagine (si chiude con
> `apt upgrade`; `unattended-upgrades` è attivo). Il 70% CIS è l'asse di
> conformità, separato dall'indice Lynis.

---

## Cap. 10 — Operazioni day-2 (`tune-vhost`, denials)

Quando la policy di un sito deve cambiare, `tune-vhost.sh` è l'unico strumento
che tocca **tutti i punti coordinati insieme** e ricarica i servizi giusti.

```bash
# aprire una destinazione di egress (relay mail) — aggiorna la chain del sito
$ sudo bash scripts/tune-vhost.sh site1 allow 10.0.0.5 587
[*] allow egress for site1: -p tcp -d 10.0.0.5 --dport 587 (v4)
[*] ufw reloaded
$ sudo grep 10.0.0.5 /etc/ufw/before.rules
-A site1_EGRESS -p tcp -d 10.0.0.5 --dport 587 -j ACCEPT

# concedere una dir scrivibile condivisa — pool + AppArmor + systemd IN SYNC
$ sudo bash scripts/tune-vhost.sh site1 grant-write /srv/site1-shared
[*] grant rw '/srv/site1-shared' to site1 (pool open_basedir + AppArmor hat + systemd RWP)
[*] done.
```

Durante il soak, `show-aa-denials.sh` elenca i dinieghi per utente. Genero un
diniego reale con il test canonico (un exec sotto l'hat) e lo osservo:

```bash
$ sudo aa-exec -p php-fpm//site1 -- /bin/sh -c 'wget -V'
/bin/sh: 1: wget: Permission denied           # <- la garanzia "no exec", diretta

$ sudo bash scripts/show-aa-denials.sh site1
ID  COUNT  KIND        PERM  TARGET
--- -----  ----------- ----- ----------------------------------
1   2      exec        x     /usr/bin/wget
    saved: /etc/hardening/sites/site1/denials.tsv

$ sudo bash scripts/add-aa-permit.sh site1 1
[x] denial #1 is an EXEC permit (/usr/bin/wget).
[x] granting exec defeats the per-pool no-exec model. If you REALLY must, re-run with --force.
```

> `add-aa-permit.sh` concede un diniego **non-exec** in un comando; per un exec
> pretende `--force` ed è sconsigliato — non si buca da soli il modello no-exec.

---

## Cap. 11 — Riepilogo

Partiti da un Ubuntu 22.04 “nudo”, in una manciata di comandi:

| Controllo | Prima | Dopo |
|---|---|---|
| Identità | 1 (`www-data` condivisa) | 1 utente + pool + hat **per sito** |
| Codice scrivibile dal runtime | sì | **no** (modello web_user) |
| Esecuzione binari dal worker | sì | **no** (hat AppArmor, nessun `x`) |
| Egress | libero | **allow-list per-uid** (DNS/DB/mail/443) |
| AppArmor | assente | **enforce** per-sito |
| Lynis hardening index | 65 | **83** |
| CIS (OpenSCAP level1) | — | **70%** |
| Patch (Trivy HIGH/CRITICAL) | — | **531 CVE** noti → `apt upgrade` |
| Isolamento cross-site (via web) | — | **verde nei due versi** |

**La garanzia:** compromettere un sito non dà accesso agli altri né all'host —
niente lettura/scrittura/esecuzione trasversale via il percorso d'attacco reale
(webshell), niente shell, niente call-home. Verificato end-to-end; l'harness
ripetibile è [`test/tier2-e2e.sh`](test/tier2-e2e.sh).

Vedi [`GUIDA.md`](GUIDA.md) per install, tuning, TLS, log e troubleshooting.
