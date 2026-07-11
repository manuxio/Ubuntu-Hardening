# Guida utente — Hardening Ubuntu multi-sito (nginx + PHP-FPM)

Guida operativa in italiano per installare, testare e gestire l'hardening di un
server Ubuntu che ospita più siti PHP (Joomla, WordPress e simili) dietro
**nginx + PHP-FPM**.

> Documentazione collegata: `README.md` (avvio rapido), `CLAUDE.md` (contesto
> tecnico), `PLAN.md` (piano di build e strategia di test),
> `apache-php-hardening-runbook.md` (razionale completo per fasi).

---

## 1. A cosa serve

L'obiettivo è **contenere il raggio d'impatto orizzontale**: la compromissione
di un sito non deve permettere di leggere, scrivere o eseguire codice sugli
altri siti, e le mosse post-exploitation tipiche (drop di una webshell,
download di un payload, apertura di una shell, connessioni in uscita verso
l'esterno) devono essere **prevenute, contenute e rilevate**.

Il principio è la **difesa a più livelli**: ogni layer presume che quello
precedente possa fallire.

---

## 2. Architettura: tre script

Il server ospita più virtual host, quindi le responsabilità sono divise per
ciclo di vita:

| Script | Quando si esegue | Cosa fa |
|---|---|---|
| `scripts/harden-os.sh` | **una volta per server** | Layer condiviso: baseline nginx + php-fpm, profilo AppArmor **master**, sandbox systemd di default, UFW default-deny + impalcatura egress, auditd, AIDE, fail2ban, unattended-upgrades, SSH, sysctl. |
| `scripts/harden-vhost.sh` | **una volta per sito** | Setup del sito: utente runtime, pool PHP-FPM, modello permessi filesystem, **hat** AppArmor per-pool, server block nginx, catena egress per-uid, regola auditd per-sito. |
| `scripts/tune-vhost.sh` | **day-2, ad ogni modifica** | Modifica la policy di un sito già configurato: host/porte raggiungibili (egress), cartelle leggibili/scrivibili, limiti pool/cgroup. |
| `scripts/enforce-vhost.sh` | **dopo il soak** | Passa l'AppArmor del sito da complain a **enforce** in sicurezza (controllo soak, health-check, **rollback automatico** in caso di errore); supporta `--revert`. |

Ordine di esecuzione: prima `harden-os.sh`, poi `harden-vhost.sh` per ogni sito,
poi il rodaggio in complain, quindi `enforce-vhost.sh` per attivare l'enforce;
`tune-vhost.sh` quando serve cambiare una policy.

### 2.1 Il principio di sincronizzazione (perché esiste `tune-vhost.sh`)

Un singolo fatto di policy è applicato in **più file contemporaneamente**, che
devono restare coerenti:

- **"l'utente runtime può scrivere nella cartella X"** = `open_basedir` del pool
  **+** hat AppArmor (`X/ rw, X/** rwk,`) **+** `ReadWritePaths` di systemd.
- **"l'utente runtime può raggiungere host:porta"** = una regola nella catena
  `<SITE>_EGRESS` in `/etc/ufw/before.rules` (+ `before6.rules`).

Modificarli a mano è la causa principale dei malfunzionamenti. `tune-vhost.sh`
è l'unico strumento che cambia **tutti i punti coinvolti in modo atomico**,
valida, ricarica i servizi giusti e mantiene la coerenza.

---

## 3. Il modello di identità

> **Due identità distinte — da non confondere:**
> - **`web_user`** = l'utente **runtime** del sito (PHP-FPM). È solo il nome di
>   esempio: va rinominato per ogni sito (variabile `RUNTIME_USER`).
> - **`www-data`** = il proprietario del **codice** e l'identità di nginx/FTP
>   (variabile `WEB_USER`). L'utente runtime raggiunge il codice *tramite questo
>   gruppo*.

La causa dell'esposizione orizzontale è avere un'unica identità (`www-data`) su
un filesystem scrivibile da quell'identità. La soluzione è **un uid per sito +
codice non scrivibile dall'utente runtime**:

- **Codice** di proprietà `www-data:www-data`, cartelle `750` / file `640`.
  L'utente runtime (es. `web_user`) accede al codice **in sola lettura tramite il
  gruppo `www-data`** — non possiede nulla, ed è intenzionale.
- **Cartelle scrivibili a runtime** (es. Joomla `images/ media/ cache/
  administrator/cache/`, più tmp/log/sessioni fuori dal docroot) sono `2770` /
  `660`. Il bit **setgid** forza il gruppo `www-data` sui nuovi file, così sia
  `web_user` (php-fpm) sia `ftp_user` continuano a gestirsi i file a vicenda.
- **`configuration.php` è `640`** — sola lettura per l'utente runtime, così una
  compromissione non può riscrivere percorsi/credenziali. Il salvataggio della
  Global Configuration dall'admin che fallisce è *voluto*.
- Due impostazioni lo rendono solido: **`UMask=0007`** su php-fpm (i file creati
  da web_user restano scrivibili dal gruppo) e **umask FTP `027`** (blocca il
  codice). Regola operativa: caricare il codice via FTP, gestire i media dal
  Media Manager dell'applicazione.

---

## 4. Prerequisiti

- **Ubuntu 22.04 LTS** (fornisce PHP 8.1 di default — allineato al box di
  riferimento). Su 24.04 usare `PHP_VERSION=8.3`.
- **PHP-FPM compilato con supporto AppArmor** (`apparmor_hat`). Verifica:
  `ldd /usr/sbin/php-fpm8.1 | grep apparmor` → deve comparire `libapparmor`.
- **AppArmor abilitato**: `cat /sys/module/apparmor/parameters/enabled` → `Y`.
- Pacchetti (installati anche da `harden-os.sh`, ma pre-installarli velocizza):
  ```
  nginx php8.1-fpm php8.1-{cli,mysql,gd,xml,mbstring,curl,zip,intl,bcmath}
  ufw auditd audispd-plugins aide acl apparmor-utils fail2ban unattended-upgrades
  ```
- Un utente con **sudo** e accesso SSH.

---

## 5. Installazione passo-passo (server reale)

### 5.1 Trasferire il repository sul server

Da una macchina che ha accesso SSH al server (esempio con tar over ssh):

```bash
tar czf - scripts templates config sites | \
  ssh utente@SERVER 'rm -rf ~/hardening && mkdir -p ~/hardening && tar xzf - -C ~/hardening && chmod +x ~/hardening/scripts/*.sh'
```

### 5.2 Hardening del sistema operativo (una volta)

```bash
ssh utente@SERVER
sudo env PHP_VERSION=8.1 SSH_HARDEN=no RUN_AIDEINIT=no \
  bash ~/hardening/scripts/harden-os.sh
```

- `SSH_HARDEN=no` all'inizio: **non** irrigidisce SSH finché non hai confermato
  l'accesso con chiave (evita di restare chiuso fuori).
- `harden-os.sh` abilita UFW consentendo `OpenSSH` **prima** di attivarlo, quindi
  la sessione SSH corrente non cade.
- AppArmor viene caricato in **complain** (fase di rodaggio, vedi §5.4).

Verifica rapida:
```bash
sudo ufw status                 # active, con OpenSSH/80/443
sudo aa-status | grep php-fpm   # profilo php-fpm caricato
sudo auditctl -l | grep webroot # regola webroot_write
```

### 5.3 Hardening di un virtual host

Il modo consigliato è preparare un file `sites/<nome>.env` (vedi
`sites/web_user.env` come esempio) e passarlo. In modalità non interattiva tutte le
variabili vanno fornite via `env`:

```bash
sudo env \
  SITE=web_user SERVER_NAME=svi-web_user.example DOCROOT=/var/www/html/web_user/public_html \
  RUNTIME_USER=web_user WEB_USER=www-data PHP_VERSION=8.1 \
  WRITABLE_DIRS="images media cache administrator/cache" \
  TMP_PATH=/var/www/html/web_user/tmp \
  SESSION_PATH=/var/www/html/web_user/sessions \
  LOG_PATH=/var/www/html/web_user/logs \
  DB_HOST=10.0.0.10 DB_PORT=3306 MAIL_HOST=10.0.0.20 ALLOW_HTTPS=yes \
  COOKIE_SECURE=off ASSUME_YES=1 ENABLE_APPARMOR_HAT=1 \
  bash ~/hardening/scripts/harden-vhost.sh
```

Note importanti:
- **`ENABLE_APPARMOR_HAT=1`** su host reale: attacca l'hat `php-fpm//<SITE>`.
  (In container viene disabilitato automaticamente perché non funzionerebbe.)
- **`COOKIE_SECURE=off`** finché il sito è in HTTP; passare a `on` con HTTPS
  attivo (vedi §6, `tls-on`).
- Impostare in `configuration.php` di Joomla i percorsi mostrati a fine script:
  `public $tmp_path` e `public $log_path`.

Senza `env` (esecuzione interattiva) lo script **chiede ogni valore** con un
default sensato.

### 5.4 Riavvio pulito di php-fpm (obbligatorio)

php-fpm all'avvio del sistema parte **prima** che il profilo AppArmor sia
caricato: il master resta quindi *unconfined*. Un **restart completo** lo
ri-esegue confinato e applica la sandbox systemd:

```bash
sudo systemctl restart php8.1-fpm
```
> Un semplice `reload` **non** basta: non ri-esegue il master né applica la
> sandbox. Serve `restart`.

Verifica:
```bash
# master confinato
MP=$(pgrep -f 'php-fpm: master' | head -1); sudo cat /proc/$MP/attr/current   # -> php-fpm (complain)
# worker nell'hat dopo una richiesta
curl -s -o /dev/null http://SERVER/  ; ps axZ | grep '[p]ool web_user'             # -> php-fpm//web_user (complain)
```

### 5.5 Rodaggio (complain) → enforce

Il workflow AppArmor è sempre **complain → soak → enforce**.

1. **Esercita il sito** in complain: frontend, login admin, salvataggio
   articolo (scrittura DB), upload media, pulizia cache, invio email di test.
2. **Raccogli le negazioni** che l'enforce bloccherebbe, come lista numerata:
   ```bash
   sudo bash scripts/show-aa-denials.sh web_user            # [today|recent|this-week|YYYY-MM-DD]
   ```
   Mostra ogni denial deduplicato con conteggio, tipo (file/network/unix/exec/
   capability) e la **regola pronta**; salva la lista per il passo successivo.
   Concedi una regola specifica per ID:
   ```bash
   sudo bash scripts/add-aa-permit.sh web_user 5            # aggiunge la regola #5 all'hat + ricarica
   sudo bash scripts/add-aa-permit.sh web_user --list       # permit già concessi
   sudo bash scripts/add-aa-permit.sh web_user --remove 2   # rimuove un permit
   ```
   I permit di **exec** sono rifiutati di default (romperebbero il modello
   no-exec): richiedono `--force` e sono sconsigliati. Ricarica/ri-esercita
   finché una passata completa non produce **zero** negazioni (le sole exec sono
   accettabili: sono l'hat che fa il suo lavoro). In alternativa `sudo aa-logprof`.
3. **Passa a enforce** con lo script dedicato (consigliato):
   ```bash
   sudo bash ~/hardening/scripts/enforce-vhost.sh web_user
   ```
   Lo script: controlla il soak (rifiuta se ci sono negazioni non-exec ancora da
   risolvere), passa l'hat a enforce, riavvia php-fpm, fa un **health-check** e —
   se il worker non serve più (es. HTTP 502) — **torna automaticamente a
   complain** elencando le negazioni da sistemare. Opzioni:
   ```bash
   sudo bash enforce-vhost.sh web_user --with-master   # enforce anche il master (da fare per ultimo, a tutti i siti soaked)
   sudo bash enforce-vhost.sh web_user --revert         # ritorna a complain
   sudo bash enforce-vhost.sh web_user --force          # enforce ignorando le negazioni pending (il rollback resta attivo)
   sudo bash enforce-vhost.sh web_user --dry-run        # mostra cosa farebbe
   ```
   > Di default viene messo in enforce solo l'**hat del sito** (il worker, dove
   > c'è il rischio): il master resta in complain e si può mettere in enforce una
   > volta sola, con `--with-master`, quando tutti i siti sono pronti.

   In alternativa, il flip manuale equivalente:
   ```bash
   sudo sed -i 's/flags=(complain,attach_disconnected)/flags=(attach_disconnected)/' \
     /etc/apparmor.d/php-fpm.d/web_user
   sudo apparmor_parser -r /etc/apparmor.d/php-fpm && sudo systemctl restart php8.1-fpm
   ```
4. **Verifica enforce**:
   ```bash
   MP=$(pgrep -f 'php-fpm: master'|head -1); sudo cat /proc/$MP/attr/current   # php-fpm (enforce)
   ps axZ | grep '[p]ool web_user'                                                  # php-fpm//web_user (enforce)
   # l'hat deve negare l'exec di binari esterni:
   sudo aa-exec -p php-fpm//web_user -- /bin/sh -c 'wget --version'                 # Permission denied
   ```

---

## 6. Operazioni day-2 (`tune-vhost.sh`)

Modifica la policy di un sito esistente mantenendo sincronizzati tutti i file.
Aggiungi `--dry-run` in fondo per vedere le modifiche senza applicarle.

```bash
# Egress: host/porte raggiungibili dall'utente del sito
sudo tune-vhost.sh web_user allow 10.0.0.20 587 tcp     # consenti SMTP verso il relay
sudo tune-vhost.sh web_user deny  10.0.0.20 25          # rimuovi una regola
sudo tune-vhost.sh web_user list                          # (vedi 'show')

# Filesystem: cartelle leggibili/scrivibili (aggiorna pool + hat + systemd insieme)
sudo tune-vhost.sh web_user grant-write /var/www/html/web_user/shared
sudo tune-vhost.sh web_user grant-read  /srv/dati-comuni
sudo tune-vhost.sh web_user revoke      /var/www/html/web_user/shared

# Impostazioni pool / cgroup
sudo tune-vhost.sh web_user set memory_limit 512M
sudo tune-vhost.sh web_user set MemoryMax 512M            # efficace con service per-pool
sudo tune-vhost.sh web_user disable exec                  # gestisci disable_functions
sudo tune-vhost.sh web_user tls-on                        # attiva session.cookie_secure (con HTTPS)

# Stato corrente
sudo tune-vhost.sh web_user show
```

> Dopo `grant-write` in **enforce**, l'hat viene ricaricato prima del pool: se
> aggiungi un percorso scrivibile, la sincronizzazione lo propaga a
> `open_basedir`, hat AppArmor e `ReadWritePaths` di systemd in un colpo solo.

### 6.1 Personalizzazione: template, tunable e cosa NON toccare

I valori "statici" dei template (es. `pm.max_children`, `memory_limit`, upload)
si cambiano a **tre livelli**:

1. **Per-sito, via `.env` (consigliato, idempotente).** I tunable comuni sono
   parametrici: impostali in `sites/<sito>.env` e ri-esegui `harden-vhost.sh`.
   ```bash
   PM_MAX_CHILDREN=25
   MEMORY_LIMIT=512M
   UPLOAD_MAX_FILESIZE=64M        # nginx client_max_body_size lo segue
   ```
   Default se omessi: `10 / 500 / 256M / 32M / 32M / 60`.
2. **Default per TUTTI i siti nuovi:** modifica il template
   `templates/php-fpm-pool.conf.tmpl` (o `nginx-app.conf.tmpl`). I siti esistenti
   lo recepiscono solo ri-eseguendo `harden-vhost.sh`.
3. **Day-2 su un sito già attivo** (senza re-render), per i valori supportati:
   `tune-vhost.sh <sito> set memory_limit 512M` (idempotente, ricarica il pool).

**NON modificare a mano** (rigenerati dalla sync-engine → le tue modifiche
andrebbero perse): `open_basedir` del pool, la regione `reach` dell'hat AppArmor,
`ReadWritePaths` systemd, le catene `<sito>_EGRESS`. Per quelli usa `tune-vhost.sh`.

> **Re-render → ri-enforce.** Ri-eseguire `harden-vhost.sh` rigenera pool e hat
> **riportando l'hat a complain**. Dopo un re-render rilancia
> `enforce-vhost.sh <sito>`. Le regioni sync-managed (open_basedir, egress) e
> un'eventuale config TLS vengono invece **preservate**.

### 6.2 HTTPS / TLS (self-signed e Let's Encrypt)

`harden-os.sh` installa `certbot` e abilita il timer di rinnovo. Per attivare
HTTPS su un sito:

```bash
# certificato self-signed (subito; warning nel browser — staging)
sudo scripts/setup-tls.sh site1 --self-signed

# Let's Encrypt (dominio PUBBLICO che risolve verso questo host, :80 aperta)
sudo scripts/setup-tls.sh site1 --letsencrypt --email tu@dominio.it
#   --staging   prova il flusso con la CA di test
```

Lo script ottiene/crea il certificato, rende il server block HTTPS (l'HTTP fa
**301 → HTTPS**, mantenendo il path ACME per i rinnovi), ricarica nginx e mette
`session.cookie_secure=on`. Per Let's Encrypt installa anche un **deploy-hook**
che ricarica nginx dopo ogni rinnovo automatico.

- Cert self-signed: `/etc/nginx/ssl/<sito>/` · Cert LE: `/etc/letsencrypt/live/<dominio>/`
- Rinnovo automatico: `certbot.timer` (2×/giorno) · test: `sudo certbot renew --dry-run`
- Ri-eseguire `harden-vhost.sh` **non** disattiva TLS (la config HTTPS è preservata).

---

## 7. Test in ambiente effimero (Docker) e su VM

### 7.1 Tier-1 — container Docker (ciclo rapido)

Valida generazione config, modello filesystem, comportamento live di php-fpm e
connettività DB (MariaDB effimero). **Non** può validare i layer a livello di
kernel (AppArmor enforce, auditd, sandbox systemd, egress ufw).

**Linux / macOS / Git-Bash:**
```bash
bash test/run-tests.sh
```

**Windows PowerShell** (se `bash` sull'host apre una WSL non funzionante):
```powershell
powershell -ExecutionPolicy Bypass -File test\run-tests.ps1
```

> `test/in-container.sh` gira **dentro** il container, mai sull'host.

Shell interattiva nel container:
```powershell
docker build -t ubuntu-harden-tier1 -f test/Dockerfile.tier1 test/
docker run --rm -it -v "${PWD}:/work" -w /work ubuntu-harden-tier1 bash
# dentro:  bash test/in-container.sh
```

### 7.2 Tier-2 — VM reale

Necessaria per i layer di kernel: AppArmor **enforce**, cattura auditd, sandbox
systemd, egress ufw reale. Vedi §5 per l'installazione sulla VM. Consiglio:
fare uno **snapshot** dopo l'installazione base e un altro dopo l'enforce, così
da poter ripartire velocemente.

---

## 8. Verifica (checklist)

- [ ] Come utente runtime **non** si può leggere il docroot di un altro sito.
- [ ] `wget` come utente runtime → AppArmor nega l'exec **e** l'egress fa REJECT.
- [ ] `test.php` in una cartella upload → servito inerte, non interpretato (403).
- [ ] `photo.jpg/foo.php` → 404, non eseguito.
- [ ] Scrittura sotto `/var/www` → compare in `ausearch -k webroot_write`.
- [ ] L'utente runtime **non** può scrivere codice/`configuration.php`; **può**
      scrivere nelle cartelle runtime + tmp.
- [ ] Worker confinato come `php-fpm//<SITE>` in enforce.
- [ ] Connessione al DB funzionante attraverso il pool hardenizzato.

### 8.1 Strumento diagnostico manuale (`tools/hardening-check.php`)

Pagina PHP autonoma con GUI (**"by manux4CONINET"**) che verifica dal vivo se la
configurazione del pool è solida. Uso **temporaneo**:

1. Carica `tools/hardening-check.php` nel docroot via FTP/SFTP.
2. Aprila nel browser → report a colori con verdetto (`HARDENED` / `REVIEW` /
   `FAIL`). Output JSON per automazioni: `…/hardening-check.php?format=json`.
   Test DB opzionale: `?db_host=…&db_user=…&db_pass=…&db_name=…`.
3. **ELIMINA il file subito dopo l'uso** — rivela lo stato di hardening.

Controlla: identità/gruppi, `disable_functions` + `exec()` live, `open_basedir`
(lettura `/etc/passwd`, list `/`), wrapper remoti, `expose_php`/`display_errors`,
scrittura nel codice (deve **fallire**) vs in tmp (deve **riuscire**), hardening
sessione, limiti risorse, egress in uscita, confinamento AppArmor e (opzionale)
connessione DB. Risponde anche a `X-Robots-Tag: noindex`.

> **Non lasciarlo online.** Rivela la postura di hardening e il test DB accetta
> host arbitrari (vettore SSRF). È usa-e-elimina. Per un endpoint ricorrente usa
> la variante gated §8.2.

### 8.2 Variante gated persistente (`tools/hardening-report.php`)

Se ti serve un endpoint ricorrente, questa variante è sicura da lasciare: **niente
test DB** (rimuove l'SSRF), percorsi `open_basedir` oscurati, e accesso protetto
da **firma asimmetrica Ed25519** — nel file c'è solo la **chiave pubblica**.

1. Su una macchina fidata (non il server) genera la coppia di chiavi:
   ```bash
   php tools/hardening-token.php keygen
   ```
2. Incolla la **chiave pubblica** in `PUBKEY_B64` dentro `hardening-report.php`
   (leggerlo non permette di forgiare token). Custodisci la **privata** fuori dal
   server.
3. Genera un token quando serve (valido per oggi, UTC) e apri il report:
   ```bash
   php tools/hardening-token.php sign <SECRET_B64>
   # -> ...hardening-report.php?key=<TOKEN>   (&format=json)
   ```

Il token è la firma di `hardening-check+<data UTC>`: vale solo **oggi/ieri**
(finestra per lo skew), non è riusabile nei giorni successivi né forgiabile senza
la privata. Ogni accesso negato restituisce un **404 identico a quello di nginx**
(header + body), così un probe non capisce nemmeno che l'endpoint esiste.
**Difesa in profondità**: aggiungi anche una allow-list nginx (snippet nell'header
del file) e servilo sulla rete di management.

---

## 9. Risoluzione problemi (lezioni dal campo)

### Dove sono i log (per-sito)

| Cosa | Percorso | Note |
|---|---|---|
| **PHP app** (errori del sito) | `<LOG_PATH>/php-error.log` — es. `/var/www/html/site1/logs/php-error.log` | per-sito, fuori dal docroot; scrivibile da `<utente>` via gruppo www-data |
| **PHP-FPM daemon/pool** (avvio worker, "child said…") | `/var/log/php8.1-fpm.log` | globale; filtra per `[pool site1]` |
| **nginx access** (per-sito) | `/var/log/nginx/site1.access.log` | un file per sito |
| **nginx error** (per-sito) | `/var/log/nginx/site1.error.log` | un file per sito |
| **auditd** (scritture web root / execve per-sito) | `/var/log/audit/audit.log` | `ausearch -k webroot_write` · `ausearch -k site1_exec` |
| **AppArmor denials** | `/var/log/audit/audit.log` | usa `show-aa-denials.sh site1` |
| App (Joomla ecc.) | il `log_path` del sito (= `<LOG_PATH>`) | impostato in `configuration.php` |

```bash
sudo tail -f /var/www/html/site1/logs/php-error.log     # errori PHP del sito
sudo tail -f /var/log/nginx/site1.error.log             # errori nginx del sito
sudo grep '\[pool site1\]' /var/log/php8.1-fpm.log       # eventi FPM del pool
```

### Note e trappole

Punti critici emersi durante i test reali (Tier-2). Molti valgono come
promemoria generale.

- **`allow_url_include/fopen = off` NON bloccano `eval()`.** Bloccano RFI e
  `include('php://input')` / `data://` (eseguire dati POST/remoti *via include*),
  ma `eval($_POST[...])` è un costrutto del linguaggio — non disabilitabile via
  `.ini` né `disable_functions`. La difesa è la **contenzione** (open_basedir,
  AppArmor no-exec, egress, isolamento DB): anche se `eval` gira, la webshell
  resta confinata.

- **UFW possiede il firewall.** Non aggiungere regole OUTPUT a mano: finirebbero
  *dopo* `ufw-track-output` che accetta ogni connessione nuova. L'egress va
  integrato in `/etc/ufw/before.rules` (+ `before6.rules`). Non usare
  `netfilter-persistent save` insieme a ufw.
- **Nome catena IPv6 diverso.** In `before6.rules` la catena di output si chiama
  `ufw6-before-output`, non `ufw-before-output`. Un hook col nome sbagliato fa
  fallire `ufw reload` — e siccome il reload è disable-then-enable, **disabilita
  il firewall**. (Corretto negli script.)
- **`NoNewPrivileges` è incompatibile con `apparmor_hat`.** Con `no_new_privs`
  il kernel rifiuta la transizione dell'hat (EPERM, **nessun record AVC**): il
  worker non serve richieste. Va **rimosso** dalla sandbox systemd — l'hat, che
  nega *ogni* exec, è un controllo più forte. (Corretto in
  `config/systemd-fpm-global.conf`.)
- **Watch auditd non ricorsivo.** `-w /var/www -p wa` **non** è ricorsivo e
  perde i file nelle sottocartelle. Usare una regola *tree* `-a always,exit -F
  dir=/var/www -F perm=wa`. (Corretto in `config/auditd-hardening.rules`.)
- **L'hat deve poter usare il proprio socket.** Il worker fa accept/read/write
  sul socket del pool (`/run/php/php8.1-<SITE>.sock`); senza regola dedicata, in
  enforce serve **0 richieste**. (Aggiunto in `templates/apparmor-child.tmpl`.)
- **`open_basedir` con slash finale.** Senza lo slash `/var/www/html/web_user`
  fa match anche su directory sorelle. Tenere allineati i nomi singolare/plurale
  (`logs` vs `log`) e creare le cartelle in anticipo.
- **nginx gira come `www-data`.** Ogni cartella superiore del docroot deve essere
  attraversabile da www-data, altrimenti `stat() ... Permission denied` → 502.
- **AVC in `/var/log/audit/audit.log`, non nel journal.** Con auditd installato,
  `journalctl -k | grep DENIED` è vuoto: usare
  `sudo ausearch -m AVC -ts recent -i`.
- **`aa-teardown` de-confina il master** → i pool con `apparmor_hat` falliscono
  (`unconfined//web_user`). Recupero: `systemctl restart apparmor` poi riavvia
  php-fpm (il master deve **ri-eseguirsi** confinato).
- **`pm = ondemand`**: nessun worker finché non arriva una richiesta. "pool non
  avviato" è normale.
- **`session.cookie_secure = on` rompe il login in HTTP puro.** Tenerlo `off`
  in staging HTTP, riattivarlo con TLS (`tune-vhost.sh <SITE> tls-on`).
- **`aa-exec` applica l'hat *on-exec*.** Per testare che l'hat blocchi l'exec,
  provare un exec *annidato* (`aa-exec -p php-fpm//web_user -- /bin/sh -c 'wget -V'`),
  non un builtin come `echo`.

---

## 10. Struttura del repository

```text
scripts/       harden-os.sh, harden-vhost.sh, tune-vhost.sh, enforce-vhost.sh,
               setup-tls.sh, show-aa-denials.sh, add-aa-permit.sh, lib/{common,policy}.sh
templates/     pool php-fpm, hat AppArmor, nginx app-snippet + server HTTP + HTTPS
tools/         hardening-check.php (temporaneo), hardening-report.php (gated Ed25519), hardening-token.php (keygen/firma)
config/        profilo AppArmor master, regole auditd, snippet nginx/TLS, drop-in systemd
sites/         <nome>.env — risposte per-sito (anche input non interattivo dei test)
test/          Dockerfile, run-tests.{sh,ps1}, in-container.sh, checks/, README
```

---

## 11. Stato verificato (VM di test)

Su una VM Ubuntu 22.04 reale (PHP 8.1, MariaDB 10.6) è stato verificato in
**enforce**:

- Master `php-fpm (enforce)`, worker `php-fpm//web_user (enforce)`.
- L'hat **nega l'exec** di `cat`/`wget`/`id` (log `denied_mask="x"`).
- Sandbox systemd attiva (`ProtectSystem=strict`, `ReadWritePaths` per-sito).
- Hardening PHP: open_basedir, disable_functions, scrittura codice negata /
  scrittura tmp consentita.
- Routing nginx: `.php` inesistente → 404, `.php` in upload → 403, `.jpg` inerte.
- Egress per-uid: web_user → :80 REJECT, web_user → :443 e DB consentiti.
- Connessione DB funzionante dal pool.
- auditd: regola *tree* `webroot_write` cattura le scritture in profondità.

---

*Guida allineata al codice del repository. Per il razionale completo e le fonti
vedere `apache-php-hardening-runbook.md`.*
