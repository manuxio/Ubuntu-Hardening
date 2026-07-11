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
| `scripts/harden-os.sh` | **una volta per server** | Layer condiviso: baseline nginx + php-fpm, profilo AppArmor **master**, sandbox systemd di default, UFW default-deny + impalcatura egress, auditd, AIDE, fail2ban, unattended-upgrades, SSH, sysctl, YARA-X. |
| `scripts/harden-vhost.sh` | **una volta per sito** | Setup del sito: utente runtime, pool PHP-FPM, modello permessi filesystem, **hat** AppArmor per-pool, server block nginx, catena egress per-uid, regola auditd per-sito. |
| `scripts/tune-vhost.sh` | **day-2, ad ogni modifica** | Modifica la policy di un sito già configurato: host/porte raggiungibili (egress), cartelle leggibili/scrivibili, limiti pool/cgroup. |
| `scripts/enforce-vhost.sh` | **dopo il soak** | Passa l'AppArmor del sito da complain a **enforce** in sicurezza (controllo soak, health-check, **rollback automatico** in caso di errore); supporta `--revert`. |

Ordine di esecuzione: prima `harden-os.sh`, poi `harden-vhost.sh` per ogni sito,
poi il rodaggio in complain, quindi `enforce-vhost.sh` per attivare l'enforce;
`tune-vhost.sh` quando serve cambiare una policy.

> Non ricordi i comandi? Il **menu interattivo** del capitolo 5 li orchestra
> tutti con delle schermate guidate.

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

## 5. Il menu interattivo (`harden-menu.sh`) — percorso guidato con schermate

Tutto ciò che i capitoli seguenti mostrano da riga di comando è disponibile in un
**menu testuale** (whiptail) che fa da orchestratore: ogni voce lancia lo script
giusto, mostra l'output dal vivo e — soprattutto — **legge e mostra lo stato
attuale** del sito prima di ogni modifica, così non lavori mai "alla cieca".

> Le schermate qui sotto sono catture reali del menu su una VM Ubuntu 22.04.

### 5.1 Avvio

```bash
sudo bash ~/hardening/scripts/harden-menu.sh
```

- Richiede i privilegi di root (usa `sudo`).
- Se `whiptail` non è installato, il menu **ripiega automaticamente** su
  un'interfaccia a righe di testo con gli stessi contenuti (vedi §5.7).
- `--check` esegue un self-test non interattivo (verifica che tutti gli script
  referenziati esistano) ed esce.

### 5.2 Come si naviga

- **Frecce ↑/↓**: sposta la selezione · **Invio**: conferma · **Tab**: passa a
  `<Ok>`/`<Cancel>`.
- **Esc** o `<Cancel>`: torna al menu precedente (annulla).
- Nei menu di gestione **resti nel sotto-menu** dopo ogni azione (puoi fare più
  modifiche di fila) finché non scegli `<< Indietro`.

### 5.3 Menu principale

Il menu principale tiene solo le operazioni globali e le due voci per i siti —
**Crea sito** e **Gestisci siti**:

```text
┌─────────────────────────────┤ Ubuntu Hardening ├─────────────────────────────┐
│ Server: ubuntu · scegli un'azione:                                           │
│                                                                              │
│               Audit: baseline sicurezza (Lynis)                              │
│               Hardening del sistema operativo (una volta)                    │
│               Audit: verifica + delta (Lynis)                                │
│               Scan CVE dei pacchetti (Trivy)                                 │
│               Audit conformità CIS (OpenSCAP)                                │
│               Crea sito                                                       │
│               Gestisci siti                                                  │
│               Test end-to-end (ATTENZIONE: crea site1/site2!)                │
│               Esci                                                           │
│                                                                              │
│                     <Ok>                         <Cancel>                    │
└──────────────────────────────────────────────────────────────────────────────┘
```

- Le prime cinque voci sono **audit e hardening globali** (una tantum per
  server): baseline Lynis, hardening OS, verify Lynis, scan CVE Trivy,
  compliance CIS.
- **Crea sito** e **Gestisci siti** sono il cuore dell'uso quotidiano.
- **Test end-to-end** provisiona due siti usa-e-getta (`site1`/`site2`) e
  verifica l'isolamento incrociato — utile in laboratorio, **non** su
  produzione (l'avviso è esplicito).

### 5.4 Crea sito

**Crea sito** chiede prima il **nome breve** del sito (usato per pool, hat
AppArmor e utente):

```text
┌────────────────────────┤ Ubuntu Hardening ├────────────────────────┐
│ Nome breve del nuovo sito (pool/hat/utente):                       │
│                                                                    │
│ web_user__________________________________________________________ │
│                                                                    │
│                 <Ok>                     <Cancel>                  │
└────────────────────────────────────────────────────────────────────┘
```

Poi presenta una **maschera a gruppi**: personalizzi i parametri per area,
quindi lanci la creazione. La riga `>>> CREA IL SITO <<<` mostra la modalità
corrente (http/https):

```text
┌─────────────────────────────┤ Ubuntu Hardening ├─────────────────────────────┐
│ Nuovo sito 'web_user' — configura per gruppi, poi CREA:                      │
│                                                                              │
│          Nginx / dominio     (server_name, HTTP/HTTPS)                       │
│          File System         (docroot, utenti, dir, path)                    │
│          PHP / Pool          (versione, memoria, limiti, workers)            │
│          Rete / DB / Mail    (DB, SMTP, egress, cookie)                      │
│          >>> CREA IL SITO (modalita: http) <<<                               │
│          Annulla                                                             │
│                                                                              │
│                     <Ok>                         <Cancel>                    │
└──────────────────────────────────────────────────────────────────────────────┘
```

Ogni gruppo elenca i campi con il **valore attuale** già compilato (default
sensati), che puoi cambiare uno per uno — per esempio il gruppo **File System**:

```text
┌─────────────────────────────┤ Ubuntu Hardening ├─────────────────────────────┐
│ File System — modifica un campo:                                             │
│                                                                              │
│        Docroot              = /var/www/html/web_user/public_html             │
│        Utente runtime       = web_user                                       │
│        Identita codice      = www-data                                       │
│        Dir scrivibili       = images media cache administrator/cache         │
│        Temp path            = /var/www/html/web_user/tmp                     │
│        Session path         = /var/www/html/web_user/sessions                │
│        Log path             = /var/www/html/web_user/logs                    │
│        << Indietro                                                           │
│                                                                              │
│                     <Ok>                         <Cancel>                    │
└──────────────────────────────────────────────────────────────────────────────┘
```

I quattro gruppi:
- **Nginx / dominio** — `server_name`, alias, HTTP vs HTTPS.
- **File System** — docroot, utente runtime, identità del codice, cartelle
  scrivibili, path di tmp/sessioni/log.
- **PHP / Pool** — versione PHP, memoria, limiti di upload/tempo, numero di
  worker.
- **Rete / DB / Mail** — host/porta del DB, relay SMTP, egress, cookie sicuri.

Alla conferma il menu esegue `harden-vhost.sh` con le risposte e ne mostra
l'output. Il sito nasce in AppArmor **complain** (rodaggio): vedi §6.5 per il
passaggio a enforce.

### 5.5 Gestisci siti

**Gestisci siti** chiede quale sito e apre il menu di gestione day-2. Ogni voce
è un'operazione mirata sul sito esistente:

```text
┌─────────────────────────────┤ Ubuntu Hardening ├─────────────────────────────┐
│ Gestisci 'cef' — scegli un'operazione:                                       │
│                                                                              │
│           Nginx: domini (server_name), abilita/disabilita                    │
│           HTTPS / TLS: certificato (self-signed o Let's Encrypt)             │
│           Egress: destinazioni consentite / bloccate                         │
│           Directory: permessi lettura / scrittura                            │
│           Esecuzione: permessi AppArmor exec di programmi                    │
│           PHP / Pool: memoria, limiti, workers, funzioni                     │
│           Cookie sicuri (session.cookie_secure)                              │
│           AppArmor: Enforce (soak -> enforce)                                │
│           AppArmor: mostra i denial del soak                                 │
│           Verifica isolamento del sito                                       │
│           Scansione malware del docroot (YARA-X)                             │
│           Deploy pagina di test PHP                                          │
│           Aggiorna config (applica gli ultimi template)                      │
│           Mostra tutta la policy del sito                                    │
│           DISTRUGGI il sito (rimuove config, NON i dati)                     │
│           << Indietro                                                        │
│                                                                              │
│                     <Ok>                         <Cancel>                    │
└──────────────────────────────────────────────────────────────────────────────┘
```

Il punto chiave: **ogni sotto-menu mostra la configurazione attuale** prima di
proporre le modifiche. Alcuni esempi.

**Directory** — elenca le cartelle scrivibili e in sola lettura con permessi e
proprietari reali; i grant/revoke avvengono scegliendo dai path esistenti
(niente digitazione alla cieca):

```text
┌─────────────────────────────┤ Ubuntu Hardening ├─────────────────────────────┐
│ Directory di 'cef':                                                          │
│                                                                              │
│ SCRIVIBILI dall'utente runtime:                                              │
│   drwxrws--- www-data:www-data  /var/www/html/cef/public_html/images         │
│   drwxrws--- www-data:www-data  /var/www/html/cef/public_html/media          │
│   drwxrws--- www-data:www-data  /var/www/html/cef/public_html/cache          │
│   drwxrws--- www-data:www-data  /var/www/html/cef/public_html/administrator/…│
│   drwxrws--- www-data:www-data  /var/www/html/cef/tmp                        │
│   drwxrws--- www-data:www-data  /var/www/html/cef/sessions                   │
│   drwxrws--- www-data:www-data  /var/www/html/cef/logs                       │
│ SOLA LETTURA:                                                                │
│   drwxr-x--- www-data:www-data  /var/www/html/cef/public_html                │
│                                                                              │
│                 Concedi SCRITTURA su una cartella                            │
│                 Concedi (sola) LETTURA su una cartella                       │
│                 REVOCA un path (scegli dall'elenco attuale)                  │
│                 << Indietro                                                  │
│                                                                              │
│                     <Ok>                         <Cancel>                    │
└──────────────────────────────────────────────────────────────────────────────┘
```

Un grant qui aggiorna **contemporaneamente** `open_basedir`, l'hat AppArmor e
`ReadWritePaths` di systemd (il "principio di sincronizzazione", §2.1).

**Egress** — mostra le destinazioni consentite in uscita per l'uid del sito;
tutto il resto è REJECT:

```text
┌─────────────────────────────┤ Ubuntu Hardening ├─────────────────────────────┐
│ Egress di 'cef':                                                             │
│                                                                              │
│ CONSENTITE (uscita per uid del sito):                                        │
│   risposte a connessioni gia' aperte                                         │
│   -o lo                                                                       │
│   -p udp --dport 53                                                          │
│   -p tcp --dport 53                                                          │
│   -d 127.0.0.1 -p tcp --dport 3306                                           │
│   -- tutto il resto: BLOCCATO (REJECT) --                                    │
│                                                                              │
│                     APRI una destinazione (host:porta)                       │
│                     CHIUDI una destinazione                                  │
│                     << Indietro                                              │
│                                                                              │
│                     <Ok>                         <Cancel>                    │
└──────────────────────────────────────────────────────────────────────────────┘
```

**PHP / Pool** — mostra i valori correnti inline; li cambi o gestisci
`disable_functions` (disabiliti/riabiliti una funzione senza doverle riscrivere
tutte):

```text
┌─────────────────────────────┤ Ubuntu Hardening ├─────────────────────────────┐
│ PHP / Pool di 'cef' — scegli cosa cambiare:                                  │
│                                                                              │
│                       memory_limit         = 256M                            │
│                       max_execution_time   = 60                              │
│                       upload_max_filesize  = 32M                             │
│                       post_max_size        = 32M                             │
│                       pm.max_children      = 10                              │
│                       pm.max_requests      = 500                             │
│                       allow_url_fopen      = off                             │
│                       display_errors       = off                             │
│                       expose_php           = off                             │
│                       MemoryMax (cgroup)   =                                 │
│                       CPUQuota (cgroup)    =                                 │
│                       TasksMax (cgroup)    =                                 │
│                       Disabilita una funzione PHP ...                        │
│                       Riabilita una funzione PHP ...                         │
│                       << Indietro                                            │
│                                                                              │
│                     <Ok>                         <Cancel>                    │
└──────────────────────────────────────────────────────────────────────────────┘
```

**Esecuzione** — il modello **no-exec**: il worker non può avviare alcun binario
esterno. Da qui puoi concedere un'eccezione mirata **scegliendola dai denial
raccolti nel soak** (sconsigliato, indebolisce il modello):

```text
┌─────────────────────────────┤ Ubuntu Hardening ├─────────────────────────────┐
│ Esecuzione programmi per 'cef':                                              │
│                                                                              │
│ Nessun programma eseguibile: il worker non puo' avviare binari esterni       │
│ (modello no-exec).                                                           │
│                                                                              │
│         Consenti l'esecuzione di un programma (dai denial del soak)          │
│         Revoca un permesso di esecuzione concesso                            │
│         Mostra/aggiorna i denial del soak                                    │
│         << Indietro                                                          │
│                                                                              │
│                     <Ok>                         <Cancel>                    │
└──────────────────────────────────────────────────────────────────────────────┘
```

Le altre voci del menu di gestione: **HTTPS/TLS** (self-signed o Let's Encrypt),
**Cookie sicuri**, **AppArmor Enforce** (soak→enforce con rollback automatico),
**AppArmor denial** (mostra le negazioni del soak), **Aggiorna config**
(riapplica gli ultimi template), **Deploy pagina di test**, e **DISTRUGGI**
(rimuove la configurazione ma **non** i dati sul disco).

### 5.6 Verifica e scansioni dal menu

Tre voci di **Gestisci siti** provano che il contenimento funziona.

**Verifica isolamento del sito** — deploya una sonda nel docroot, la richiama via
nginx e verifica che ogni tentativo di evasione sia negato:

```text
==> bash scripts/probe-vhost.sh cef
-------------------------------------------------------------
[!] no second site — testing host isolation only (cross-site keys still assert via open_basedir).
== isolation: 'cef' -> host ==
  PASS xsite_read_config
  PASS xsite_list_dir
  PASS xsite_read_secret
  PASS xsite_write
  PASS read_etc_shadow
  PASS exec_denied
  PASS shell_spawn_denied
  PASS egress_80_denied
  PASS own_write_ok

[*] ISOLATION OK — PASS=9 FAIL=0
-------------------------------------------------------------
```

Le asserzioni: lettura/scrittura verso un altro sito, lettura di `/etc/shadow`,
exec di binari, apertura di una shell, connessione in uscita su :80 — **tutte
negate** — mentre la scrittura nella propria cartella funziona (`own_write_ok`).
Con un secondo sito configurato, la prova diventa **incrociata nei due sensi**.

**Scansione malware del docroot (YARA-X)** — cerca pattern da webshell con `yr`:

```text
==> bash scripts/scan-malware.sh cef
-------------------------------------------------------------
[*] YARA-X malware scan — site 'cef', rules: webshells.yar
    scanning /var/www/html/cef/public_html

[x] MATCHES: 1 — REVIEW each (rule  file). A CMS can trip some rules; confirm before acting.
    php_cmd_from_http_input /var/www/html/cef/public_html/hardening-check.php
    full report: /var/log/hardening-audit/malware-cef.txt
-------------------------------------------------------------
```

> Nell'esempio la scansione segnala `hardening-check.php`: è la **pagina di
> test** che deployiamo di proposito, contiene `system()` alimentato da input
> HTTP per verificare `disable_functions` — quindi fa scattare la regola
> "comando da input HTTP". È un vero positivo *atteso*: rimuovi la pagina di test
> dopo l'uso (voce **Deploy pagina di test** → rimuovi, oppure
> `scripts/deploy-test.sh <sito> --remove`).

**Mostra tutta la policy del sito** — riepilogo unico di open_basedir, cartelle
reach (rw/ro) ed egress v4/v6:

```text
==> bash scripts/tune-vhost.sh cef show
-------------------------------------------------------------
== cef (PHP 8.1, uid 997) ==
-- open_basedir --
php_admin_value[open_basedir] = /var/www/html/cef/public_html/:…/images/:…/media/:
  …/cache/:…/administrator/cache/:…/tmp/:…/sessions/:…/logs/
-- reach (rw) --
/var/www/html/cef/public_html/images
/var/www/html/cef/public_html/media
/var/www/html/cef/public_html/cache
/var/www/html/cef/public_html/administrator/cache
/var/www/html/cef/tmp
/var/www/html/cef/sessions
/var/www/html/cef/logs
-- reach (ro) --
/var/www/html/cef/public_html
-- egress v4 --
-p tcp -d 127.0.0.1 --dport 3306
[*] done.
-------------------------------------------------------------
```

### 5.7 Modalità testo (senza whiptail)

Se `whiptail` non è installato, il menu funziona identico ma stampa le voci
numerate su terminale semplice (comodo anche via console seriale o quando
l'output è loggato). Nessuna funzione va persa.

---

## 6. Installazione da riga di comando (server reale)

> Tutto questo capitolo è disponibile anche dal menu guidato (§5). Qui trovi i
> comandi equivalenti, utili per automazioni e per capire cosa fa ogni passo.

### 6.0 Audit e misura (Lynis · Trivy · OpenSCAP) — fase preliminare consigliata

Misura **prima e dopo** l'hardening con strumenti standard. Sono read-only
(tranne `audit-cis.sh --remediate`); i report vanno in `/var/log/hardening-audit/`.

```bash
# BASELINE (prima di harden-os) — Lynis calcola l'hardening index (0-100)
sudo bash scripts/audit-os.sh --baseline

#  ... applica l'hardening (6.1 -> 6.5) ...

# VERIFY (dopo) — rimisura e mostra il delta
sudo bash scripts/audit-os.sh --verify            # es. reale: 65 -> 84

# CVE dei pacchetti (asse "sei patchato?", diverso dall'hardening di config)
sudo bash scripts/scan-cve.sh                      # Trivy: HIGH/CRITICAL
#   -> remediation = apt upgrade (unattended-upgrades è già attivo)

# Compliance CIS (OpenSCAP + SCAP Security Guide ubuntu2204)
sudo bash scripts/audit-cis.sh                     # profilo cis_level1_server, report HTML
sudo bash scripts/audit-cis.sh --level2            # CIS Level 2
sudo bash scripts/audit-cis.sh --remediate         # applica i fix (RISCHIOSO, opt-in; ri-testa i siti)
```

- **Lynis** *misura*, non hardenizza: usalo come bracket **baseline → harden →
  verify**. `harden-os.sh` include già i controlli OS che Lynis segnala
  (login.defs/aging, `pam_pwquality`, blacklist moduli kernel, core dump off,
  banner legale, sysctl estesi).
- **Trivy** copre le CVE dei pacchetti (patching), asse complementare.
- **OpenSCAP/CIS** dà un punteggio di compliance standard; `--remediate` applica
  i fix (attenzione: può cambiare cose non coperte dai nostri script).

### 6.1 Trasferire il repository sul server

Da una macchina che ha accesso SSH al server (esempio con tar over ssh):

```bash
tar czf - scripts templates config sites | \
  ssh utente@SERVER 'rm -rf ~/hardening && mkdir -p ~/hardening && tar xzf - -C ~/hardening && chmod +x ~/hardening/scripts/*.sh'
```

### 6.2 Hardening del sistema operativo (una volta)

```bash
ssh utente@SERVER
sudo env PHP_VERSION=8.1 SSH_HARDEN=no RUN_AIDEINIT=no \
  bash ~/hardening/scripts/harden-os.sh
```

- `SSH_HARDEN=no` all'inizio: **non** irrigidisce SSH finché non hai confermato
  l'accesso con chiave (evita di restare chiuso fuori).
- `harden-os.sh` abilita UFW consentendo `OpenSSH` **prima** di attivarlo, quindi
  la sessione SSH corrente non cade.
- AppArmor viene caricato in **complain** (fase di rodaggio, vedi §6.5).

Verifica rapida:
```bash
sudo ufw status                 # active, con OpenSSH/80/443
sudo aa-status | grep php-fpm   # profilo php-fpm caricato
sudo auditctl -l | grep webroot # regola webroot_write
```

### 6.3 Hardening di un virtual host

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
  attivo (vedi §7, `tls-on`).
- Impostare in `configuration.php` di Joomla i percorsi mostrati a fine script:
  `public $tmp_path` e `public $log_path`.

Senza `env` (esecuzione interattiva) lo script **chiede ogni valore** con un
default sensato.

### 6.4 Riavvio pulito di php-fpm (obbligatorio)

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

### 6.5 Rodaggio (complain) → enforce

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

## 7. Operazioni day-2 (`tune-vhost.sh`)

Modifica la policy di un sito esistente mantenendo sincronizzati tutti i file.
Aggiungi `--dry-run` in fondo per vedere le modifiche senza applicarle. (Tutte
queste operazioni sono anche nel menu **Gestisci siti**, §5.5.)

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

### 7.1 Personalizzazione: template, tunable e cosa NON toccare

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

### 7.2 HTTPS / TLS (self-signed e Let's Encrypt)

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

## 8. Test in ambiente effimero (Docker) e su VM

### 8.1 Tier-1 — container Docker (ciclo rapido)

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

### 8.2 Tier-2 — VM reale

Necessaria per i layer di kernel: AppArmor **enforce**, cattura auditd, sandbox
systemd, egress ufw reale. Vedi §6 per l'installazione sulla VM. Consiglio:
fare uno **snapshot** dopo l'installazione base e un altro dopo l'enforce, così
da poter ripartire velocemente.

---

## 9. Verifica (checklist)

- [ ] Come utente runtime **non** si può leggere il docroot di un altro sito.
- [ ] `wget` come utente runtime → AppArmor nega l'exec **e** l'egress fa REJECT.
- [ ] `test.php` in una cartella upload → servito inerte, non interpretato (403).
- [ ] `photo.jpg/foo.php` → 404, non eseguito.
- [ ] Scrittura sotto `/var/www` → compare in `ausearch -k webroot_write`.
- [ ] L'utente runtime **non** può scrivere codice/`configuration.php`; **può**
      scrivere nelle cartelle runtime + tmp.
- [ ] Worker confinato come `php-fpm//<SITE>` in enforce.
- [ ] Connessione al DB funzionante attraverso il pool hardenizzato.

> Prova tutto in un colpo dal menu (**Gestisci siti → Verifica isolamento**,
> §5.6) oppure con `sudo bash scripts/probe-vhost.sh <sito> [<altro-sito>]`.

### 9.1 Strumento diagnostico manuale (`tools/hardening-check.php`)

Pagina PHP autonoma con GUI (**"by manux4CONINET"**) che verifica dal vivo se la
configurazione del pool è solida. Uso **temporaneo**:

1. Carica `tools/hardening-check.php` nel docroot via FTP/SFTP (o dal menu
   **Deploy pagina di test**).
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
> la variante gated §9.2. (Nota: contenendo `system()`+input HTTP, fa scattare la
> scansione YARA-X — è atteso, §5.6.)

### 9.2 Variante gated persistente (`tools/hardening-report.php`)

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

## 10. Risoluzione problemi (lezioni dal campo)

### Dove sono i log (per-sito)

| Cosa | Percorso | Note |
|---|---|---|
| **PHP app** (errori del sito) | `<LOG_PATH>/php-error.log` — es. `/var/www/html/site1/logs/php-error.log` | per-sito, dentro l'open_basedir del sito; scrivibile da `<utente>` via gruppo www-data |
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
- **La pagina `hardening-check.php` fa scattare YARA-X.** Contiene `system()`
  alimentato da input HTTP per testare `disable_functions`: è un match *atteso*
  della scansione malware, non una vera infezione. Rimuovila dopo l'uso.
- **`aa-exec` applica l'hat *on-exec*.** Per testare che l'hat blocchi l'exec,
  provare un exec *annidato* (`aa-exec -p php-fpm//web_user -- /bin/sh -c 'wget -V'`),
  non un builtin come `echo`.

---

## 11. Struttura del repository

```text
scripts/       harden-os.sh, harden-vhost.sh, tune-vhost.sh, enforce-vhost.sh, setup-tls.sh,
               harden-menu.sh (TUI), destroy-vhost.sh, refresh-vhost.sh, probe-vhost.sh,
               deploy-test.sh, scan-malware.sh (YARA-X),
               audit-os.sh (Lynis), scan-cve.sh (Trivy), audit-cis.sh (OpenSCAP/CIS),
               show-aa-denials.sh, add-aa-permit.sh, lib/{common,policy}.sh
templates/     pool php-fpm, hat AppArmor, nginx app-snippet + server HTTP + HTTPS
tools/         hardening-check.php (temporaneo), hardening-report.php (gated Ed25519), hardening-token.php (keygen/firma)
config/        profilo AppArmor master, regole auditd, snippet nginx/TLS, drop-in systemd, yara/webshells.yar
sites/         <nome>.env — risposte per-sito (anche input non interattivo dei test)
test/          Dockerfile, run-tests.{sh,ps1}, in-container.sh, checks/, README
```

---

## 12. Stato verificato (VM di test)

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
- Isolamento verificato dal menu: **9/9 asserzioni PASS** (host) / **32/32** nel
  test end-to-end con due siti.

---

*Guida allineata al codice del repository. Per il razionale completo e le fonti
vedere `apache-php-hardening-runbook.md`.*
