# Containerizzare un sito — `export-site.sh`

Trasforma un vhost hardenizzato in un **bundle container minimale** che mantiene gli
**stessi controlli runtime** dell'host — come **docker-compose** (test locali) e come
**manifest Kubernetes**. Stessa versione PHP, stessa struttura file (volume
persistente), stessi `php_admin_*`. Gli scanner host (Lynis/Trivy/OpenSCAP/YARA)
**non** fanno parte del container: sono strumenti di host/CI, non di runtime.

```bash
sudo bash scripts/export-site.sh <sito> --both      # compose + k8s
# --compose  solo docker-compose   ·   --k8s  solo Kubernetes
```

Legge lo stato del sito (`/etc/hardening/sites/<sito>/`) e **chiede** i parametri
del container (nomi immagini, repliche, namespace, Redis, PVC, porta). Ogni valore
è env-overridable per uso non interattivo. Output in `export/<sito>/{compose,k8s}/`
con un `README.md` per-bundle.

## Logica delle utenze

| Identità | uid:gid | Ruolo | Codice |
|---|---|---|---|
| `www-data` | 33:33 | proprietario del codice; **nginx** gira così | owner, ma volume **read-only** per nginx |
| runtime del sito | `<UID>`:33 | worker **php-fpm** | via gruppo 33: **legge** (750), **scrive solo** le dir 2770 |

- Codice `www-data:www-data`, dir `750` / file `640`: il runtime lo legge via
  gruppo, **non può scriverlo** (né `configuration.php`, `640`).
- Dir scrivibili `2770` setgid gruppo `www-data`: il runtime ci scrive.
  Preparate una volta da `init-perms.sh` (init container / init service, unico
  step con root); poi i container girano **rootless e shell-less**.
- nginx→php via **TCP `127.0.0.1:9000`**: in compose nginx condivide il netns di
  php (`network_mode: service:php`), in k8s stanno nello stesso pod. La 9000 non
  è mai pubblicata.

## Sicurezza runtime (mappa host → container)

Nessuna dipendenza da AppArmor a runtime *obbligatoria*: la difesa è a strati, e
AppArmor è un livello aggiuntivo (consigliato) sopra gli altri.

| Host | Container |
|---|---|
| uid per-sito + gruppo www-data | `runAsUser/runAsGroup` (k8s) · `user:` (compose) |
| codice non scrivibile dal runtime | modello permessi + volume RO in nginx + `readOnlyRootFilesystem` |
| hat AppArmor no-exec | **immagine senza shell/tool** + profilo `hardening-<sito>` + `disable_functions` |
| sandbox systemd (ProtectSystem, NoNewPrivileges, PrivateTmp) | `readOnlyRootFilesystem` · `allowPrivilegeEscalation:false` · `capabilities.drop:[ALL]` · `seccompProfile:RuntimeDefault` · `/tmp` tmpfs |
| egress firewall per-uid | **NetworkPolicy** (k8s) · **DOCKER-USER** `docker-egress.sh` (compose) |
| open_basedir / disable_functions / limit_extensions | identici, nel pool `php_admin_*` **incorporato** nell'immagine |
| limiti cgroup | `resources.limits` (k8s) · limiti compose |

Le **immagini sono minimali**: partono da `php:<ver>-fpm` e `nginx`, installano le
stesse estensioni dell'host, poi rimuovono shell (`/bin/sh`, bash) e tool di rete
(`wget`, `curl`, `apt`). php-fpm e nginx girano come **PID 1 in exec form**: non
c'è nulla che una webshell possa eseguire (l'equivalente-immagine dell'hat
no-exec, rinforzato da `disable_functions` e dal profilo AppArmor).

## Egress

Le regole egress per-uid dell'host diventano una policy **standard** del sito:

- **k8s** — una `NetworkPolicy` generata dalla allow-list del sito: consente solo
  **DNS + DB + mail + 443**, nega il resto (e isola la porta 9000 al solo pod).
  Serve un CNI che la applichi (Calico, Cilium…).
- **compose** — `docker-egress.sh apply` installa una catena in `DOCKER-USER`
  che limita l'uscita della subnet del progetto agli **stessi** host/porte.

## Redis e servizi opzionali

Lo script chiede se serve **Redis** (backend sessioni/cache): lo aggiunge come
servizio separato con la sua rete/policy e configura il pool
(`session.save_handler = redis`). Il **database resta esterno** (come sull'host):
il container lo raggiunge solo via egress.

## Uso

**Compose (test locali):**
```bash
cd export/<sito>/compose
docker compose up -d --build
sudo ./docker-egress.sh apply                       # opzionale: blocca l'egress
sudo apparmor_parser -r -W hardening-<sito>.aa      # opzionale: AppArmor
curl -H 'Host: <dominio>' http://localhost:<porta>/
```

**Kubernetes:**
```bash
cd export/<sito>/k8s
docker build -f Dockerfile.php   -t <img-php>   . && docker push <img-php>
docker build -f Dockerfile.nginx -t <img-nginx> . && docker push <img-nginx>
# carica hardening-<sito>.aa su OGNI nodo (o togli il riferimento appArmorProfile)
kubectl apply -k .
```

- **Repliche**: parametro `REPLICAS` (Deployment o HPA). Con repliche > 1 il PVC
  del codice deve essere **ReadWriteMany** (lo script lo imposta).
- Il `Service` (`:80 → 8080`) va esposto con un Ingress/Gateway (la TLS termina
  lì; imposta `session.cookie_secure=on` via `X-Forwarded-Proto`).

## Stato di validazione

Verificato buildando ed eseguendo il bundle di un sito reale su Docker: immagini
che buildano, estensioni funzionanti (gd/zip/intl/redis), container **non-root +
read-only rootfs + cap-drop ALL + no-new-privileges + shell-less**, modello
identità fedele (**scrittura del codice negata, scrittura upload consentita**),
profilo AppArmor che carica, tutti i manifest k8s validi.
