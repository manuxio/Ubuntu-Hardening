# dockerize.md — containerizzare un sito hardenizzato

Guida pratica per trasformare un vhost già hardenizzato in un **container** che
mantiene gli **stessi controlli runtime** dell'host, come **docker-compose** (test
locali) e come **Kubernetes**. Per la mappa completa dei controlli e delle utenze
vedi [`docs/CONTAINERS.md`](docs/CONTAINERS.md); qui trovi il *come si fa*.

> Cosa **non** entra nel container: gli scanner di host/CI (Lynis, Trivy, OpenSCAP,
> YARA-X). Quelli restano sull'host. Nel container entrano i controlli **runtime**:
> non-root, read-only rootfs, cap-drop, no-new-privileges, seccomp, AppArmor,
> egress, `php_admin_*`, e il modello di permessi del codice.

---

## 1. Genera il bundle

**Dal menu** (consigliato): `harden-menu.sh` → **Gestisci siti** → *(scegli il
sito)* → **Containerizza: genera bundle compose + k8s**.

**Da CLI:**
```bash
sudo bash scripts/export-site.sh <sito> --both      # compose + k8s
#   --compose   solo docker-compose      --k8s   solo Kubernetes
```

Lo script legge lo stato del sito (`/etc/hardening/sites/<sito>/`) e **chiede**:

| Domanda | Default | Note |
|---|---|---|
| Nome immagine PHP-FPM / nginx | `<sito>-php:latest` / `<sito>-nginx:latest` | build & push tue |
| Path host da montare (compose) | il site-root dell'host | bind persistente `-v` |
| Porta host (compose) | `8080` | pubblica nginx localmente |
| Namespace k8s | `<sito>` | |
| Repliche k8s | `2` | > 1 richiede un PVC **ReadWriteMany** |
| HPA? | no | autoscaler su CPU |
| Redis? | no | backend sessioni/cache (DB resta esterno) |
| **Basic auth?** | no | protegge il container con user/password |
| StorageClass / PVC size | `standard` / `2Gi` | |

Ogni risposta è **env-overridable** per uso non interattivo, es.:
```bash
sudo env WANT_REDIS=yes REPLICAS=3 NAMESPACE=acme \
     WANT_BASICAUTH=yes BASICAUTH_USER=admin BASICAUTH_PASS='…' \
     bash scripts/export-site.sh acme --both
```

Output in `export/<sito>/{compose,k8s}/` con un `README.md` per-bundle.

---

## 2. Test locale con docker-compose

```bash
cd export/<sito>/compose
docker compose up -d --build
```

Il sito è servito su `http://localhost:<porta>/` (Host header = il dominio del
sito). Il tree del sito è **bind-mount persistente** allo stesso path dell'host:
deponi lì il codice (o via FTP, come sull'host).

Due opzioni consigliate:
```bash
# egress: limita l'uscita a DNS/DB/mail/443 (come il firewall per-uid dell'host)
sudo ./docker-egress.sh apply           # ./docker-egress.sh clear per rimuoverlo

# AppArmor (difesa in profondità): carica il profilo sull'host, poi 'up'
sudo apparmor_parser -r -W hardening-<sito>.aa
```

> **AppArmor nel container**: il bundle include il profilo per-sito
> `hardening-<sito>.aa` (no-exec + reach), **referenziato** dal compose
> (`security_opt: apparmor=…`). È applicato dal **kernel dell'host**, quindi va
> **caricato** prima di `up`; se non lo carichi, commenta la riga `apparmor=…` (gli
> altri strati — seccomp, cap-drop, RO-rootfs, no-new-privileges, immagine
> shell-less — restano attivi).

Verifica il contenimento:
```bash
curl http://localhost:<porta>/healthz            # 200 (nginx, senza PHP)
# il worker gira non-root, rootfs read-only, senza shell:
docker compose exec php id                        # (fallisce: niente shell)  -> ok
```

---

## 3. Deploy su Kubernetes

```bash
cd export/<sito>/k8s
# build & push delle immagini minimali (stesso contesto della compose)
docker build -f Dockerfile.php   -t <img-php>   . && docker push <img-php>
docker build -f Dockerfile.nginx -t <img-nginx> . && docker push <img-nginx>

# carica il profilo AppArmor su OGNI nodo (o togli 'appArmorProfile' dal Deployment)
sudo apparmor_parser -r -W hardening-<sito>.aa

kubectl apply -k .          # namespace + PVC + Deployment + Service + NetworkPolicy (+ hpa/redis)
```

- Il pod ha **due container** (php-fpm + nginx) che condividono `localhost`
  (nginx→php su `127.0.0.1:9000`, mai esposto).
- La **NetworkPolicy** consente solo DNS + DB + mail + 443 (serve un CNI che la
  applichi: Calico, Cilium…).
- Esponi il `Service` (`:80 → 8080`) con un Ingress/Gateway; la TLS termina lì.
  Metti `session.cookie_secure=on` propagando `X-Forwarded-Proto`.
- **Repliche > 1** → il PVC del codice dev'essere **ReadWriteMany** (lo script lo
  imposta; serve una StorageClass RWX: NFS, CephFS, EFS…).

---

## 4. Basic auth nel container

Se rispondi **sì** a *Basic auth*, lo script genera un `.htpasswd` (hash apr1) e lo
incorpora nell'immagine nginx (`/etc/nginx/.htpasswd`) con `auth_basic` a livello
server. Risultato:

- `/` senza credenziali → **401**; con credenziali corrette → l'app.
- `/healthz` resta **senza** auth (le sonde k8s funzionano).

Per cambiarla, rigenera il bundle con nuove credenziali e ri-builda l'immagine
nginx. (La basic auth **sull'host** è un'altra cosa: menu **Gestisci → Basic auth**,
vedi `GUIDA.md`.)

---

## 5. Personalizzazione

- **Repliche / HPA**: modifica `deployment.yaml` (o `hpa.yaml`) o rigenera con
  `REPLICAS=…`.
- **Redis**: `WANT_REDIS=yes` aggiunge il servizio + la sua NetworkPolicy e
  configura `session.save_handler=redis`.
- **Tunable PHP** (memoria, upload, workers): sono presi dal pool del sito; per
  cambiarli, aggiorna il sito (`tune-vhost` / menu) e rigenera.
- I manifest sono normali file kustomize: puoi editarli o comporli via
  `kustomization.yaml`.

---

## 6. Troubleshooting

- **nginx esce con `open("/tmp/nginx.pid") … Permission denied`**: manca la tmpfs
  `/tmp`. Compose e k8s la montano (mode 1777); se avvii un container a mano,
  aggiungi `--tmpfs /tmp:rw,mode=1777`.
- **`docker compose up` fallisce su `apparmor=…`**: il profilo non è caricato sul
  host → `sudo apparmor_parser -r -W hardening-<sito>.aa`, oppure commenta la riga.
- **PVC in Pending con repliche > 1**: la StorageClass non offre ReadWriteMany.
- **Estensioni PHP mancanti a runtime**: le immagini sono già validate (gd, zip,
  intl, mysqli, redis…); se ne servono altre, aggiungile al `Dockerfile.php` e
  ri-builda.
- **Cookie di sessione non `secure`**: dietro un Ingress TLS propaga
  `X-Forwarded-Proto=https` e imposta `session.cookie_secure=on`.

---

*Bundle validato su Docker: immagini che buildano, estensioni funzionanti,
container non-root + read-only + cap-drop ALL + no-new-privileges + shell-less,
codice non scrivibile dal runtime, basic auth (401/200) funzionante, profilo
AppArmor che parsa, manifest k8s validi.*
