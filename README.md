# Leazone

Serveur **DNS + DHCP** léger, avec haute disponibilité, interface web moderne, conçu pour Docker.

> **État : phase 1 sur 6.** Disponible : l'application, l'interface web, l'authentification complète
> (mots de passe, passkeys, TOTP, codes de secours, sessions, rôles, jetons d'API, audit) et l'image Docker.
> DNS (phase 2), DHCP (phase 3), HA (phase 4), blocage et DNSSEC (phase 5) arrivent ensuite.
> Le plan complet est dans [docs/PLAN.md](docs/PLAN.md).

---

## Installation (3 commandes)

Prérequis : un hôte Linux avec Docker et le plugin compose.

```bash
git clone https://github.com/prohand/leazone.git && cd leazone
```

```bash
cp compose/.env.example compose/.env && mkdir -p compose/secrets && touch compose/secrets/admin_password
```

```bash
docker compose -f compose/single.yml --env-file compose/.env up -d --build
```

Puis :

- Le mot de passe du compte `admin` s'affiche **une seule fois** dans les journaux :
  ```bash
  docker logs leazone
  ```
  Pour le choisir vous-même, écrivez-le dans `compose/secrets/admin_password` **avant** le premier démarrage.
- Ouvrez `https://<ip-ou-nom-de-l-hôte>:8443`.
- Au premier login, Leazone **impose la configuration du MFA** (passkey ou TOTP) et donne 10 codes de secours. Gardez-les.

> Tant que l'image n'est pas publiée sur `ghcr.io/prohand/leazone`, `--build` la construit sur place.

### Ce que fait le fichier compose

| Réglage | Pourquoi |
|---|---|
| `network_mode: host` | Obligatoire pour le DHCP : le conteneur doit recevoir les broadcasts de chaque interface et VLAN de l'hôte |
| `user: 1000:1000` | Leazone ne tourne jamais en root |
| `read_only: true` + tmpfs `/tmp` | Rien n'est écrit hors de `/data`, `/logs` et `/tmp` |
| `cap_drop: ALL` + `NET_BIND_SERVICE`, `NET_RAW` | Seules les capabilities utiles (ports 53/67, sockets DHCP). `NET_ADMIN` seulement pour l'IP virtuelle (HA) |
| `no-new-privileges: true` | Aucune élévation de privilèges possible |
| secret `admin_password` | Le mot de passe initial n'est jamais dans une variable d'environnement |

### Volumes

| Dossier | Contenu |
|---|---|
| `/config` | `leazone.yaml` (optionnel) |
| `/data` | base SQLite, clé maître (`keys/`), certificats (`tls/`), sauvegardes avant migration (`backups/`) |
| `/logs` | `leazone.log` (JSON, rotation 20 Mo × 5). Les journaux vont aussi dans `docker logs` |

**Sauvegarde du volume `/data`** (nœud arrêté ou non, la base est en mode WAL) :

```bash
docker run --rm -v leazone_leazone-data:/data:ro -v "$PWD":/backup alpine tar czf /backup/leazone-data.tgz -C /data .
```

Gardez cette archive en lieu sûr : elle contient la clé maître qui déchiffre les secrets.

---

## Derrière nginx (HTTPS + passkeys)

Les passkeys exigent **un nom de domaine** et **un certificat de confiance**. Le plus simple : nginx porte
le certificat de votre PKI et renvoie vers Leazone.

1. Dans `compose/.env` :
   ```dotenv
   LEAZONE_PUBLIC_URL=https://leazone.mondomaine.lan
   LEAZONE_TRUSTED_PROXIES=127.0.0.1          # IP de nginx (ici sur le même hôte)
   ```
2. Configuration nginx :
   ```nginx
   server {
       listen 443 ssl;
       http2 on;
       server_name leazone.mondomaine.lan;

       ssl_certificate     /etc/nginx/tls/leazone.crt;
       ssl_certificate_key /etc/nginx/tls/leazone.key;
       add_header Strict-Transport-Security "max-age=31536000" always;

       location / {
           proxy_pass https://127.0.0.1:8443;
           proxy_ssl_server_name on;
           # Optionnel : épingler le certificat de Leazone (Paramètres > HTTPS > empreinte)
           # proxy_ssl_trusted_certificate /etc/nginx/tls/leazone-backend.pem;
           # proxy_ssl_verify on;

           proxy_set_header Host              $host;
           proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;
           proxy_set_header X-Forwarded-Proto https;
           proxy_set_header X-Forwarded-Host  $host;

           # Événements temps réel (SSE)
           proxy_buffering    off;
           proxy_read_timeout 1h;
       }
   }
   ```
3. Redémarrez Leazone : `docker compose -f compose/single.yml --env-file compose/.env up -d`.

Pourquoi `LEAZONE_TRUSTED_PROXIES` : Leazone n'accepte `X-Forwarded-For` **que** de ces adresses. Il connaît ainsi la
vraie IP du client (blocage après échecs, audit, liste d'IP autorisées) sans qu'un client puisse mentir sur son IP.

**Sans nginx** : importez votre certificat dans *Paramètres > HTTPS*, ou déposez `cert.pem` + `key.pem`
dans `/data/tls/` puis redémarrez. Le certificat auto-signé créé au premier démarrage ne sert qu'à l'installation.

**En HA** (phase 4) : nginx pointera vers l'IP virtuelle, pour garder le même nom (et donc les mêmes passkeys) après une bascule.

---

## Comptes et sécurité

- **Rôles** : `admin` (tout), `operator` (baux, réservations, enregistrements DNS), `readonly` (lecture seule).
- **MFA** : passkeys (YubiKey, Windows Hello, Touch ID, Face ID, gestionnaires de mots de passe) ou TOTP
  (Google Authenticator, Aegis, Bitwarden…). Règles dans *Paramètres > Sécurité*.
- **Actions sensibles** (supprimer un utilisateur, changer la sécurité, importer un certificat…) : Leazone redemande
  une passkey ou un code TOTP si la dernière vérification date de plus de 5 minutes.
- **Blocage** : 5 échecs sur un compte (ou 20 depuis une IP) → blocage 1 min, doublé à chaque nouvel échec (max 1 h).
- **Jetons d'API** (*Mon compte > Jetons*) : `Authorization: Bearer lz_…`. Un jeton « lecture » ne fait que des GET,
  et un jeton n'a jamais plus de droits que son propriétaire.
- **API** : spec OpenAPI sur `/api/v1/openapi.json` (source : [api/openapi.yaml](api/openapi.yaml)).

### Commandes de secours

Elles passent par un socket local du conteneur : il faut un accès à l'hôte.

```bash
docker exec -it leazone leazone admin reset-mfa <utilisateur>
```

```bash
docker exec -it leazone leazone admin reset-password <utilisateur>
```

```bash
docker exec -it leazone leazone admin reset-ui-allowlist
```

---

## Configuration

Tout se règle par variables d'environnement (prioritaires) ou dans `/config/leazone.yaml`.

| Variable | Défaut | Rôle |
|---|---|---|
| `LEAZONE_PUBLIC_URL` | vide | URL tapée dans le navigateur (`https://…`) |
| `LEAZONE_TRUSTED_PROXIES` | vide | IP/réseaux des reverse proxies de confiance |
| `LEAZONE_HTTP_LISTEN` | `:8443` | Adresse de l'interface web / API |
| `LEAZONE_ADMIN_USER` | `admin` | Nom du premier compte |
| `LEAZONE_ADMIN_PASSWORD_FILE` | vide | Fichier (secret Docker) du mot de passe initial |
| `LEAZONE_LOG_LEVEL` | `info` | `debug`, `info`, `warn`, `error` |
| `LEAZONE_LOG_FORMAT` | `text` | Format de `docker logs` : `text` ou `json` |
| `LEAZONE_DATA_DIR` / `LEAZONE_LOG_DIR` / `LEAZONE_CONFIG_DIR` | `/data` `/logs` `/config` | Dossiers |

Les secrets ne se passent **que** par fichier (`LEAZONE_*_FILE`). Une variable secrète en clair est refusée,
sauf `LEAZONE_ALLOW_PLAIN_SECRETS=true` (déconseillé).

Exemple de `leazone.yaml` :

```yaml
public_url: https://leazone.mondomaine.lan
trusted_proxies: [127.0.0.1]
http_listen: ":8443"
log_level: info
```

---

## Mises à jour

Au démarrage, Leazone met la base à jour tout seul, **après** en avoir fait une copie dans `/data/backups/`
(5 dernières gardées).

```bash
docker compose -f compose/single.yml --env-file compose/.env pull
```

```bash
docker compose -f compose/single.yml --env-file compose/.env up -d
```

Revenir à une version précédente : avec la **nouvelle** image, nœud arrêté, ramenez la base au schéma attendu par
l'ancienne version (`leazone version` affiche le schéma), puis lancez l'ancienne image :

```bash
docker compose -f compose/single.yml --env-file compose/.env run --rm leazone migrate down --to 1
```

La procédure sans coupure en HA arrive avec la phase 4.

---

## Dépannage

**Le conteneur ne démarre pas : « n'est pas accessible en écriture pour l'UID … »**
Vous avez changé `LEAZONE_UID`/`LEAZONE_GID`. Donnez les volumes à ce compte :

```bash
docker run --rm -v leazone_leazone-data:/d -v leazone_leazone-logs:/l alpine chown -R 1001:1001 /d /l
```

**« le port de l'interface web … est déjà utilisé »**
Un autre service écoute sur 8443. Changez `LEAZONE_HTTP_LISTEN` (ex : `:9443`).

**Port 53 déjà pris (systemd-resolved)** — concerne la phase 2.
Leazone n'écoute que sur les IP choisies, donc pas sur `127.0.0.53` : pas de conflit dans le cas normal.
Si un service écoute en `0.0.0.0:53`, désactivez-le, ou pour systemd-resolved :
`DNSStubListener=no` dans `/etc/systemd/resolved.conf`, puis `systemctl restart systemd-resolved`.

**Les passkeys sont refusées ou le bouton est grisé**
- Ouvrez l'interface par un **nom de domaine**, pas par une IP.
- Le certificat doit être **de confiance** pour le navigateur (pas l'auto-signé).
- Derrière nginx : `LEAZONE_PUBLIC_URL` doit être exactement l'URL du navigateur, et `LEAZONE_TRUSTED_PROXIES` l'IP de nginx.
- Si vous avez réglé un RP ID (*Paramètres > Sécurité*), le nom du navigateur doit être ce domaine ou un sous-domaine.
- Une passkey est liée au nom : si vous changez de nom, il faut en enregistrer une nouvelle.

**Je me suis bloqué avec la liste d'IP autorisées**
`docker exec -it leazone leazone admin reset-ui-allowlist`.

**Vérifier les capabilities effectives**
`docker exec leazone leazone caps` affiche par exemple `NET_BIND_SERVICE=yes NET_RAW=yes NET_ADMIN=no`.

---

## Développement

```bash
cd web && npm ci && npm run build && cd ..
```

```bash
go test ./...
```

```bash
test/integration/phase1.sh
```

Le binaire seul fonctionne aussi hors Docker (`go build ./cmd/leazone`), avec `LEAZONE_DATA_DIR`,
`LEAZONE_LOG_DIR` et `LEAZONE_CONFIG_DIR` pointant vers des dossiers accessibles.
