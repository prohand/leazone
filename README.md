# Leazone

Serveur **DNS + DHCP** léger, avec haute disponibilité, interface web moderne, conçu pour Docker.

> **État : phase 3 sur 6.** Disponible : l'authentification complète (mots de passe, passkeys, TOTP,
> codes de secours, sessions, rôles, jetons d'API, audit), l'image Docker, le **DNS** (zones, redirecteurs
> UDP/TCP/DoT/DoH, cache, écoute par interface), le **DHCP multi-VLAN** (direct et relais, enregistrement DNS
> automatique) et l'**import depuis Technitium**. HA (phase 4), blocage et DNSSEC (phase 5) arrivent ensuite.
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

## DNS

### 1. Choisir où Leazone écoute

*Interfaces* liste les interfaces de l'hôte (physiques, VLAN 802.1Q, bonds, bridges) avec leurs IP.
Activez **DNS** sur les interfaces voulues : Leazone écoute en UDP et TCP sur **leurs IP seulement**
(jamais sur `0.0.0.0`). Une IP ou une interface ajoutée sur l'hôte est prise en compte sans redémarrer.

Les VLAN se créent **sur l'hôte** (netplan, systemd-networkd), pas dans Leazone. Exemple netplan :

```yaml
network:
  version: 2
  ethernets:
    eno1: {}
  vlans:
    eno1.20:
      id: 20
      link: eno1
      addresses: [192.168.20.2/24]
```

Pour écouter sur une IP hors interface (ex : `127.0.0.1`), utilisez *Paramètres > DNS > adresses d'écoute supplémentaires*.

### 2. Zones

- **Zone directe** : `maison.lan` → enregistrements A, AAAA, CNAME, MX, TXT, SRV, PTR, NS. Le SOA est géré par la zone
  (numéro de série mis à jour tout seul).
- **Zone inverse** : tapez simplement le réseau, ex. `192.168.20.0/24` → `20.168.192.in-addr.arpa`.
- Import / export au format BIND (fichier `.zone`), pratique pour migrer.
- Les zones locales répondent à **tous** les clients ; la récursion (noms externes) est limitée aux
  *réseaux autorisés* (par défaut : réseaux privés RFC 1918, CGNAT, loopback, ULA IPv6).

### 3. Redirecteurs

- **Globaux** : utilisés pour tout nom qui n'est pas dans une zone locale.
- **Conditionnels** : pour un domaine précis (ex : `corp.local` → le DNS de l'Active Directory).
- Protocoles : UDP, TCP, **DoT** (DNS over TLS, port 853), **DoH** (DNS over HTTPS).
- Ordre = priorité. Si un redirecteur ne répond pas, Leazone passe au suivant et le met de côté quelques secondes.
- Bouton **Tester** : vraie requête, avec la latence ou l'erreur en clair (certificat invalide, délai dépassé…).
- DoT/DoH : la vérification du certificat est active par défaut. Pour DoH, donnez l'**IP de démarrage**
  (Leazone ne peut pas résoudre le nom du serveur DoH avant d'avoir un redirecteur).

Exemples :

| Fournisseur | Protocole | Adresse | Nom TLS / URL |
|---|---|---|---|
| Quad9 | DoT | 9.9.9.9 | dns.quad9.net |
| Cloudflare | DoH | 1.1.1.1 | https://cloudflare-dns.com/dns-query |
| Google | DoT | 8.8.8.8 | dns.google |

### 4. Cache

TTL minimum / maximum, TTL négatif maximum et taille dans *Paramètres > DNS*. Bouton **Vider le cache**
(tout, ou un seul nom et ses sous-domaines).

---

## DHCP multi-VLAN

### Deux façons de servir un VLAN (utilisables en même temps)

| Mode | Quand | Réglage de l'étendue |
|---|---|---|
| **Direct** | L'hôte a une patte dans le VLAN (sous-interface sur un port trunk, ex : `eno1.20`) | *Interface* = `eno1.20`, et DHCP activé sur cette interface dans *Interfaces* |
| **Relais** | Le routeur ou le switch relaie les requêtes (`ip helper-address`, DHCP relay) | *Relais* activé. L'étendue est choisie selon l'adresse du relais (giaddr) |

Exemples de relais vers Leazone (IP `192.168.1.2`) :

```text
! Cisco IOS
interface Vlan40
 ip address 10.40.0.1 255.255.255.0
 ip helper-address 192.168.1.2
```

```text
# MikroTik RouterOS
/ip dhcp-relay add name=relay-vlan40 interface=vlan40 dhcp-server=192.168.1.2 local-address=10.40.0.1 disabled=no
```

En HA (phase 4), mettez les **deux** nœuds en `helper-address`.

### Isolation stricte

- Une requête reçue en direct ne sert **que** l'étendue liée à l'interface d'arrivée.
- Une requête relayée ne sert que l'étendue dont le réseau contient l'adresse du relais (ou ses *agents relais supplémentaires*).
- Aucune étendue trouvée → pas de réponse. Une demande d'adresse d'un autre réseau → refus (NAK).
- Deux étendues ne peuvent pas avoir des réseaux qui se chevauchent.

### Pour chaque étendue

Plage, exclusions, durée du bail, passerelle, DNS, domaine, NTP, options personnalisées (code + type + valeur),
réservations par MAC ou identifiant client, ping avant attribution (option, nécessite `NET_RAW`),
seuil d'alerte de remplissage (80 % par défaut).

### DNS automatique

Quand un client obtient un bail avec un nom d'hôte, Leazone crée :
- un **A** dans le domaine DNS de l'étendue (ex : `tablette.invites.lan`, zone créée si besoin) ;
- un **PTR** dans la zone inverse du réseau (créée automatiquement avec l'étendue).

Ils sont supprimés à la fin du bail. Un enregistrement **manuel** n'est jamais remplacé, et un nom déjà pris par
un autre client actif n'est pas volé. Le nom d'une réservation passe avant celui envoyé par le client.

### Pages utiles

- **VLAN** : une carte par VLAN avec le remplissage de chaque étendue, les baux actifs et le mode (direct/relais).
- **Baux** : temps réel, filtres par VLAN/étendue/état, option 82 (circuit-id, remote-id) des clients relayés,
  boutons *Libérer* et *Convertir en réservation*.

---

## Importer depuis Technitium

*Paramètres > Import* (admin) lit votre ancien serveur Technitium par son API HTTP :

1. Dans Technitium : *Administration > Sessions > Create Token* (ou utilisez un compte et son mot de passe).
2. Dans Leazone : URL (ex : `http://10.0.0.5:5380`), jeton, puis **Prévisualiser** : rien n'est écrit.
3. Vérifiez la liste, puis **Importer**.

| Importé | Détail |
|---|---|
| Zones primaires | Tous les enregistrements A, AAAA, CNAME, MX, TXT, SRV, PTR, NS. Les types propres à Technitium (APP, FWD, ALIAS…) sont ignorés et signalés |
| Zones « Forwarder » | Deviennent des redirecteurs conditionnels (UDP, TCP, DoT, DoH ; QUIC n'est pas géré) |
| Redirecteurs globaux | Seulement si Leazone n'en a pas encore |
| Étendues DHCP | Plage, masque, bail, passerelle, DNS, domaine, NTP, exclusions, options, ping, réservations. Mode direct si l'hôte a une interface dans le réseau, sinon relais |

Rien d'existant n'est écrasé : un objet du même nom est ignoré. Les baux en cours ne sont pas importés
(les clients renouvellent leur adresse auprès de Leazone). Le jeton ou le mot de passe ne sert que pour cette requête
et n'est pas enregistré.

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
| `LEAZONE_DNS_PORT` | `53` | Port du serveur DNS (à changer seulement pour des tests) |
| `LEAZONE_DHCP_PORT` | `67` | Port du serveur DHCP (les clients sont joints sur ce port + 1) |
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

**Port 53 déjà pris (systemd-resolved, dnsmasq…)**
La page *Interfaces* affiche l'erreur en rouge sous l'interface concernée (« le port 53 est déjà utilisé sur … »).
Leazone n'écoute que sur les IP choisies, donc pas sur `127.0.0.53` : pas de conflit avec systemd-resolved dans le cas normal.
Si un service écoute sur toutes les adresses (`0.0.0.0:53`), trouvez-le :

```bash
sudo ss -lntup | grep ':53 '
```

Pour systemd-resolved : `DNSStubListener=no` dans `/etc/systemd/resolved.conf`, puis `systemctl restart systemd-resolved`.
Leazone réessaie tout seul toutes les 20 secondes : pas besoin de le redémarrer.

**Un VLAN n'apparaît pas dans *Interfaces***
- Vérifiez sur l'hôte : `ip -d link show` doit montrer l'interface (ex : `eno1.20`, `vlan protocol 802.1Q id 20`).
- Le conteneur doit être en `network_mode: host` (sinon il ne voit que ses propres interfaces).
- Le module noyau `8021q` doit être chargé : `sudo modprobe 8021q`.
- Sans IP sur le VLAN, Leazone le voit mais ne peut pas y écouter : ajoutez une adresse dans netplan.

**Le DHCP ne répond pas**
- *Étendues* affiche un bandeau rouge si le port 67 est pris (`dnsmasq`, `isc-dhcp-server`, `kea`…) :
  `sudo ss -lunp | grep ':67 '`, puis arrêtez ce service.
- Mode direct : l'étendue doit avoir son *Interface*, **et** le DHCP doit être activé sur cette interface (*Interfaces*).
- Mode relais : *Relais* activé sur l'étendue, et l'adresse du relais (giaddr) dans le réseau de l'étendue
  (sinon ajoutez-la dans *agents relais supplémentaires*). Le pare-feu de l'hôte doit laisser passer UDP 67.
- Le conteneur doit être en `network_mode: host` pour recevoir les broadcasts.

**Le DNS ne répond pas aux clients d'un autre réseau**
Les noms locaux répondent à tous. Pour les noms externes, ajoutez le réseau des clients dans
*Paramètres > DNS > réseaux autorisés pour la récursion* (sinon réponse REFUSED).

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

```bash
sudo go test -tags integration -v ./test/integration/
```

Le binaire seul fonctionne aussi hors Docker (`go build ./cmd/leazone`), avec `LEAZONE_DATA_DIR`,
`LEAZONE_LOG_DIR` et `LEAZONE_CONFIG_DIR` pointant vers des dossiers accessibles.
