# Leazone

Serveur **DNS + DHCP** léger, avec haute disponibilité, interface web moderne, conçu pour Docker.

Fonctions :

- **DNS** : zones locales, redirecteurs UDP/TCP/DoT/DoH avec bascule, cache, écoute par interface (jamais sur `0.0.0.0`).
- **DHCP multi-VLAN** : direct ou par relais, isolation stricte par réseau, option 82, réservations, DNS automatique.
- **Haute disponibilité** : 2 nœuds + témoin, bascule automatique en quelques secondes, IP virtuelle.
- **Modules** : blocage des publicités, DNSSEC (signature et validation).
- **Exploitation** : tableau de bord en direct, journaux des requêtes DNS et du DHCP, métriques Prometheus,
  sauvegarde/restauration en un fichier, import depuis Technitium.
- **Sécurité** : passkeys, TOTP, rôles, jetons d'API, audit ; conteneur non-root en lecture seule ; image signée.

Le plan et les choix techniques sont dans [docs/PLAN.md](docs/PLAN.md).

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

> `--build` construit l'image sur place. Pour utiliser l'image publiée (`ghcr.io/prohand/leazone`, amd64 et arm64),
> retirez `--build`. Vérifier sa signature : voir « Mises à jour ».

### Ce que fait le fichier compose

| Réglage | Pourquoi |
|---|---|
| `network_mode: host` | Obligatoire pour le DHCP : le conteneur doit recevoir les broadcasts de chaque interface et VLAN de l'hôte |
| `user: 1000:1000` | Leazone ne tourne jamais en root |
| `read_only: true` + tmpfs `/tmp` | Rien n'est écrit hors de `/data`, `/logs` et `/tmp` |
| `cap_drop: ALL` + `NET_BIND_SERVICE`, `NET_RAW` | Seules les capabilities utiles (ports 53/67, sockets DHCP). `NET_ADMIN` seulement pour l'IP virtuelle (HA) |
| `no-new-privileges: true` | Aucune élévation de privilèges possible |
| secret `admin_password` | Le mot de passe initial n'est jamais dans une variable d'environnement |

### Mode macvlan (alternative à `network_mode: host`)

Le conteneur a sa propre IP sur le réseau (comme une machine à part). Utile si l'hôte a déjà un DNS sur le port 53.

```yaml
services:
  leazone:
    networks:
      lan:
        ipv4_address: 192.168.1.53
networks:
  lan:
    driver: macvlan
    driver_opts:
      parent: eno1        # ou eno1.20 pour un VLAN
    ipam:
      config:
        - subnet: 192.168.1.0/24
          gateway: 192.168.1.1
```

Limites :

- **Un seul réseau par interface macvlan** : pour plusieurs VLAN en direct, ajoutez un réseau macvlan par VLAN
  (`parent: eno1.20`, `eno1.30`…), ou servez les VLAN par **relais DHCP** (recommandé dans ce mode).
- **L'hôte ne joint pas le conteneur** (règle du noyau Linux pour macvlan) : l'hôte lui-même ne peut pas utiliser
  ce DNS, sauf avec une interface macvlan supplémentaire côté hôte.
- L'IP virtuelle de la HA n'est pas gérée dans ce mode : utilisez `network_mode: host` pour la HA.

### Volumes

| Dossier | Contenu |
|---|---|
| `/config` | `leazone.yaml` (optionnel) |
| `/data` | base SQLite, clé maître (`keys/`), certificats (`tls/`), listes de blocage, journaux des requêtes (`logs.db`), sauvegardes (`backups/`) |
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
   LEAZONE_HTTP_LISTEN=127.0.0.1:8443         # seul nginx joint Leazone
   ```
   Par défaut (`:8443`), Leazone écoute sur **toutes** les interfaces de l'hôte (`network_mode: host`), VLAN clients
   compris. Avec `127.0.0.1:8443`, l'interface n'est plus joignable qu'à travers nginx. Limitez aussi qui peut
   l'ouvrir : *Paramètres > Sécurité > Réseaux autorisés pour l'interface* (ex : le réseau d'administration).
   Prometheus passe alors aussi par nginx (`https://leazone.mondomaine.lan/metrics`).
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

**En HA** : gardez le même nom (et donc les mêmes passkeys) après une bascule. Deux choix :

- nginx vers l'IP virtuelle : laissez `LEAZONE_HTTP_LISTEN=:8443` (l'IP virtuelle change d'hôte, Leazone doit
  écouter partout) et réglez la liste *Réseaux autorisés pour l'interface* (IP de nginx, réseau d'administration) ;
- ou chaque nœud n'écoute que sur son IP de gestion, dans `compose/.env` :
  `NODE1_HTTP_LISTEN=192.168.1.2:8443` et `NODE2_HTTP_LISTEN=192.168.1.3:8443`, et nginx envoie au nœud 1, puis au
  nœud 2 s'il ne répond pas :
  ```nginx
  upstream leazone {
      server 192.168.1.2:8443;
      server 192.168.1.3:8443 backup;
  }
  # puis, dans location / : proxy_pass https://leazone;
  ```
  `LEAZONE_TRUSTED_PROXIES` : l'IP de nginx (les deux IP de gestion si nginx tourne sur les nœuds eux-mêmes).

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

En HA, mettez les **deux** nœuds en `helper-address`.

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

## Modules optionnels : blocage et DNSSEC

Désactivés par défaut. *Paramètres > Modules* (admin) : on/off **sans redémarrage**, appliqué aux deux nœuds en HA.
Les pages *Blocage* et *DNSSEC* n'apparaissent que si le module est actif.

### Blocage des publicités et traqueurs

1. *Blocage > Listes > Ajouter* : une URL (formats hosts, domaines, AdBlock `||domaine^` ; détection automatique).
   Trois listes connues sont proposées en un clic. La liste est téléchargée tout de suite, puis toutes les 24 h
   (réglable) ; bouton **Mettre à jour maintenant**.
2. **Liste noire / liste blanche** manuelles : un domaine bloque ou autorise aussi ses sous-domaines.
   **La liste blanche gagne toujours.** Les exceptions AdBlock (`@@||domaine^`) sont respectées.
3. **Où bloquer** : par réseau client (ex : `192.168.30.0/24`), par VLAN ou par interface.
   La règle la plus précise gagne (réseau, puis VLAN, puis interface), sinon le réglage par défaut.
4. **Réponse** : `NXDOMAIN` (défaut) ou adresse nulle `0.0.0.0` / `::`. La réponse porte le code EDE « Blocked ».
5. **Pause** : 5 min, 1 h, 24 h (les deux nœuds), bouton *Reprendre*.

Les traqueurs cachés derrière un CNAME (« CNAME cloaking ») sont bloqués aussi. *Tester un domaine* dit si un nom
est bloqué et par quelle liste. Les statistiques (% bloqué, domaines les plus bloqués) sont celles du nœud affiché.
En HA, chaque nœud télécharge les listes lui-même (seul l'abonnement est répliqué).

> Le conteneur télécharge les listes : il lui faut un accès HTTPS sortant (proxy : `HTTPS_PROXY` est respecté).

### DNSSEC : signer vos zones

1. *DNSSEC* > choisir la zone > **Signer la zone** : ECDSA P-256 (recommandé) ou Ed25519, NSEC3 (recommandé,
   cache la liste des noms) ou NSEC.
2. Copiez l'enregistrement **DS** affiché et donnez-le à votre registrar (bureau d'enregistrement).
3. Une fois le DS publié, cliquez **J'ai publié le DS**.

| Clé | Rôle | Changement |
|---|---|---|
| ZSK | Signe les enregistrements | **Automatique** tous les 90 jours (nouvelle clé annoncée 2 h avant, ancienne gardée 2 jours) |
| KSK | Signe les clés (c'est elle que vise le DS) | **Manuel** : *Changer la KSK*, publiez le nouveau DS, puis *J'ai publié le DS* |

- Les clés sont créées une seule fois sur le primaire puis **répliquées chiffrées** : les deux nœuds signent avec les
  mêmes clés. Les signatures sont valables 15 jours et renouvelées chaque jour, sans action.
- *Exporter les clés* (admin + revérification passkey/TOTP) : fichier au format BIND, **contient les clés privées**.
- *Arrêter la signature* : **retirez d'abord le DS chez le registrar**, sinon les résolveurs qui valident
  ne pourront plus joindre la zone.

Vérifier depuis un poste (BIND 9.18+), avec le DS de la zone :

```bash
cat > anchors.conf <<'END'
trust-anchors { maison.lan. static-ds 12345 13 2 "ABCDEF..."; };
END
delv @192.168.1.2 -a anchors.conf +root=maison.lan nas.maison.lan A   # « ; fully validated »
```

### DNSSEC : valider les réponses des redirecteurs

Option séparée (*Paramètres > Modules*). Leazone vérifie lui-même la chaîne de confiance depuis la racine
(ancres officielles de l'IANA, clés 20326 et 38696) :

- réponse signée et valide : bit **AD** pour les clients qui le demandent ;
- domaine non signé (prouvé par la zone parente) : réponse normale, sans AD ;
- signature fausse ou absente là où elle est obligatoire : **SERVFAIL** (code EDE « DNSSEC Bogus »).
  Un client peut passer outre avec le bit CD (`dig +cd`).

> Les redirecteurs doivent transmettre les données DNSSEC (1.1.1.1, 9.9.9.9, 8.8.8.8 le font). Un redirecteur
> qui les supprime rend tous les domaines signés « bogus » : désactivez alors la validation.

---

## Tableau de bord, journaux et supervision

### Tableau de bord

Mis à jour en direct (toutes les 2 s) : requêtes/s, taux de cache, top domaines, top clients, domaines bloqués,
remplissage de chaque étendue DHCP, état de la HA. Ce sont les chiffres **du nœud affiché**.

### Journaux (page *Journaux*)

| Onglet | Contenu |
|---|---|
| Requêtes DNS | Heure, client, nom, type, réponse, origine (local, cache, redirecteur, bloqué…), latence. Filtres par nom, client ou réseau (`192.168.20.0/24`), type, réponse, origine, période. Mode « suivre en direct » |
| DHCP | Offres, attributions, refus (NAK) avec la raison, libérations, conflits, baux expirés, et clients **ignorés** (aucune étendue pour leur interface ou relais : utile quand un poste n'a pas d'IP) |
| Audit | Connexions et modifications (qui, quoi, quand, depuis quelle IP) |

- Stockés dans `/data/logs.db`, **par nœud** (non synchronisés).
- Rétention réglable : 7 jours et 500 Mo par défaut ; les plus anciens partent en premier.
- Journalisation DNS désactivable (vie privée, ou très gros trafic). Sous forte charge, des entrées peuvent être
  sautées plutôt que de ralentir le DNS : le compteur « non écrites » l'indique.

### Prometheus

`/metrics` demande un **jeton d'API** (*Mon compte > Jetons d'API*, portée « lecture » suffisante) :

```yaml
scrape_configs:
  - job_name: leazone
    scheme: https
    authorization:
      credentials_file: /etc/prometheus/leazone_token
    tls_config:
      insecure_skip_verify: true   # ou ca_file: … si le certificat n'est pas public
    static_configs:
      - targets: ["192.168.1.2:8443", "192.168.1.3:8443"]
```

| Métrique | Contenu |
|---|---|
| `leazone_dns_queries_total`, `leazone_dns_answers_total{source}` | Requêtes, réponses par origine |
| `leazone_dns_cache_hits_total`, `leazone_dns_cache_entries` | Cache |
| `leazone_dns_forwarder_up`, `leazone_dns_forwarder_latency_seconds` | État de chaque redirecteur |
| `leazone_dhcp_scope_addresses`, `…_used_addresses`, `…_active_leases` | Remplissage des étendues |
| `leazone_blocking_blocked_total`, `leazone_blocking_paused` | Blocage |
| `leazone_cluster_role{role}`, `leazone_cluster_peer_up`, `leazone_cluster_witness_reachable` | HA |

Exemple d'alerte : `leazone_dhcp_scope_used_addresses / leazone_dhcp_scope_addresses > 0.9`.

`/health` (sans authentification) répond `{"status":"ok"}` : pour un équilibreur ou une supervision simple.

---

## Sauvegarde et restauration

Toute la configuration (utilisateurs, passkeys, TOTP, jetons, certificat, zones, redirecteurs, étendues,
réservations, VLAN, blocage, clés DNSSEC, réglages) tient dans **un fichier YAML**. Les secrets restent chiffrés ;
leur clé est chiffrée par **votre mot de passe** (Argon2id + AES-256-GCM). Le fichier est aussi protégé contre
toute modification. Les baux DHCP et les journaux n'y sont pas (les clients renouvellent leurs adresses).

**Depuis l'interface** : *Paramètres > Sauvegarde* (admin, revérification passkey/TOTP).

**En ligne de commande** :

```bash
docker exec leazone leazone backup --password-file /run/secrets/backup_password > leazone-backup.yaml
```

```bash
docker exec -i leazone leazone restore - --password-file /run/secrets/backup_password < leazone-backup.yaml
```

(`--dry-run` vérifie le fichier et le mot de passe sans rien changer.)

**Sauvegarde automatique** : donnez un mot de passe par `LEAZONE_BACKUP_PASSWORD_FILE` (lignes prêtes, en commentaire,
dans les fichiers compose). Leazone écrit alors chaque jour `/data/backups/leazone-AAAAMMJJ.yaml` et garde les 7 derniers.
Avec ce réglage, `--password-file` devient inutile dans les commandes ci-dessus.

Bon à savoir :

- La restauration **remplace** toute la configuration. Les comptes, passkeys et TOTP redeviennent ceux de la sauvegarde :
  sur une installation neuve, reconnectez-vous avec le compte admin **de la sauvegarde**.
- Les passkeys restent valables si l'adresse de l'interface (`LEAZONE_PUBLIC_URL`) est la même.
- En HA, restaurez sur le **primaire** : le secondaire reprend tout seul la nouvelle configuration.
- Une sauvegarde faite par une version plus récente est refusée (mettez Leazone à jour d'abord).
- Perte du mot de passe = sauvegarde inutilisable. Gardez-le avec vos codes de secours.

---

## Haute disponibilité en 5 minutes

Deux nœuds Leazone (un conteneur par hôte) et un **témoin** sur un 3e hôte (petite VM, NAS, Raspberry Pi).

```text
   hôte 1 (dns1)            hôte 2 (dns2)            hôte 3
 ┌──────────────┐  7443  ┌──────────────┐         ┌─────────┐
 │ leazone      │◄──────►│ leazone      │         │ témoin  │
 │ primaire     │ mTLS   │ secondaire   │         │         │
 └──────┬───────┘        └──────┬───────┘         └────▲────┘
        └────────── 7443 ───────┴───────── 7443 ───────┘
        IP virtuelle 192.168.1.10 (portée par le primaire)
```

1. **Une clé de cluster**, la même partout (c'est elle qui authentifie les nœuds entre eux) :
   ```bash
   mkdir -p compose/secrets && openssl rand -base64 32 > compose/secrets/cluster_key && touch compose/secrets/admin_password
   ```
   Copiez `compose/secrets/cluster_key` sur les 3 hôtes.
2. **Le témoin** (hôte 3) :
   ```bash
   docker compose -f compose/witness.yml up -d
   ```
3. **La configuration** (identique sur les hôtes 1 et 2) :
   ```bash
   cp compose/.env.ha.example compose/.env
   ```
   Renseignez `NODE1_IP`, `NODE2_IP`, `LEAZONE_WITNESS=https://<ip-témoin>:7443`, et si vous voulez une IP virtuelle :
   `LEAZONE_VIP` et `NODE1_VIP_INTERFACE` / `NODE2_VIP_INTERFACE`.
4. **Les nœuds** :
   ```bash
   docker compose -f compose/ha-node1.yml --env-file compose/.env up -d
   ```
   ```bash
   docker compose -f compose/ha-node2.yml --env-file compose/.env up -d
   ```
5. Ouvrez l'interface du nœud 1 (ou l'IP virtuelle) : la page **Cluster** montre le primaire, le secondaire et le témoin.
   Configurez tout sur le primaire : le secondaire reçoit chaque modification, en lecture seule.

Ports à ouvrir entre les hôtes : **TCP 7443** (nœuds ↔ nœuds, nœuds → témoin).

Les deux hôtes doivent avoir **les mêmes noms d'interfaces** pour les VLAN servis en direct (ex : `eno1.20` des deux
côtés) : la configuration, répliquée, désigne les interfaces par leur nom. La page Cluster signale un VLAN présent sur
un seul nœud.

### Ce qui se passe en cas de panne

| Événement | Réaction |
|---|---|
| Le primaire ne répond plus (3 heartbeats manqués, 3 s par défaut) | Le secondaire demande le rôle au témoin ; le témoin l'accorde quand le bail du primaire a expiré (6 s) et si le secondaire a **toutes** les modifications validées. Il prend l'IP virtuelle (ARP gratuit) et sert tous les clients DHCP |
| Le lien entre les deux nœuds est coupé, les deux voient le témoin | Le primaire garde son bail, le secondaire ne peut pas le prendre : **jamais deux primaires** |
| Le primaire perd tout le réseau | Il redevient secondaire de lui-même (plus de quorum) avant que le témoin ne donne le rôle à l'autre |
| L'ancien primaire revient | Toujours **secondaire d'abord**, resynchronisation, puis retour à son rôle (auto après 5 min par défaut, ou bouton *Rebasculer*) |
| Modification faite sur un primaire juste avant qu'il soit coupé, jamais transmise | Rien n'est perdu en silence : elle apparaît dans *Cluster > Conflits*, avec *Réappliquer* / *Ignorer* |

Mesuré dans les tests Docker : promotion du secondaire **4 s** après l'arrêt du primaire, DNS de nouveau servi
sur l'IP virtuelle 4,3 s après la panne.

### Le témoin : conteneur ou IP à pinger

| `LEAZONE_WITNESS` | Protection |
|---|---|
| `https://<ip>:7443` (conteneur témoin) | **Complète** : jamais deux primaires, et un nœud en retard ne peut pas devenir primaire |
| `ping:<ip>` (ex : la passerelle) | **Partielle** : protège si un nœud est isolé, mais si seul le lien entre les deux nœuds coupe, les deux peuvent devenir primaires. Le DHCP reste sûr (chaque nœud ne donne que ses propres adresses) ; les modifications faites des deux côtés finissent en conflits |
| vide | Pas de bascule automatique : bouton *Promouvoir ce nœud* sur la page Cluster |

### DHCP en HA

- **Load-balancing** (par défaut) : chaque client est servi par un seul nœud selon le hachage de sa MAC ou de son
  identifiant client (RFC 3074), environ 50/50. Chaque nœud ne donne de **nouvelles** adresses que dans sa moitié de la plage,
  et chaque bail est envoyé à l'autre nœud **avant** l'accusé de réception au client. Un même bail ne peut donc jamais
  être donné à deux clients, même si les nœuds sont coupés l'un de l'autre.
- Quand le témoin confirme que l'autre nœud est en panne, le survivant sert tous les clients et toute la plage.
- Un client qui attend depuis 5 s ou plus (l'autre nœud redémarre, par exemple) est servi par n'importe quel nœud,
  toujours dans la moitié de plage de ce nœud.
- **Actif/passif** (*Cluster > Paramètres*) : seul le primaire répond.
- Relais : mettez les **deux** nœuds en `ip helper-address`.

### Passkeys et HTTPS en HA

Utilisez **le même nom** pour les deux nœuds (celui de l'IP virtuelle, ou nginx devant l'IP virtuelle) et le même
`LEAZONE_PUBLIC_URL`. Une passkey est liée à un nom : avec un nom par nœud, elle ne marcherait plus après une bascule.
Le certificat importé est répliqué (chiffré) sur les deux nœuds.

### Mise à jour sans coupure

1. Mettez à jour le **secondaire** :
   ```bash
   docker compose -f compose/ha-node2.yml --env-file compose/.env pull
   ```
   ```bash
   docker compose -f compose/ha-node2.yml --env-file compose/.env up -d
   ```
   Pendant que les versions diffèrent, la configuration est **en lecture seule** (bandeau orange) ; DNS, DHCP et baux
   continuent d'être servis et synchronisés.
2. Mettez à jour le **primaire** de la même façon (`ha-node1.yml`). Le secondaire prend le relais pendant le redémarrage,
   puis le nœud 1 reprend son rôle.
3. Les deux nœuds ont la même version : la configuration redevient modifiable.

Deux versions trop éloignées (version majeure différente, ou plus d'une version mineure d'écart) refusent de se
synchroniser, avec un message clair sur la page Cluster : mettez-les à jour l'une après l'autre.

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
| `LEAZONE_BACKUP_PASSWORD_FILE` | vide | Mot de passe des sauvegardes automatiques et de `leazone backup/restore` |
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

Images publiées : `ghcr.io/prohand/leazone` pour amd64 et arm64 (Raspberry Pi 4/5, serveurs ARM), avec les tags
`1.2.3`, `1.2` et `latest`. Chaque image a son SBOM (liste des composants) et est **signée** (cosign, sans clé,
par GitHub Actions). Vérifier avant de déployer :

```bash
cosign verify ghcr.io/prohand/leazone:1.2.3 --certificate-identity-regexp 'https://github.com/prohand/leazone/.github/workflows/release.yml@.*' --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

Pour suivre les correctifs sans changer de version mineure, mettez `LEAZONE_IMAGE=ghcr.io/prohand/leazone:1.2` dans `.env`.

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

En HA, suivez « Mise à jour sans coupure » plus haut.

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

**Le blocage ne bloque rien**
- *Paramètres > Modules* : le module est-il actif ? *Blocage* : pas de pause en cours ?
- *Listes* : nombre d'entrées > 0 et pas d'erreur en rouge (le conteneur doit pouvoir sortir en HTTPS).
- *Tester un domaine* avec l'IP du client : « Le blocage ne s'applique pas à ce client » = une règle *Où bloquer*.
- Le navigateur garde ses propres réponses en cache quelques minutes, et certains utilisent leur propre DNS (DoH) :
  désactivez « DNS sécurisé » dans le navigateur.

**DNSSEC : tous les domaines répondent SERVFAIL**
La validation est active mais le redirecteur supprime les signatures, ou l'heure du serveur est fausse
(les signatures ont une date de validité). Vérifiez l'heure (`timedatectl`), changez de redirecteur ou
désactivez la validation.

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

**Le cluster ne se forme pas (page Cluster : nœud « hors ligne »)**
- TCP 7443 doit être ouvert entre les nœuds et vers le témoin (`nc -vz <ip> 7443`).
- La clé de cluster doit être **identique** partout (sinon : « certificat de cluster refusé »).
- `LEAZONE_CLUSTER_ADDR` / `NODEx_IP` : l'adresse que l'**autre** nœud utilise pour joindre celui-ci.

**Un nœud reste « isolé »**
Il ne voit ni le primaire ni le droit de devenir primaire (témoin injoignable, ou données en retard). Vérifiez le
témoin (`docker logs leazone-witness`) et la page Cluster (raison affichée). Sans témoin, utilisez *Promouvoir ce nœud*.

**« Ce nœud est secondaire : configuration en lecture seule »**
C'est normal : modifiez sur le primaire (lien dans le bandeau), ou passez par l'IP virtuelle.

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
