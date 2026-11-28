# Changements

## 1.1.0

Version de sécurité : correction de toutes les failles trouvées par une revue de sécurité complète (DNS, DHCP,
haute disponibilité, authentification, API, sauvegarde, interface, publication). Chaque correctif a son test.

### À savoir avant la mise à jour

**Haute disponibilité : mettez à jour les 3 hôtes ensemble.**
- Le protocole de cluster passe en 2.0 (clés dérivées par Argon2id) : un nœud 1.x et un nœud 1.1 ne se parlent plus.
  Mettez à jour à la suite le témoin, le nœud 1 puis le nœud 2 (`docker compose ... pull` puis `up -d`).
- Pendant ces quelques secondes : pas de split-brain (un nœud qui voit l'autre refuser ses certificats reste
  « incompatible », un primaire qui perd le témoin redevient secondaire). DNS reste servi, DHCP renouvelle les baux
  existants ; la configuration est en lecture seule et l'IP virtuelle peut manquer.
- Le témoin a maintenant sa propre clé et ne reçoit plus la clé de cluster. Un témoin qui reçoit encore
  `LEAZONE_CLUSTER_KEY_FILE` marche, avec un avertissement « SÉCURITÉ ». Migration (nouveau `compose/witness.yml`) :
  1. hôte 1 : `docker compose -f compose/ha-node1.yml --env-file compose/.env exec -T leazone /leazone cluster witness-key > witness_key`
  2. `scp witness_key <hôte3>:<dossier>/compose/secrets/witness_key && rm witness_key`
  3. hôte 3 : `docker compose -f compose/witness.yml up -d && rm compose/secrets/cluster_key`
- Une clé de cluster faible (moins de 32 octets aléatoires) est acceptée avec un avertissement.
  Pour en générer une : `openssl rand -base64 32` ou `leazone cluster gen-key`.

**DHCP**
- Relais : une requête relayée doit venir de l'adresse du relais (`giaddr`). Si votre relais envoie depuis une autre
  adresse, ajoutez-la dans les *agents relais supplémentaires* de l'étendue.
- Les options 82.5 et 118 ne sont suivies que si le relais est listé dans les *agents relais supplémentaires* de
  l'étendue visée ; sinon l'étendue est choisie d'après `giaddr`.
- INFORM : pas de réponse si l'adresse du client n'est pas dans le réseau de son étendue.
- Limites anti-inondation : 10 requêtes d'affilée puis 1/s par MAC, 200/s par interface ou relais.
- Les noms `wpad`, `isatap` et `localhost` envoyés par un client ne sont plus enregistrés dans le DNS
  (une réservation peut les garder).

**DNS**
- `100.64.0.0/10` (CGNAT) n'est plus dans les réseaux de récursion par défaut (sans effet si vos réglages DNS sont
  déjà enregistrés).
- `0.0.0.0` et `::` sont refusés comme adresses d'écoute supplémentaires ; une ancienne config qui les contient est
  ignorée avec un avertissement.
- Clients hors des réseaux autorisés : ANY ne renvoie qu'un type d'enregistrement, et au-delà de 20 réponses/s par
  /24 ou /56 les réponses sont tronquées ou ignorées. Le réseau local n'est jamais limité.
- Réponses UDP limitées à 1232 octets (au-delà, le client repasse en TCP). Au plus 1000 requêtes récursives en cours
  (100 par client) et 512 connexions TCP (32 par adresse).
- Les noms DHCP peuvent mettre jusqu'à 2 s à apparaître (rechargements regroupés).
- Leazone écoute aussi sur les IPv6 globales des interfaces où le DNS est activé : filtrez le port 53 au pare-feu.

**Connexion et comptes**
- Passkeys : sans `LEAZONE_PUBLIC_URL`, le nom tapé dans le navigateur doit être exactement le RP ID. Si vous avez un
  RP ID parent (ex. `mondomaine.lan`), réglez `LEAZONE_PUBLIC_URL=https://leazone.mondomaine.lan`.
- Jetons d'API : révoqués quand le rôle change ou que la politique MFA devient plus stricte ; refusés tant que le
  propriétaire n'a pas le facteur exigé.
- Opérateurs : ils ne peuvent plus mettre le blocage en pause, modifier les listes de domaines ni lancer la mise à
  jour des listes (réservé aux admins).
- Un compte sans facteur doit retaper son mot de passe pour ajouter une passkey, un TOTP ou un jeton si sa session a
  plus de 5 minutes. Après passage à « passkey uniquement », un compte qui n'a qu'un TOTP donne un code TOTP avant
  d'enregistrer sa passkey.
- Le cookie de session et le jeton CSRF changent à la fin de la connexion (les clients d'API par cookie doivent
  reprendre le `csrfToken` renvoyé).
- Au plus 4 vérifications de mot de passe à la fois ; au-delà de 2 s d'attente, réponse 429.

**Audit**
- Nouveau réglage de conservation, 365 jours par défaut : au premier démarrage, les lignes plus anciennes sont
  supprimées. Pour garder plus, réglez *Paramètres > Sécurité > Conservation du journal d'audit* (jusqu'à 3650 jours).
- Les nouvelles lignes sont signées (HMAC) ; les anciennes restent valides. Gardez les journaux du conteneur : les
  lignes `audit chain head` permettent de voir une suppression des dernières lignes.

**Sauvegarde, fichiers et socket**
- Restauration d'une sauvegarde de la même installation : un compte supprimé depuis revient désactivé et sans jeton ;
  un mot de passe changé, un compte désactivé ou un rôle abaissé depuis gardent leur valeur actuelle. Le résultat
  liste ces comptes. Une sauvegarde d'une autre installation est restaurée comme avant.
- `serve` et `witness` créent leurs fichiers avec umask 077 ; `/data/backups` passe en 0700, la base en 0600.
- Socket de contrôle : un dossier modifiable par d'autres (ex. `/tmp`) est refusé ; `leazone admin ...` sous un autre
  UID que le serveur est refusé (root autorisé).
- IP virtuelle : une `LEAZONE_VIP` égale à une adresse principale de l'hôte n'est plus ajoutée ni retirée.
- Import Technitium : appels en POST (identifiants hors de l'URL).

**Publication et vérification de l'image**
- Une release ne part plus que de `main` (tag `vX.Y.Z` sur un commit de `main`), après les tests, via
  l'environnement GitHub `release`.
- La commande `cosign verify` documentée n'accepte plus que `release.yml` lancé depuis `main` ou un tag `vX.Y.Z`.
- Images de base épinglées par digest ; la page Cluster n'ouvre plus de confirmation depuis un lien `?confirm=`.

### DNS et DNSSEC
- Validation DNSSEC : une réponse modifiée avec un faux signataire (`SignerName`) était acceptée comme non signée ;
  elle est maintenant rejetée (SERVFAIL). Même chose pour un faux NXDOMAIN.
- Jokers DNSSEC : le contrôle se fait sur la signature réellement vérifiée (plus de preuve d'absence sautée).
- Absence de DS acceptée comme « non signée » seulement pour une vraie délégation.
- Anti-amplification : ANY minimal (RFC 8482), taille UDP plafonnée, limitation de débit des réponses.
- Plafonds de requêtes récursives et de connexions TCP ; statistiques en coût constant.
- Import de zones : `$INCLUDE` n'est jamais suivi, même dans l'analyse ligne par ligne.

### DHCP
- Relais : un client ne peut plus obtenir un bail dans un autre VLAN en forgeant `giaddr` ou l'option 118.
- Inondation bornée : 64 requêtes traitées à la fois, limites par MAC et par interface, 16 ping-checks au plus,
  écritures en base groupées hors du verrou, pas de rechargement DNS si rien ne change.
- DNS automatique : noms sensibles refusés (`wpad`, `isatap`, `localhost`).

### Haute disponibilité
- Le témoin ne peut plus agir comme un nœud : clé et autorité séparées, rôle vérifié dans les certificats, identité
  du nœud liée à son certificat, passage de rôle (handoff) validé par le témoin.
- Clé de cluster dérivée par Argon2id (attaque hors ligne beaucoup plus coûteuse) ; nouvelles commandes
  `leazone cluster gen-key` et `leazone cluster witness-key`.

### Connexion, API et audit
- Un échec de connexion ne peut plus remplir le disque : nom d'utilisateur borné, champs d'audit tronqués, refus
  répétés regroupés, conservation réglable.
- Plus de saturation mémoire par les connexions (calculs Argon2 limités).
- Origine des passkeys prise dans la configuration, pas dans l'en-tête `Host`.
- Session renouvelée à la fin de la connexion ; défis passkey anonymes avec un quota séparé.
- Chaîne d'audit signée par HMAC et ancrée dans les journaux.
- En-tête HSTS avec un certificat importé en accès direct.
- Nouvelle métrique `leazone_dns_rate_limited_total` ; la restauration liste les comptes touchés dans l'audit.

### Sauvegarde, stockage et système
- Restauration : les accès retirés depuis la sauvegarde ne reviennent plus.
- Base SQLite et copies créées privées dès le départ ; socket de contrôle authentifié des deux côtés (UID du pair).
- Identifiants Technitium envoyés en POST ; l'adresse de l'hôte n'est jamais retirée par la gestion de l'IP virtuelle.

### Publication (CI)
- `release.yml` : plus d'injection par l'entrée `version`, publication depuis `main` seulement, tests avant
  publication, environnement d'approbation.
- Actions GitHub épinglées par SHA, Dependabot, scan des vulnérabilités (`govulncheck`, `npm audit`).
- `.dockerignore` : secrets locaux (`.env`, `*.pem`, `*.key`, `compose/secrets`) exclus du contexte de build.
- Documentation nginx : écouter l'interface sur `127.0.0.1:8443` derrière un proxy.

## 1.0.2

Version de correction de l'interface web : une soixantaine de bugs et défauts trouvés par une revue de l'interface,
vérifiés dans un navigateur (ordinateur et mobile, thèmes clair et sombre).

### À savoir avant la mise à jour
- La déconnexion après inactivité s'applique vraiment : un onglet ouvert qui se rafraîchit tout seul ne garde plus
  la session ouverte. Les requêtes avec l'en-tête `X-Leazone-Background: 1` ne comptent pas comme une activité.
- API : `/me` renvoie `totpAllowed` ; le tableau de bord renvoie `alertThreshold` et `alert` pour chaque étendue ;
  la source `blocked` est documentée pour le test de résolution.

### Connexion et compte
- Les codes de secours ne disparaissent plus pendant le premier enrôlement MFA.
- Une origine refusée (proxy mal réglé) affiche la vraie cause au lieu de « Session expirée ».
- Le cache est vidé quand un autre utilisateur se connecte dans le même onglet.
- Un code TOTP collé avec un espace est accepté ; le TOTP est présélectionné quand les passkeys sont impossibles.
- Jetons d'API et mots de passe temporaires : la fenêtre ne se ferme qu'avec « J'ai copié ».
- La reconfirmation d'identité ne propose plus le TOTP si la politique l'interdit.
- Les erreurs de chargement s'affichent au lieu de faux états vides ; les anciennes erreurs ne reviennent plus.

### DHCP
- Modifier une réservation garde à la fois la MAC et l'identifiant client.
- Formulaire d'étendue validé comme le serveur : options gérées par Leazone, adresses réseau et broadcast,
  préfixe, exclusions, durée de bail, passerelle dans la plage, DNS automatique sans domaine.
- Aperçu des zones inverses correct pour les préfixes non alignés (/20, /23).
- Désactiver une étendue demande confirmation ; le numéro d'un VLAN est verrouillé au renommage.
- Pas de « Convertir en réservation » sur les lignes sans MAC ; liens Ctrl+K vers les baux suivis sur la page.
- Bandeau « DHCP n'écoute pas » seulement quand une étendue est active.

### DNS, blocage et journaux
- La table des enregistrements ne déborde plus avec un nom long.
- Test de résolution : source « Bloqué » et recherche inverse IPv6.
- Validation IPv6 stricte ; TTL et SOA bornés comme le serveur.
- « Bloquer ce domaine » demande confirmation et refuse un nom à un seul label.
- Audit : tous les types d'action dans le filtre, avec des libellés en français.
- Tableau de bord : liens des tops sur 24 h, données périmées signalées, mêmes seuils d'usage DHCP partout.
- Taille des journaux en Mio, comme la limite appliquée par le serveur.

### Interface
- Contraste du orange et du vert corrigé en thème clair, badge TOTP lisible en thème sombre.
- Mobile : onglets à la ligne, colonnes secondaires masquées, filtres et messages vides non coupés.
- Accessibilité : un seul `<main>`, erreurs reliées aux champs, libellés et en-têtes d'actions.
- Réglages : validation en français, boutons actifs seulement après une modification.
- Cluster interrogé seulement si la haute disponibilité est configurée.

## 1.0.1

Version de correction : plus de 40 bugs trouvés par une revue du code, chacun avec un test de régression.

### À savoir avant la mise à jour
- Une restauration ferme toutes les sessions (il faut se reconnecter).
- Le socket de contrôle passe de `/tmp/leazone.sock` à `<data_dir>/run/leazone.sock`.
- Ajouter une passkey ou un TOTP, ou créer un jeton d'API, demande une revérification quand le compte a déjà un
  facteur. Changer de mot de passe ou réinitialiser la MFA révoque les jetons d'API.
- DHCP : un client ne garde qu'un bail par étendue.

### DHCP
- Une libération de bail avec une adresse IPv6 bloquait tout le moteur DHCP.
- Un renouvellement est refusé si l'adresse a été réservée pour un autre client, exclue ou sortie de la plage.
- Choix de l'étendue fiable avec un relais ; en actif/passif, le nœud passif ne répond plus.
- DECLINE accepté seulement du client qui a le bail ; un bail libéré depuis l'interface reçoit un NAK.
- La fin d'un ancien bail n'efface plus l'enregistrement DNS du nouveau.
- Horloge des baux monotone entre les deux nœuds ; contrôle des réservations quand une étendue change.
- Fuite mémoire et boucle à 100 % CPU (suivi des interfaces) corrigées.

### DNS
- Le cache de validation DNSSEC pouvait marquer « sûre » une réponse différente.
- Validation des jokers et des preuves NSEC/NSEC3 renforcée (RFC 6840).
- Bit CD et types inconnus pris en compte dans la clé du cache.
- Sous-zones déléguées et CNAME vers l'extérieur : passage par les redirecteurs, le blocage et la validation.
- Blocage : la liste noire manuelle passe avant les exceptions des listes abonnées.
- Pagination des journaux DNS avec un filtre réseau ; délai de retrait des anciennes clés ZSK.

### Haute disponibilité
- L'IP virtuelle restait sur l'hôte après un crash du conteneur.
- Le témoin compare aussi le mandat (epoch) : plus d'élection d'un nœud à qui il manque des changements validés.
- Un nœud coupé de son pair n'attribue plus de nouvelles adresses (plus d'IP en double).
- Baux conservés pendant une panne du pair, échange complet retenté jusqu'à réussite.
- Écritures en cours terminées avant un changement de rôle ; marge du bail du témoin élargie.
- Répartition DHCP correcte après la réinstallation d'un nœud.
- `migrate down` ne casse plus la base ; URL de pair avec « / » final acceptée ; erreur claire sans clé de cluster.

### Sécurité et exploitation
- Sauvegarde/restauration depuis l'interface web : erreur 500 corrigée.
- Un certificat expiré n'empêche plus le démarrage ; le certificat auto-signé se renouvelle en fonctionnement.
- Limite d'essais du second facteur séparée du mot de passe ; adresses IPv6 regroupées par /64.
- Changement de rôle ou de politique MFA : les sessions concernées sont révoquées.
- Restauration : jetons révoqués et codes de secours utilisés ne reviennent plus ; paramètres de chiffrement
  bornés ; refus d'une sauvegarde sans admin actif.
- Audit écrit même si le navigateur se déconnecte ; dernier admin protégé contre deux désactivations simultanées.

## 1.0.0

Première version publiée : `ghcr.io/prohand/leazone:1.0.0` (amd64 et arm64, SBOM, signée avec cosign).

### DNS
- Zones locales (A, AAAA, CNAME, MX, TXT, SRV, PTR, NS, jokers), import/export au format BIND.
- Redirecteurs UDP, TCP, DoT et DoH, avec bascule et redirecteurs par domaine.
- Cache, récursion limitée aux réseaux autorisés.
- Écoute seulement sur les IP des interfaces choisies (jamais `0.0.0.0`), interfaces ajoutées à chaud.

### DHCP
- Plusieurs VLAN en direct ou par relais (option 82, liens 82.5/118), isolation stricte par réseau.
- Réservations, options, ping avant attribution, enregistrement DNS automatique et zones inverses.
- Vue par VLAN, baux en temps réel.

### Haute disponibilité
- Deux nœuds + témoin (conteneur ou IP à pinger), bascule en quelques secondes, IP virtuelle (ARP gratuit).
- Configuration répliquée (secondaire en lecture seule), baux partagés, répartition 50/50 (RFC 3074) ou actif/passif.
- Retour du primaire d'origine, détection des écarts et des conflits, mise à jour sans coupure.

### Modules (désactivés par défaut)
- Blocage des publicités : listes par URL (hosts, domaines, AdBlock), listes noire et blanche, règles par
  interface/VLAN/réseau, pause, statistiques.
- DNSSEC : signature des zones (ECDSA P-256 ou Ed25519, NSEC ou NSEC3), changement automatique de ZSK,
  changement de KSK guidé, DS à copier ; validation des réponses des redirecteurs.

### Exploitation
- Tableau de bord en direct, journaux des requêtes DNS et des événements DHCP, audit.
- Métriques Prometheus (`/metrics`, jeton d'API), `/health`.
- Sauvegarde/restauration en un fichier YAML chiffré par mot de passe, sauvegarde quotidienne automatique.
- Import depuis Technitium.

### Sécurité
- Passkeys, TOTP, codes de secours, MFA imposé aux admins, rôles, jetons d'API, revérification pour les actions
  sensibles, blocage après échecs, audit chaîné.
- Conteneur non-root (UID 1000), système de fichiers en lecture seule, seules les capabilities utiles,
  secrets uniquement par fichier.
