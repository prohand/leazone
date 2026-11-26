# Changements

## 1.0.1

Version de correction : plus de 40 bugs trouvés par une revue du code, chacun avec un test de régression.

### À savoir avant la mise à jour
- Une restauration révoque toutes les sessions et tous les jetons d'API (il faut se reconnecter).
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
