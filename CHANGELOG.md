# Changements

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
