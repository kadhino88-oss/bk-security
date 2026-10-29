# Phase 15 — contrat de déploiement portable

**Décision produit du 2026-10-24 :** conserver une cible indépendante d'un fournisseur cloud. Le format de livraison candidat est une image OCI et le contrat d'orchestration candidat est l'API Kubernetes, utilisable sur site ou chez un hébergeur compatible. Ce choix fixe une interface de déploiement; il ne sélectionne ni opérateur, ni région, ni fournisseur, et ne signifie pas que BK Security tourne déjà dans un conteneur.

## Unité d'isolation

- Un plan de données dédié correspond à un seul client et une seule région déclarée, avec son propre processus applicatif, identités, clés, stockage, files, exports et sauvegardes.
- Le plan de contrôle est facultatif et ne reçoit pas les événements bruts par défaut. Toute synchronisation doit être limitée aux métadonnées et politiques explicitement approuvées.
- Un namespace Kubernetes peut aider à appliquer des politiques, mais il ne sera pas considéré seul comme preuve d'isolation client. La topologie finale (namespace, nœuds dédiés, cluster dédié ou machine dédiée) doit être choisie selon le niveau de menace et vérifiée par des essais inter-clients.
- Les agents d'extrémité et les capteurs réseau appartiennent au réseau du client. Le service central d'ingestion ne doit pas exiger des privilèges d'administrateur hôte ni capturer implicitement le réseau du nœud.

## Portabilité et profil de sécurité candidat

Le package devra éviter les services propres à un fournisseur et déclarer ses dépendances via des interfaces explicites : volumes persistants, secrets fournis par le runtime, stockage/file remplaçables, identité de service, DNS et métriques. Les manifests devront prendre en charge une politique réseau par défaut restrictive, des limites CPU/mémoire, un système de fichiers racine en lecture seule lorsque compatible, un compte non privilégié, aucune capacité Linux superflue et aucun jeton d'API Kubernetes monté si le processus n'en a pas besoin. Le profil `Restricted` de Kubernetes est un point de départ pertinent pour les workloads Linux ; les exigences officielles couvrent notamment l'exécution non-root, l'interdiction de l'escalade de privilèges, le profil seccomp et la suppression des capacités Linux ([Pod Security Standards](https://kubernetes.io/docs/concepts/security/pod-security-standards/)). Les politiques réseau et la gestion de secrets doivent être configurées et testées sur chaque runtime ; la checklist Kubernetes indique aussi de ne pas mettre les données confidentielles dans les ConfigMaps, de chiffrer au repos les Secrets stockés dans etcd et de limiter les jetons de comptes de service ([Security Checklist](https://kubernetes.io/docs/concepts/security/security-checklist/), [Network Policies](https://kubernetes.io/docs/concepts/services-networking/network-policies/)).

Ces recommandations ne sont pas encore des configurations présentes dans le dépôt. Elles ne garantissent pas non plus, à elles seules, l'isolation du noyau, du stockage ou de l'administrateur de cluster.

## Barrière avant exposition réseau

Le serveur actuel n'est pas prêt à être exposé à des agents ou opérateurs distants : `bk_security/desktop_backend.py` écoute par défaut sur `127.0.0.1`, et `production_configuration_errors` refuse actuellement une adresse de production non-loopback. Les sessions utilisateur peuvent être révoquées dans le registre SQLite local, mais il n'y a pas encore d'IdP/MFA, de révocation administrateur synchronisée entre réplicas, de mTLS agent/service ou de passerelle d'ingestion distante. Les jetons locaux antérieurs sans identifiant de session restent actifs jusqu'à expiration et ne sont pas révocables; les anciens jetons dédiés sont invalidés lors de la mise à jour. Il ne faut donc pas contourner la vérification d'adresse pour rendre le backend accessible.

Le déploiement serveur ne pourra ouvrir une interface qu'après l'intégration et les tests de l'authentification opérateur et agent, de TLS/mTLS ou d'une frontière de proxy de confiance documentée, des quotas, de l'audit et de la séparation de rôles. L'interface ne devra jamais exposer l'API d'administration directement à Internet.

## Capacité et dépendances

SQLite/WAL lié à un fichier et le bus mémoire de la V1 restent adaptés au poste local et aux essais unitaires de la portée dédiée. Ils ne constituent pas un stockage de service distribué, une file durable avant accusé de réception, une réplication HA ou un moteur de recherche pour un milliard d'événements par jour. Le découpage en passerelle, file durable, consommateurs, stockage évolutif et rejeu relève de la phase 16. L'orchestration des agents de détection/investigation et Ollama facultatif relève de la phase 17; les actions de blocage/correction/vérification/restauration relèvent de la phase 18.

Le profil de 1 milliard d'événements/jour reste une hypothèse de dimensionnement de la phase 14. Aucune capacité, performance soutenue, disponibilité, perte nulle, RPO ou RTO n'est revendiqué avant un essai représentatif de la pile choisie.

## Critères de sortie avant un pilote portable

1. Image construite de façon reproductible, inventaire logiciel produit, artefact signé et signature vérifiée au déploiement.
2. Profil Linux de service séparé de l'application de bureau Windows, avec probes distinctes de liveness/readiness, arrêt gracieux, limites et comportement documenté si un volume ou une clé manque.
3. Deux installations de test dédiées avec identités et secrets indépendants. Tentatives croisées de lecture, recherche, réponse, export, accès de service et restauration refusées et auditées.
4. Identités d'opérateurs et de capteurs vérifiables, révocables et à rotation; tests négatifs pour secret cloné, certificat révoqué, rejeu et tentative de changement de client/région.
5. Stockage, files, clés, rétention, suppression et sauvegardes spécifiés avec chiffrement, restauration et suppression vérifiés, y compris les copies secondaires.
6. Déploiement et politique réseau exécutés sur au moins un runtime d'essai documenté; la portabilité n'est revendiquée qu'après répétition sur une seconde distribution compatible et comparaison des contrôles effectifs.
7. Résidence attestée par l'infrastructure et contrôles d'exploitation; la valeur `BK_SECURITY_REGION` reste une déclaration de configuration jusqu'à cette preuve.
8. Tests de volume et de défaillance selon le profil client ratifié; le benchmark local de la V1 ne sert pas de preuve de capacité serveur.

## État de l'environnement de développement

Au moment de la décision, la CLI Docker existe mais son moteur n'est pas démarré; `kubectl` ne dispose d'aucun contexte configuré et Helm n'est pas installé. Le dépôt ne contient ni Dockerfile, ni image BK Security, ni chart ou manifests de déploiement. Il n'y a donc pas de validation d'image ou de cluster à enregistrer dans ce changement. Le profil portable reste une cible d'architecture et la phase 15 reste ouverte.

La validation locale du choix portable a vérifié les liens vers les documents et modules cités. Les tests de configuration et de périmètre, rejoués après l'ajout de la révocation de session, ont réussi : **37 tests Python ciblés**. Le passage complet du 2026-10-24 a réussi avec **219 tests Python**; les **32 tests dashboard** et le build Vite 8.3.3 ont également réussi. Cette exécution ne valide aucun conteneur, réseau, stockage partagé, identité de workload ou cluster Kubernetes.

## Références de travail

- Spécification produit : `docs/BK_SECURITY_V1_ARCHITECTURE_TECHNICAL_SPEC.txt`, section 56, phases 15–16.
- Exigences entreprise : `docs/PHASE14_ENTERPRISE_REQUIREMENTS.md`.
- Décision d'isolation et cycle des données : `docs/PHASE15_CUSTOMER_DATA_PLANE.md`.
- Kubernetes Pod Security Standards : https://kubernetes.io/docs/concepts/security/pod-security-standards/
- Kubernetes Security Checklist : https://kubernetes.io/docs/concepts/security/security-checklist/
- Kubernetes Network Policies : https://kubernetes.io/docs/concepts/services-networking/network-policies/
