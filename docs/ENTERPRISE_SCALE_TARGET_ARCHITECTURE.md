# BK Security — cible architecture entreprise

**Statut : cible de conception, pas une capacité livrée.** Ce document étend la V1 sans modifier son ordre de phases. Il doit servir de base au threat model, aux exigences mesurables et aux changements de code de la phase 14 et suivantes.

## Avis de capacité actuel

BK Security V1 est un moteur SOC local pour Windows : événements normalisés, détection/corrélation, alertes/incidents, investigation IA avec provenance, politiques de réponse, audit, API et interface. La persistance active est SQLite/WAL et le bus d'événements est en mémoire dans un processus. Les capteurs Windows existants couvrent des observations locales ; une capture Wi-Fi validée sur un poste ne représente pas tout le trafic d'un réseau d'entreprise.

Le benchmark Windows synthétique enregistré le 12 octobre 2026 a mesuré 1 295,89 événements/s sur 10 000 événements avec vidage SQLite. Il ne prouve ni une charge soutenue de production, ni une mise à l'échelle horizontale, ni des milliards d'événements, ni une disponibilité entreprise. Il n'existe pas encore de preuve d'isolation de plusieurs entreprises dans un service partagé, de bascule multi-nœud ou de restauration à un RPO/RTO convenu. La cible entreprise ne doit donc pas être présentée comme déjà atteinte.

### Avancement vérifié dans le workspace — 2026-10-23

- Le rapport d'activité mensuel V1 est implémenté dans le workspace : `GET /api/v1/audit/monthly?month=YYYY-MM`, protégé par RBAC, avec résumé agrégé et carte dans le dashboard.
- Il rapporte les événements, alertes, incidents, tentatives/résultats de réponse, réparations sûres BK et l'état de vérification de l'audit. Il n'expose pas les charges utiles, noms d'hôtes ou identifiants dans son résumé.
- Le rapport marque la complétude comme non prouvée et les limites de rétention ; il ne prétend pas mesurer les attaques évitées ou les menaces remédiées. C'est un résumé de l'instance locale V1, pas un audit de conformité exhaustif.
- Revalidation synthétique Windows le 2026-10-23 : 10 000 événements, 1 218,12 événements/s avec vidage SQLite, writer sain. Cette mesure locale unique ne valide pas un débit soutenu, un pic, plusieurs nœuds, une charge représentative de production ou la cible milliard.
- Tests workspace après ajout : 204 Python, 29 dashboard. Le Vite build génère les ressources statiques correspondantes. L'installateur Windows n'a pas été reconstruit et l'application installée n'a pas reçu ce changement.
- Le cadrage de phase 14 (menaces, frontières, exigences et profil candidat de 1 milliard d'événements/jour) est rédigé dans [PHASE14_ENTERPRISE_REQUIREMENTS.md](PHASE14_ENTERPRISE_REQUIREMENTS.md). Ces objectifs restent à ratifier et aucun test de phase 20 ne les a démontrés.
- Phase 15 a des garde-fous locaux supplémentaires : une base SQLite persistante est liée à une référence client opaque, un UUID stable de déploiement et une région déclarée ; les connexions revalident ce lien, les jetons API/WebSocket sont scellés au client/déploiement et les sessions peuvent être révoquées dans cette base. Le rapport mensuel indique explicitement que la résidence et l'isolation réelle ne sont pas attestées. Voir [PHASE15_CUSTOMER_DATA_PLANE.md](PHASE15_CUSTOMER_DATA_PLANE.md). La régression complète workspace a passé **219 tests Python**, les tests dashboard **32**, et le build Vite 8.3.3. Ces tests locaux ne valident pas une isolation réseau, serveur ou cloud inter-client, ni une révocation propagée entre réplicas.
- Le choix d'hébergement communiqué le 2026-10-24 est portable, sans fournisseur cloud : image OCI et API Kubernetes comme contrat candidat, sur site ou environnement compatible. Le backend de production reste loopback-only; aucune image, manifest ou installation serveur n'est livré. Voir le [contrat de déploiement portable de la phase 15](PHASE15_PORTABLE_DEPLOYMENT_CONTRACT.md).

## Architecture cible

```text
Postes, serveurs, réseau, identités, applications et cloud
                            │
             Agents et capteurs locaux authentifiés
                            │ mTLS, identifiant client/appareil, tampon local borné
                            ▼
             Passerelle d'ingestion par client/région
                            │ validation de schéma, quotas, limitation de débit
                            ▼
       File durable partitionnée, rejeu et backpressure
                            ▼
       Normalisation → enrichissement → règles déterministes
                            ▼
           Corrélation → alerte → incident et preuves
                            ▼
       Moteur de politiques / orchestrateur de réponse
                            │
         contenir → corriger → vérifier → rétablir
                            ▼
      Stockages séparés, API authentifiée, SOC et audit

Ollama local facultatif ──► aide à l'investigation, sans autorité d'exécution
```

### Déploiement et données client

- Par défaut, chaque client entreprise dispose d'un plan de données isolé dans son réseau, son cloud privé ou une région dédiée. Le plan de contrôle peut distribuer les versions et politiques signées sans recevoir les événements bruts.
- Une variante SaaS mutualisée n'est autorisée qu'après conception et validation d'une isolation tenant complète dans les identités, l'API, la base, les index, les files, les caches, les tâches différées, les clés et les exports. Un simple `tenant_id` dans les événements ne suffit pas.
- Les capteurs authentifient l'identité appareil/service, chiffrent les échanges et tamponnent localement avec une limite de taille/durée annoncée. La politique d'expiration doit être appliquée même si la liaison centrale est coupée.
- La collecte minimise les données. Les charges utiles de transactions, données de paiement, secrets et contenus de fichiers ne sont pas collectés par défaut. La pseudonymisation, la résidence, la durée de rétention, les exports et la suppression sont configurables et audités.
- Un réseau privé et filtré est la cible normale. Un vrai réseau air-gap exige une procédure distincte pour importer, vérifier et appliquer les mises à jour et renseignements de menace signés.

### Ingestion et traitement

- Remplacer le bus mono-processus par une file durable et partitionnée avant de prétendre à une capacité distribuée. Le contrat d'événement doit être versionné, idempotent, validé et porter la provenance, l'identité de la source et l'heure de collecte.
- Accuser réception uniquement après persistance au point de durabilité défini. Les producteurs doivent pouvoir rejouer ; les consommateurs doivent gérer les doublons ; les événements malformés vont en quarantaine avec métriques et inspection contrôlée.
- Appliquer quotas par client, limites de taille et de débit, backpressure sans perte silencieuse, métriques de retard de file et contrôles de saturation. Les sources et les analyses optionnelles doivent dégrader proprement sans masquer l'état de santé.
- Séparer le stockage transactionnel des incidents/configurations, l'index de recherche des événements et le stockage objet chiffré des preuves nécessaires. Définir les règles de rétention et les copies indépendamment pour chacun.

### Agents, analyse et réponse

- « Agent » désigne d'abord un capteur de collecte ou un service spécialisé supervisé : collecte, normalisation, détection, corrélation, triage, réponse, vérification et rapport. Chaque service a un contrat, une identité, des permissions minimales, une limite de ressources, un heartbeat, des métriques, une politique de redémarrage et une voie de désactivation.
- Utiliser des règles déterministes pour les décisions critiques et l'IA pour résumer, prioriser, enquêter et proposer. Toute recommandation IA garde les identifiants d'événements/preuves, le modèle et sa version, la confiance, les limites et les conflits.
- Ne jamais laisser un modèle appeler directement PowerShell, une commande système ou un adaptateur de blocage. L'orchestrateur valide l'action, la cible, les rôles, la politique, l'approbation, l'idempotence et le résultat.
- Cycle exigé : détecter et qualifier → contenir/bloquer si autorisé → corriger → vérifier de façon indépendante → rétablir/redémarrer lorsque les contrôles de santé réussissent → auditer. Un blocage ne prouve pas la correction. Un redémarrage sans contrôle de santé peut réintroduire une machine compromise.
- Les actions sont classées par impact. L'alerte et le plan à blanc sont les valeurs initiales. Les actions non réversibles ou à impact métier élevé exigent une approbation humaine explicite, une fenêtre de changement, un journal inviolable, un arrêt d'urgence et un rollback lorsque techniquement possible.

### Ollama

Ollama peut être un fournisseur de modèle local optionnel pour la synthèse et l'investigation. Il doit rester sur une interface locale ou derrière une passerelle privée authentifiée et chiffrée ; son API locale ne doit pas être exposée directement au réseau client ou à Internet. Les versions et empreintes des modèles sont épinglées, les invites sont minimisées, les flux sortants sont bloqués par défaut, et l'analyse continue de fonctionner en mode règles si le modèle est indisponible. Aucun mécanisme de détection ou de blocage ne doit dépendre exclusivement de lui.

### Audit mensuel

Le rapport couvre une période UTC explicitement affichée et inclut la qualité/completude des données. Il distingue : événements reçus par type/source, alertes, incidents confirmés, faux positifs connus, plans proposés, approbations, actions tentées, actions exécutées et vérifiées, corrections vérifiées, restaurations, incidents encore ouverts, délais de détection/réponse, couverture des capteurs, événements rejetés/perdus, exceptions et retard de file.

« Attaque bloquée » n'est comptée qu'avec preuve de l'action et de son résultat. « Attaque évitée » ne peut pas être inférée d'une recommandation ou d'un plan à blanc. Le rapport indique les sources indisponibles, les trous de collecte, les événements simulés et les données expirées ; un rapport incomplet n'est jamais présenté comme exhaustif. Les décisions et exports du rapport sont eux-mêmes audités.

## Dimensionnement : mesures avant matériel

Fixer par client et par région : événements/s moyen, pic et durée du pic ; taille normalisée p50/p95/p99 ; latence d'ingestion et de détection p95/p99 ; nombre d'agents concurrents ; taux d'enrichissement ; rétention chaude/tiède/archivée ; nombre d'opérateurs et requêtes concurrentes ; disponibilité ; RPO/RTO ; coût maximum par million d'événements.

Exemple purement arithmétique : 1 milliard d'événements/jour équivaut à environ 11 574 événements/s en moyenne. À 1 Ko par événement, le volume non compressé est environ 1 To/jour, avant index, réplication, métadonnées et sauvegardes. Le pic peut être plusieurs fois supérieur à la moyenne. Ce calcul ne donne pas une configuration serveur : le matériel et le nombre de nœuds viennent d'un benchmark de bout en bout avec les vrais types d'événements, les règles, les recherches et les exigences de rétention.

## Ordre d'exécution et portes de validation

L'évolution suit les phases 14 à 20 de la section 56 de la spécification canonique. Chaque phase exige code produit, tests adaptés, intégration au parcours API/SOC/desktop, mesure réelle et compte rendu. Les validations de charge doivent inclure durée, pics, concurrence, panne d'un consommateur/nœud, reprise/rejeu, files saturées, coupure réseau, restauration, isolation entre clients et absence de perte silencieuse. Les résultats de simulation et les résultats réels sont séparés.

Avant les pilotes : menace modélisée, identité appareil, politiques d'accès, chiffrement et gestion des clés, journal d'audit vérifié, sauvegarde restaurée, mises à jour signées, inventaire/SBOM, test de sécurité indépendant, procédures d'incident et rôles de support documentés. Aucune certification ou conformité n'est revendiquée sans audit correspondant.
