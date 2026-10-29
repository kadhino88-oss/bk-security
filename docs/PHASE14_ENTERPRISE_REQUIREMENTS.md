# Phase 14 — cadrage entreprise et modèle de menace

**État au 2026-10-23 : proposition de base rédigée et contrôlée dans le workspace.** Ce document fixe un profil de départ vérifiable pour les phases 15 à 20. Les objectifs de charge, disponibilité, RPO/RTO et conservation sont des hypothèses de conception ; aucun client ne les a encore approuvés et aucun ne constitue un SLA ou une capacité déjà démontrée.

## 1. Périmètre et décisions de cadrage

- Le produit existant est la V1 Windows locale décrite dans `BK_PRODUCT_ARCHITECTURE.md`. Le bus reste en mémoire et SQLite/WAL reste le stockage courant. Elle n'est pas une plateforme d'ingestion distribuée et ne satisfait pas les objectifs ci-dessous.
- Le premier pilote entreprise visé utilise un plan de données dédié à un client. Pas de SaaS multitenant partagé tant que l'isolation n'a pas été conçue, testée et vérifiée à toutes les frontières de données.
- Un plan de contrôle central facultatif peut gérer des versions et politiques signées. Il ne reçoit pas de télémétrie brute par défaut. Un déploiement déconnecté est un profil distinct qui doit documenter et valider l'import de mises à jour et d'indicateurs signés.
- Les capteurs collectent des événements de sécurité minimisés, pas le contenu de paiement, les secrets, le texte de fichiers ou le contenu complet des transactions par défaut. Les sources, filtres et données conservées doivent être visibles pour l'administrateur client.
- Les règles déterministes assurent les décisions de détection critiques. Les modèles locaux ou distants, dont Ollama, peuvent trier et proposer une investigation ; ils n'obtiennent aucune permission directe de commande ou de réponse.
- La réponse suit l'ordre obligatoire : qualifier → contenir si la politique le permet → corriger → vérifier indépendamment → rétablir/redémarrer après contrôles de santé → auditer. L'état actuel n'autorise pas à présenter ce cycle complet comme disponible de façon générale.

## 2. Zones de confiance et actifs

```text
[Poste / serveur client]
  capteur + tampon local borné + identité appareil
       │ canal authentifié, chiffré, limité à la destination autorisée
       ▼
[Plan de données dédié au client et à sa région]
  passerelle → file durable → traitement → stockage client → SOC/API
       │ politiques et mises à jour signées seulement, si activé
       ▼
[Plan de contrôle facultatif]

[Opérateur / administrateur client] ── identité forte et RBAC ──► SOC/API
[Service d'investigation IA] ── preuves sélectionnées, droits lecture seule ──► SOC
[Orchestrateur de réponse] ── adaptateurs explicitement autorisés ──► actifs client
```

Actifs à protéger : télémétrie et preuves ; secrets et clés ; identités des clients, opérateurs, agents et services ; règles, politiques et mises à jour ; incidents et actions de réponse ; journaux d'audit ; disponibilité et intégrité de la file, du stockage et des capteurs. Les frontières comprennent les postes clients, le réseau de collecte, chaque plan client, le plan de contrôle, les opérateurs, le fournisseur IA éventuel, les sauvegardes et la chaîne de compilation/distribution.

## 3. Menaces prioritaires et critères de réduction

| Menace / frontière | Conséquence | Réduction exigée avant pilote | Preuve de sortie |
| --- | --- | --- | --- |
| Vol ou clonage d'un secret d'agent | Injection, suppression ou rejeu de télémétrie | Identité appareil révocable, authentification mutuelle, rotation, anti-rejeu, quotas et séquences détectant les trous | Tests de certificats révoqués, rejeu, usurpation, rotation et alarmes de séquence |
| Traversée entre deux clients | Divulgation ou action sur le mauvais client | Plan de données dédié en pilote ; clés, identités, stockage, files, tâches, exports et sauvegardes séparés | Tests négatifs de lecture, recherche, export, tâche différée et réponse entre deux clients |
| Compromission d'un compte opérateur | Lecture excessive ou réponse non autorisée | MFA/fédération à définir, RBAC serveur, séparation approbateur/répondeur, expiration de session et journal d'audit | Matrice d'autorisation testée et vérification des refus API/UI |
| Événement forgé, malformé ou hostile | Déni de service, faux incident, corruption du traitement | Schéma versionné strict, taille maximale, limitation, validation, quarantaine et consommateurs isolés | Fuzzing de schéma, limite de taille/débit et preuve de backpressure sans perte silencieuse |
| Prompt injection ou hallucination IA | Fausse alerte ou commande dangereuse | Séparer instructions et données, références de preuves, accès lecture seule, sortie non exécutable, règles déterministes et validation de politique | Tests d'injection et preuve qu'aucun appel de modèle ne peut atteindre un adaptateur |
| Mauvaise correction ou redémarrage prématuré | Interruption métier ou retour d'un hôte compromis | Approbation selon impact, idempotence, préconditions, vérification indépendante, contrôle de santé, arrêt d'urgence et rollback testé | Exercices d'échec à chaque étape sur environnement isolé restaurable |
| Rançongiciel, panne de nœud ou épuisement de disque | Données perdues, file bloquée, détection retardée | Files durables, budgets disque, backpressure, surveillance de retard, sauvegarde chiffrée et restauration testée | Reprise/rejeu, saturation, perte de nœud et restauration avec mesure RPO/RTO |
| Compromission de la chaîne de build ou mise à jour | Exécution de code malveillant chez un client | Build traçable, inventaire logiciel, signature, vérification avant mise à jour et stratégie de retour arrière | Vérification de signature, rejet d'artefact modifié et exercice de rollback |
| Abus interne ou export de données | Exfiltration ou suppression de preuve | Moindre privilège, minimisation, approbation d'export, chiffrement, rétention et audit append-only vérifiable | Tests d'accès/export, vérification d'audit et preuve de suppression selon politique |
| Exposition du fournisseur IA | Divulgation de données ou dépendance réseau | IA désactivable ; Ollama uniquement sur interface locale/privée authentifiée ; aucun événement sensible envoyé à un service externe par défaut | Analyse réseau et mode dégradé sans modèle ; configuration et empreintes épinglées |

Les réductions sont des exigences pour le travail futur, pas des contrôles tous présents dans la V1. Les risques résiduels, le propriétaire, les exceptions et l'acceptation client doivent être conservés dans un registre avant pilote. Les marchés et obligations réglementaires sont à confirmer par chaque client ; ce document ne revendique aucune conformité.

### Contrôles V1 observés et écarts

| Domaine | Contrôle déjà présent dans le workspace | Limite qui reste ouverte |
| --- | --- | --- |
| Accès à l'API desktop | Backend lié à la boucle locale ; cinq rôles et mots de passe distincts en production, jetons HMAC expirants, contrôle RBAC, limiteur de connexion et requête | Pas d'identité dédiée par agent, fédération/MFA ni accès réseau client ; pas d'isolation multitenant |
| Événements | Schéma API typé, limites sur certains champs, taille de requête bornée | Pas de contrat interservices versionné ni d'authentification mutuelle des capteurs |
| Persistance | File d'écriture bornée dans le processus, SQLite/WAL, traitements par lots et rétention des événements/alertes | File non durable avant écriture SQLite, aucune réplication ou reprise distribuée ; base locale non documentée comme chiffrée au repos |
| Audit | Table append-only avec contrôles SQLite, chaîne de hachage vérifiable du journal de fiabilité | Preuve locale au même hôte ; une altération du fichier/base par un administrateur système n'est pas empêchée par un dépôt immuable externe |
| Investigation | Résultats structurés, provenance événements/alertes et validation des recommandations | Les suggestions ne sont pas une preuve indépendante de remédiation ; l'intégration d'Ollama n'est pas une capacité revendiquée |
| Réponse | Moteur de politique, séparation approbateur/répondeur, vérification d'adaptateur prévue et contrôle d'approbation | L'application Windows V1 garde `BK_SECURITY_WINDOWS_RESPONSE=0` ; aucun blocage/correctif/rétablissement entreprise n'est validé par les essais de cette contribution |
| Secrets | `safeStorage` desktop pour les identifiants et secret d'authentification selon le guide Windows | Le chiffrement de la base et du stockage de preuves, la gestion de clés client et la rotation d'identité appareil restent à concevoir |

Références de vérification source : `bk_security/configuration.py`, `bk_security/api/app.py`, `bk_security/database/store.py`, `bk_security/events/bus.py`, `bk_security/auth/security.py`, `bk_security/policy/response.py`, `electron/main.js`, `docs/SECURITY_RELIABILITY.md` et `docs/WINDOWS_PRODUCTION_SETUP.md`. Ces références décrivent le workspace, pas le binaire déjà installé.

## 4. Profil de charge candidat pour dimensionner les essais

Le profil de référence proposé pour une instance client est **1 milliard d'événements par jour**, taille normalisée moyenne **1 Kio**, avec une pointe de **3× la moyenne pendant 15 minutes** et **30 jours de recherche chaude**. Il représente environ 11 574 événements/s en moyenne, 34 722 événements/s pendant la pointe, 0,93 Tio/jour et 27,94 Tio de charges utiles sur 30 jours avant index, réplication, métadonnées, preuves, sauvegardes et marge. Ce calcul est un profil d'essai, pas une promesse de débit ni un dimensionnement matériel.

| Mesure candidate | Objectif à confirmer | Condition de validation ultérieure |
| --- | --- | --- |
| Volume quotidien | 1 milliard d'événements par plan client | Générateurs et jeux de données représentatifs, décompte exact après rejeu |
| Débit soutenu | 11 574 événements/s sur 24 h | Pas de perte silencieuse, retard de file borné, erreurs et CPU/disque mesurés |
| Pointe | 34 722 événements/s pendant 15 min | Backpressure visible, producteurs récupérables, puis drainage complet |
| Taille des événements | moyenne 1 Kio ; essais de distribution jusqu'au p99 réel client | Mesurer octets avant/après normalisation et cas malformés/surdimensionnés |
| Latence d'acceptation | p95 ≤ 2 s, p99 ≤ 5 s après arrivée à la passerelle | Accusé seulement après la durabilité convenue ; latence par étape et par percentile |
| Détection déterministe | p95 ≤ 10 s à partir de la persistance | Écarter la latence IA du SLO ; inclure les règles et corrélations sélectionnées |
| Rétention chaude | 30 jours consultables | Essai avec volumes et index, sauvegardes, restauration et coût mesurés |
| Disponibilité de l'ingestion gérée | 99,9 % par mois, maintenance planifiée publiée à part | Mesure de bout en bout sur architecture HA ; non applicable à la V1 locale actuelle |
| RPO cible | ≤ 5 minutes pour données acquittées | Couper/perdre un nœud, restaurer et mesurer les événements acquittés absents |
| RTO cible | ≤ 60 minutes pour le service d'ingestion d'un plan client | Chronométrer détection, bascule/restauration, validation et retour à l'état sain |

Les SLO, RPO et RTO ci-dessus sont des valeurs de travail pour la conception et les essais. Ils nécessitent une validation par produit, exploitation et client avant adoption. Toute évolution du profil (sources, volume, rétention, indexation, régions, exigences de confidentialité) doit recalculer coût, stockage et charge. Les résultats des tests synthétiques et les mesures de production restent séparés.

## 5. Questions d'acceptation à fermer avec le pilote

Avant de figer les phases 15–20, recueillir par client : événements et taille moyenne/p95/p99 par source ; simultanéité et durée des pics ; sources réellement couvertes ; régions et transferts interdits ; catégories sensibles ; rétention chaude/tiède/archive et suppression ; fenêtre de maintenance ; disponibilité et dépendances ; RPO/RTO contractuels ; limites de coût ; règles de blocage et approbateurs ; objectifs de faux positifs ; environnement de restauration ; fonctionnement isolé/déconnecté.

## 6. Porte de sortie Phase 14

La phase est un **cadrage workspace**, pas une phase acceptée par un client. Sa clôture de conception exige :

1. approbation par les responsables produit/sécurité des frontières, menaces et profils de déploiement ;
2. valeurs SLO/RPO/RTO et profil de charge ratifiés ou remplacés par une fiche pilote signée ;
3. propriétaires et traitement de chaque risque critique documentés ;
4. scénarios de preuve affectés aux phases 15–20, sans reporter cette validation après annonce commerciale ;
5. confirmation des exigences de données, résidence, rétention, restauration et budget du client pilote.

**Résultat de la présente contribution :** les propositions et scénarios d'essai sont documentés et reliés à la section 56. Le propriétaire du produit a demandé de poursuivre avec ces chiffres comme hypothèses de travail ; aucun client pilote ni contrat de service n'a ratifié de SLA. Les mesures distribuées, tests d'isolation, sauvegarde/restauration et exploitation pilote restent à réaliser ; la V1 ne satisfait pas les objectifs chiffrés.
