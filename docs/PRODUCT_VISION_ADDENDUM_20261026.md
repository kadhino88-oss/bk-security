# BK Security — addendum de vision produit (2026-10-26)

Source : précision donnée par le propriétaire du produit en session. Ce document **complète** la spécification canonique sans la modifier : la section 55 décrit encore « une plateforme Windows » et devra être réconciliée sur décision du propriétaire.

## Vision

BK Security est un logiciel de cybersécurité évolué, indépendant et commercialisable, destiné aux TPE/PME comme aux grandes entreprises. Il n'est pas limité à Windows : il vise tous les systèmes d'exploitation et tous les réseaux sur lesquels il est installé.

Parcours attendu à l'installation : analyser le réseau et ses flux → détecter les failles → les notifier → établir une procédure de blocage et de correction → bloquer/corriger attaques et failles en autonomie dans son périmètre d'action. Les données sensibles de l'entreprise sont traitées en local, sans y toucher et sans perturber le fonctionnement du système de l'entreprise. Chaque tâche est confiée à un agent IA spécialisé, afin de servir de garde-fou.

## Lecture de cette vision contre l'existant (vérifié dans le dépôt)

| Exigence | État observé |
|---|---|
| Modularité (capteurs, règles, workers IA, intel, adaptateurs de réponse) | Interfaces présentes : `SecurityWorker` (`ai/contracts.py`), adaptateurs de réponse (`policy/adapters.py`, `policy/windows_adapters.py`), capteurs (`sensors/`). Un seul fichier de workers (`ai/workers/builtin.py`). |
| Multi-OS | **Non atteint.** Spécifique Windows : `platform_windows.py`, `policy/windows_adapters.py`, détection Npcap, installeur NSIS, app Electron packagée pour Windows. Le cœur Python (événements, détection, corrélation, incidents, SOC, API, file d'ingestion) n'en dépend pas. Scapy et Electron sont techniquement portables ; aucun test Linux/macOS n'a été exécuté. |
| Tous réseaux | Capture limitée au poste (endpoint) ; la vue réseau complète exige un miroir/TAP ou des capteurs distribués, non validés. |
| Un agent spécialisé par tâche | Phase 17 de la spec : non réalisée. L'orchestrateur et les workers actuels sont une base, pas l'isolation/supervision visée. |
| Blocage/correction autonomes | **Non activés** : réponses Windows réelles en NO-GO (Phase 6), seulement dry-run. Phase 18 non réalisée. |
| Données sensibles en local, sans interférence | Traitement local, pas de stockage de paquets bruts, assainissement des événements, base dédiée par client. Aucune validation d'absence d'interférence sur un système tiers. |
| Commercialisable | Bloqué : licence commerciale Orbis introuvable (voir `NOTICE-ORIGINS.md`, checklist). Non signé (Authenticode). |

## Garde-fous proposés (à valider par le propriétaire)

L'autonomie totale est contraire au cycle de réponse déjà posé en spec (section 57 / phase 18 : approbation humaine pour les actions sensibles, idempotence, audit, arrêt d'urgence, rollback, vérification indépendante). Proposition : des niveaux d'autonomie **configurés par le client**, le niveau par défaut étant le plus bas.

1. **Observer** : capture passive, détection, notification. Aucune action.
2. **Recommander** : procédure de blocage/correction proposée, jamais exécutée.
3. **Contenir automatiquement** : uniquement actions réversibles, à faible rayon d'impact, listées par politique, avec vérification et rollback.
4. **Autonome étendu** : actions plus larges, réservées à ce que le client active explicitement, avec arrêt d'urgence.

Chaque agent spécialisé (collecte, détection, investigation, décision de politique, exécution, vérification, audit) n'a que les droits de sa tâche ; l'agent d'analyse (y compris un modèle local) n'a jamais de droit d'exécution direct. Les données sensibles ne quittent pas l'environnement du client par défaut.

## Ordre de travail recommandé

1. Phase 16 (en cours) : contrat d'événements et ingestion durable — module et routes locales posés, voir la checklist.
2. Extraire une couche de plateforme (capture, découverte d'interfaces, adaptateurs de réponse) avec implémentations Windows / Linux / macOS, puis tests de contrat communs. Le service Linux est aussi la cible du contrat de déploiement portable (Phase 15).
3. Phase 17 : agents spécialisés supervisés, un par tâche, droits minimaux.
4. Phase 18 : cycle de réponse contrôlé, d'abord dans un laboratoire isolé avec adaptateurs réels, niveau par niveau.
5. Levée des blocages de commercialisation (licence, signature) avant toute distribution.

Rien de ce qui précède n'est revendiqué comme réalisé : ce sont des cibles et un écart constaté.

## Modèle d'exploitation : service géré par le créateur (précision du 2026-10-26)

Le client final ne configure ni n'opère rien lui-même. Le créateur et exploitant (BK ENTREPRISE) installe, surveille, maintient et gère le produit à distance ou sur site. Conséquences de conception, à valider :

- **Rôles.** Un rôle opérateur BK (fournisseur) distinct des utilisateurs du client. Le niveau d'autonomie d'un client est fixé par l'opérateur, avec l'accord du client consigné dans le journal d'audit. Le client garde une vue en lecture et un arrêt d'urgence local.
- **Accès à distance = surface critique.** Un canal d'administration distant donne la main sur tous les clients ; il ne peut pas être ouvert avant : identité forte opérateur (MFA), mTLS appareil/service, session courte et révocable, journal d'audit non modifiable et visible du client, accès par client (jamais un compte global), et mode « accès sur site » en alternative. Cela reste la barrière « avant exposition réseau » du contrat Phase 15 ; l'API locale reste en loopback.
- **Plan de contrôle minimal.** Le plan de contrôle de l'opérateur reçoit des métadonnées et l'état de santé, pas les événements bruts ni les données sensibles, sauf extraction explicitement autorisée par le client pour un incident donné.
- **Maintenance sans interférence.** Mises à jour signées, déploiement progressif et retour arrière, sondes de santé, mode dégradé sûr (en cas de panne le produit ne coupe jamais le trafic du client).
- **Responsabilité.** Une action autonome engage l'opérateur : politique par client versionnée, périmètre d'actions autorisées, preuve de vérification et rollback pour chaque action.

## Couche de plateforme multi-OS — état au 2026-10-26

Ajout de `bk_security/platforms/` : un contrat `PlatformProvider` (élévation, loopback, prérequis de capture, adaptateurs de réponse) avec fournisseurs Windows, Linux et macOS, plus un fournisseur « non pris en charge » qui échoue de façon sûre.

- Windows : délègue au code existant (Npcap, PowerShell) sans changement de comportement.
- Linux : adaptateurs nftables (table dédiée `bk_security`, ensembles d'IP, isolation par table propre), prérequis root/`CAP_NET_RAW` et libpcap/tcpdump.
- macOS : adaptateurs pf (ancre et table dédiées ; la vérification signale `anchor_not_active` plutôt que d'annoncer un blocage non appliqué), prérequis BPF.
- Terminaison de processus : adaptateur psutil commun, refusant init, le processus BK, son parent et les noms protégés.
- Activation : `BK_SECURITY_OS_RESPONSE=1` (désactivé par défaut ; refusé en production tant que les adaptateurs ne sont pas validés en laboratoire). `BK_SECURITY_WINDOWS_RESPONSE` reste pris en charge.

**Non validé.** Les adaptateurs Linux et macOS n'ont été exercés que contre des simulateurs de `nft` et `pfctl` ; aucune commande réelle n'a été lancée sur Linux ni macOS, et l'on ignore si la syntaxe nft/pf émise est acceptée par les outils réels. Aucune capture live n'a été essayée hors Windows. Le service Linux (conteneur) et les paquets macOS restent à construire.
