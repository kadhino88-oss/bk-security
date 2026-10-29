# Phase 15 — isolation client, identités et cycle des données

**Statut : garde-fous locaux de périmètre et de session implémentés dans le workspace ; phase encore ouverte.** Une base SQLite est liée à une identité de déploiement client/région, le rapport mensuel indique son niveau d'attestation, un administrateur peut lister/révoquer les sessions par compte dans cette instance et les secrets courants sont filtrés à l'entrée des événements. Cela ne fournit pas encore un plan de données distribué, une isolation d'hôte/réseau, un service d'identité d'agent, un chiffrement de base ou une suppression vérifiée.

## Décision d'architecture

Le premier pilote reste **un plan de données dédié par client et par région**, avec son propre runtime, identités, passerelle, file, stockage, clés et sauvegardes. Les flux du plan de contrôle sont limités aux versions, politiques et métadonnées opérationnelles approuvées ; la télémétrie brute ne remonte pas au plan de contrôle. Une région déclarée dans la configuration n'est pas une attestation de résidence. Un service partagé multitenant n'est pas retenu tant que chaque chemin d'accès, cache, export, tâche différée, clé, sauvegarde et opération de réponse n'a pas passé les tests d'isolation croisée.

Cette séparation suit le modèle d'accès par identité de service, appareil et utilisateur de NIST Zero Trust : un segment ou un réseau privé ne rend pas un pair digne de confiance par sa seule localisation. Pour un environnement cloud-native ou hybride, NIST décrit l'application de politiques d'identité au niveau des services ; une identité de workload à certificats courts, telle que SPIFFE X.509-SVID, est une option pour le futur fournisseur d'identités, pas une dépendance déjà intégrée à BK Security ([NIST SP 800-207](https://csrc.nist.gov/pubs/sp/800/207/final), [NIST SP 800-207A](https://csrc.nist.gov/pubs/sp/800/207/A/final), [SPIFFE Concepts](https://spiffe.io/docs/latest/spiffe/concepts/)).

Le choix d'hébergement est désormais **portable et sans fournisseur cloud choisi**. Une image OCI et l'API Kubernetes sont le contrat candidat pour permettre un déploiement sur site ou chez un hébergeur compatible; aucun conteneur ou cluster BK Security n'est encore livré. Le [contrat de déploiement portable](PHASE15_PORTABLE_DEPLOYMENT_CONTRACT.md) fixe les garde-fous d'exposition réseau, de durcissement et les preuves de sortie. Le backend de bureau reste loopback-only en production et ne doit pas être rendu accessible en contournant ce contrôle.

## Identités et autorisations requises

| Sujet | Identité et contrôle cible | Situation V1 |
| --- | --- | --- |
| Client et région | Référence client opaque et environnement/région affectés par le provisioning ; une base et une clé par plan | Nouvel ancrage de configuration et de base locale ; aucune attestation de région |
| Agent/capteur | Identité d'appareil révocable, renouvellement automatique, authentification mutuelle et séquence anti-rejeu | Pas d'identité distante propre à un agent ; les capteurs intégrés au desktop utilisent le processus local |
| Service | Identité distincte, permissions minimales par API/stockage/file, rotation et révocation | Pas de mesh ou de fédération d'identité de workload |
| Opérateur client | IdP/MFA en cible, compte lié au client/région, RBAC côté serveur et audit | Les jetons HMAC portent un identifiant de session; les ouvertures de session sont persistées dans la base dédiée. Logout et révocation administrateur de toutes les sessions d'un compte sont audités et limités à cette instance. Les comptes restent activables; mots de passe locaux, pas de fédération/MFA |
| Réponse | Identité de l'approbateur et du répondeur séparées, toutes deux limitées au même plan | Séparation de rôle présente ; action Windows maintenue désactivée en V1 |

Les attributs d'identité et de routage ne doivent pas être pris du payload d'événement ni d'un en-tête libre fourni par le capteur. Le plan d'ingestion doit les dériver de l'identité authentifiée et d'une affectation serveur. Le contrôle d'autorisation lie explicitement l'utilisateur, le service ou l'appareil au client, à la région, à la ressource et à l'action.

Le profil dédié lie désormais chaque jeton API et WebSocket à `customer_ref` et `deployment_id`; un jeton déjà émis dans un autre déploiement, ou un jeton dédié présenté au profil local, est refusé même si le secret HMAC a été réutilisé par erreur. Les jetons émis ont aussi un `jti` aléatoire. L'API persiste le `jti`, l'utilisateur et l'expiration à la connexion; `POST /api/v1/auth/logout` révoque la session courante, et `GET /api/v1/auth/sessions` expose aux seuls administrateurs un résumé sans identifiant de jeton. `POST /api/v1/auth/sessions/{username}/revoke` révoque les sessions actives de ce compte dans la base courante et trace le nombre révoqué dans l'audit. Le tableau de bord permet de rafraîchir cette liste et demande confirmation avant la révocation. Les requêtes suivantes avec les jetons révoqués sont refusées et le flux WebSocket revérifie le statut chaque seconde. L'état du registre SQLite n'est pas partagé entre réplicas; ce contrôle ne désactive pas le compte et ne bloque donc pas une nouvelle connexion. Les anciens jetons locaux sans `jti` ne peuvent pas être révoqués et restent valides jusqu'à expiration; les anciens jetons du profil dédié sans `jti` sont refusés après mise à jour et exigent une nouvelle connexion. Un secret HMAC partagé ou compromis permettrait toujours de fabriquer des jetons : chaque déploiement doit recevoir son propre secret depuis un coffre et le faire tourner. Cela ne remplace pas un IdP, MFA, l'identité d'agent à certificats ni le provisioning/rôle des opérateurs.

## Données, résidence et conservation

Les principes de minimisation, limitation de finalité et conservation limitée du RGPD guident le schéma, la sélection des capteurs et les durées ; les paramètres juridiques et la durée de preuve sont à ratifier par le client et son responsable de traitement. La protection par défaut/conception et les mesures de sécurité adaptées au risque sont des objectifs de conception, sans revendication de conformité ([règlement officiel (UE) 2016/679, articles 5, 25 et 32](https://eur-lex.europa.eu/eli/reg/2016/679/oj/eng/)).

| Classe | Règle cible | État connu / travail requis |
| --- | --- | --- |
| Événements de sécurité | Champs minimaux ; contenus de transactions, secrets et données de paiement exclus par défaut ; filtres et rétention visibles | Le pipeline masque certains champs et motifs de secrets avant détection et persistance, mais ne détecte pas les secrets encodés ou les PII en texte libre. Il borne le nombre d'événements sans mesurer la complétude des capteurs ni appliquer une rétention par âge |
| Incidents et réponses | Garder les liens de preuve nécessaires, décisions, approbations et vérifications ; masquer les données personnelles inutiles | Persistance locale disponible ; durée client configurable et propagation d'identité à travers chaque API à définir |
| Audit | Append-only, protégé contre l'altération et séparé de la télémétrie ; durée et export gouvernés | Chaîne de hachage locale vérifiable ; pas de coffre immuable distant, et la rétention légale peut empêcher une suppression immédiate |
| Secrets et clés | Stockage dans un KMS/HSM ou coffre de l'environnement ; clés distinctes par client, rotation, révocation et sauvegarde testée | `safeStorage` desktop couvre les identifiants ; clé de base/données de sécurité dédiée non implémentée |
| IA et télémétrie opérationnelle | Fournisseur hors plan client désactivé par défaut ; aucun payload brut dans les prompts ou métriques | Aucune attestation de résidence/réseau IA par client dans cette tranche |
| Sauvegardes et exports | Même région que le plan, chiffrement, durée définie, accès audité, suppression/pruning et restauration éprouvés | Procédure desktop manuelle documentée ; aucun mécanisme de suppression/expiration de sauvegardes vérifié |

La politique de rétention devra distinguer événements, alertes, incidents, preuves, audit, exports et sauvegardes. Les demandes de suppression devront traiter les données actives, index, files différées, caches, exports et copies de sauvegarde, préserver les éventuelles obligations de conservation et produire une preuve d'exécution. **Aucun endpoint de purge n'est ajouté ici** : une suppression irréversible sans matrice de conservation et sauvegarde validées serait dangereuse.

CloudEvents v1.0.2 est retenu comme candidat d'interopérabilité à évaluer en phase 16, pas comme contrat adopté. Son format sépare contexte et données, recommande de ne pas placer de données sensibles dans les attributs de contexte et préconise le chiffrement des payloads et la sécurité du protocole ([spécification CloudEvents](https://github.com/cloudevents/spec/blob/main/cloudevents/spec.md), [versions stables du projet](https://github.com/cloudevents/spec)). Le schéma BK devra rester versionné, imposer ses propres identités/provenances et contrôler ses tailles.

## Garde-fou livré dans le workspace

Le nouveau profil `dedicated_customer` prend sa référence client opaque, UUID de déploiement et région déclarée depuis la configuration du processus. Tout `SecurityStore` créé sans contexte injecté hérite ce profil depuis l'environnement, et un contexte explicitement différent ne peut pas le remplacer. Ainsi, un worker, CLI ou utilitaire interne n'ouvre pas par défaut une base liée en mode `local_v1` et ne peut pas changer l'identité client du processus. Le profil refuse les valeurs manquantes/malformées et les bases éphémères, lie atomiquement le fichier SQLite à ce triplet au premier démarrage et refuse une autre identité sur la même base. Chaque connexion SQLite vérifie à nouveau le lien, afin qu'un chemin de base réaffecté en cours d'exécution soit refusé. Il refuse également d'affecter automatiquement à un client les données non liées d'une ancienne base peuplée. Le rapport mensuel montre la portée et affiche explicitement que l'application n'atteste ni la région ni une isolation complète.

Configuration de développement/test :

```text
BK_SECURITY_DEPLOYMENT_PROFILE=dedicated_customer
BK_SECURITY_CUSTOMER_REF=reference-opaque-du-client
BK_SECURITY_DEPLOYMENT_ID=<UUID stable de ce déploiement>
BK_SECURITY_REGION=<identifiant de région déclaré par l'opérateur>
```

Le même UUID doit être conservé lors de la reprise du même plan de données. Une restauration vers un plan/une région différente doit passer par un processus de migration validé ; ne pas simplement modifier les variables d'environnement. La base doit être neuve ou vide. Le profil `local_v1` garde le comportement V1 actuel.

### Filtrage des secrets à l'ingestion

Le bus central masque récursivement les champs dont le nom indique clairement un secret (mot de passe, secret, jeton, clé privée/API, identifiant bancaire ou carte), les valeurs de paramètres URL sensibles, les valeurs `Bearer`, les blocs de clé privée et les arguments secrets de ligne de commande. Le filtrage intervient avant détection, investigation et écriture SQLite; l'événement renvoyé par l'API porte aussi la version filtrée. Les champs de détection non sensibles, comme le port destination et le nom de processus, restent présents. L'adaptateur endpoint utilise le même filtre borné pour les arguments de processus.

Ce filtre réduit certains risques de collecte accidentelle, mais ne fait ni classification sémantique ni détection générale de données personnelles : une valeur secrète placée sous un champ anodin ou encodée peut passer. Il ne chiffre pas SQLite, n'efface pas les anciennes données, ne protège pas une base déjà copiée et n'établit pas une conformité juridique. Les champs et durées réellement collectés doivent encore être définis avec le client.

### Limites de ce garde-fou

- Une liaison en base ne sépare pas physiquement des clients, ne chiffre pas les fichiers, ne contrôle pas l'emplacement du serveur et ne remplace pas les permissions OS/KMS.
- Le filtre d'ingestion ne garantit pas la découverte de secrets dans du texte libre ou encodé, ni l'anonymisation des noms, identifiants d'hôte, adresses réseau ou autres données personnelles.
- Elle n'ajoute ni authentification mTLS des agents, ni endpoint d'ingestion distante, ni fédération utilisateur/service, ni contrôle d'accès ligne par ligne.
- La révocation de session locale ne se propage pas entre réplicas et ne remplace ni la désactivation administrateur d'un compte, ni un IdP/MFA, ni le provisioning d'opérateurs.
- Deux clients ne doivent pas partager un processus ou un stockage en prétendant que ce mécanisme suffit. Le pilote dédié par client est la frontière cible, à fournir par l'infrastructure et à tester entre deux instances.
- L'installation Electron actuelle ne configure pas les variables de profil dédié ; elle demeure `local_v1` et ne reçoit pas ces changements sans nouveau package.

## Validation et porte restante

Les tests couvrent la validation fail-closed du profil, son héritage depuis l'environnement, le refus d'un contexte explicite qui contredit l'identité du processus, la liaison atomique, le redémarrage avec même identité, le refus d'un autre client ou deployment ID, le refus d'une base ancienne peuplée et d'une base éphémère, la revalidation à chaque connexion et l'affichage honnête de la portée. Ils vérifient qu'un logout révoque le jeton et que l'état reste révoqué après réouverture de la base, que seuls les administrateurs peuvent lister ou révoquer, que la liste ne révèle aucun identifiant de jeton, que toutes les sessions d'un compte sont révoquées, que l'action est auditée et qu'une WebSocket active ferme avec le code 1008 à la prochaine vérification de révocation. Le filtre d'ingestion est testé avec des champs imbriqués, des arguments de processus, des en-têtes Bearer, des URL et la réponse API; les valeurs utiles à la détection restent disponibles et les secrets de test n'apparaissent ni dans les alertes ni dans la base. Les tests dashboard couvrent l'appel aux deux endpoints et le signalement des erreurs. Un test avec deux fichiers distincts vérifie que les événements, alertes, incidents, actions de réponse et audits d'un dépôt local ne se lisent pas depuis l'autre. Un test d'API authentifiée vérifie que le rapport mensuel restitue la portée et les événements de la base dédiée sélectionnée. La suite ciblée événement/capteur/authentification a réussi avec **25 tests Python**; la suite dashboard avec **35 tests**; la suite Python complète du 2026-10-24 avec **223 tests**. Le build Vite 8.3.3 a réussi et le bundle construit a été intégré dans `dashboard/static` après sauvegarde de l'ancien, avec empreintes SHA-256 comparées. Le benchmark synthétique final a atteint **802,95 événements/s** avec le writer SQLite sain; c'est environ **14,4 fois sous** la moyenne du profil candidat d'un milliard d'événements/jour. Voir [le rapport de performance](PHASE11_PERFORMANCE_VALIDATION_20261012.md). L'installation desktop reste sur son ancien build. Ces validations locales ne prouvent pas l'isolation réseau/stockage ni la résidence réelle.

Avant de clore la phase 15, il faut encore choisir et éprouver le modèle d'identité et de provisioning, créer deux plans de test client/région indépendants, tester la propagation de révocation entre instances, prouver qu'aucun secret/télémétrie ne traverse un client/région, décider des durées et suppressions avec le client, vérifier les clés et sauvegardes, et valider l'infrastructure de résidence. La phase 16 ne doit pas réutiliser un champ `customer_id` non authentifié comme frontière de sécurité.

## Références de recherche — consultées le 2026-10-24

- NIST SP 800-207, Zero Trust Architecture : https://csrc.nist.gov/pubs/sp/800/207/final
- NIST SP 800-207A, contrôles d'accès cloud-native et identités de services : https://csrc.nist.gov/pubs/sp/800/207/A/final
- SPIFFE Concepts et identités X.509 de courte durée : https://spiffe.io/docs/latest/spiffe/concepts/
- Règlement (UE) 2016/679, EUR-Lex : https://eur-lex.europa.eu/eli/reg/2016/679/oj/eng/
- CloudEvents spec et release stable v1.0.2 : https://github.com/cloudevents/spec
- NIST SP 800-61 Rev. 3, réponse aux incidents dans la gestion des risques : https://csrc.nist.gov/pubs/sp/800/61/r3/final (référence pour les phases 18–20, pas preuve d'une conformité BK Security).
- Kubernetes Pod Security Standards : https://kubernetes.io/docs/concepts/security/pod-security-standards/ (profil candidat, pas une configuration appliquée au dépôt).
- Kubernetes Security Checklist : https://kubernetes.io/docs/concepts/security/security-checklist/ (recommandations à vérifier sur le runtime cible).
- Kubernetes Network Policies : https://kubernetes.io/docs/concepts/services-networking/network-policies/ (contrôles réseau à appliquer et tester par environnement).
