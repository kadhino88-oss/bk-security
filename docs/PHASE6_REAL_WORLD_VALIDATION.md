# Phase 6 — Real-world validation / hardening

Dernière capture réelle : 2026-10-12 (Europe/Zurich). Recontrôle VM/hôte : 2026-10-20. Aucune activation ni réponse Windows réelle.

## Revalidation loopback du 2026-10-12

L’utilisateur a exécuté `scripts/validate_live_loopback_soc.py` depuis une session PowerShell élevée, avec `BK_SECURITY_WINDOWS_RESPONSE=0`. La sortie complète a été fournie dans la conversation; l’horodatage précis de l’exécution n’est pas présent dans cette sortie.

- Résultat `passed`; interface `\Device\NPF_Loopback`; filtre `udp and dst port 4444 and host 127.0.0.1`.
- Un datagramme local vers `127.0.0.1:4444/udp` a été capturé et relié à une alerte `SUSPICIOUS_NETWORK_BEHAVIOR` de sévérité `medium`.
- L’incident a été créé avec Threat Family `tf-ec0dc1185abfa62e505c`; l’investigation AI est valide avec deux éléments de preuve et la provenance alerte/événement/incident.
- La tentative `BLOCK` a été ramenée à `ALERT` par la policy de sévérité medium (`allowed=false`). Le plan était `dry_run=true`; `execution_started=false` et `response_adapters_enabled=false`.
- La base SQLite était temporaire et supprimée à la fin; aucun paquet brut n’a été stocké. La portée réseau observée était limitée au loopback localhost.

Cette exécution valide le pipeline live Npcap loopback → événement → détection/incident → investigation AI/provenance → plan dry-run dans le script du workspace. Elle ne valide ni le démarrage live depuis l’interface du produit empaqueté, ni la capture Wi-Fi, ni la visibilité réseau multi-client, ni une réponse Windows réelle.

## État machine observé

- Windows / PowerShell 7.6.5 (la version détaillée de Windows n’a pas été relevée).
- Service Npcap : Running; Npcap détecté dans C:\Program Files\Npcap.
- Scapy : 2.7.0. Cinq interfaces réseau détectées; Wi-Fi Up, Ethernet Disconnected, interface Npcap loopback \Device\NPF_Loopback visible par Scapy.
- L’inspection initiale était non élevée (is_elevated=False). L’utilisateur a ensuite exécuté le contrôle loopback dans une session élevée; la capture a réussi comme documenté ci-dessous.
- Le garde-fou du script loopback a été vérifié sans élévation : il s’arrête avec code 2 et indique qu’aucune capture n’a démarré.
- BK_SECURITY_WINDOWS_RESPONSE était absent du processus d’inspection (valeur par défaut de l’application : désactivé). Les commandes de validation ci-dessous ont imposé 0.
- Aucun processus Python/uvicorn correspondant au backend BK Security n’a été trouvé lors de l’inspection.
- Le dossier ne contient pas .git; aucune branche, révision ou diff Git ne peut être certifié. Une copie de sauvegarde des deux fichiers modifiés est conservée dans backup-phase6-prechange-20261006.

## Protections et correction

- Les adapters Windows ne sont raccordés qu’avec BK_SECURITY_WINDOWS_RESPONSE=1; le flag est resté à 0 pour les validations.
- Le plan dry-run retourne executed=False sans appeler l’adapter. Les actions Windows disponibles sont BLOCK, ISOLATE et TERMINATE_PROCESS; il n’existe pas d’adapter Windows non destructif adapté à un test réel. Les adapters n’ont donc été exercés que par mocks.
- Correction ciblée : LivePacketCapture._parse() transmet maintenant l’horodatage Scapy au PacketObservation; si la valeur manque ou n’est pas numérique, l’heure locale de traitement sert de repli.
- Ajout d’un test de propagation Scapy → observation → SecurityEvent, et assertion de Threat Family dans le scénario de capture simulée.

## Validations exécutées sans élévation

- Compilation syntaxique en mémoire : PASS — 98 fichiers Python compilés en mémoire (BOM UTF-8 accepté).
- Suite complète : 145 passed in 24.16s; exit code 0. Réponses imposées à 0; API canary en simulation; données d’essai isolées dans work/phase6-final ou TemporaryDirectory.
- Canary API avec redémarrage, persistance, RBAC, AI SOC / provenance, plan dry-run et capture de simulation : PASS.
- Preflight runtime : PASS.
- Les contrôles de Threat Family, audit chaîné, échec de vérification, RBAC, rollback par mocks et absence d’activation des adapters sont couverts par la suite automatisée; aucune mutation firewall/processus n’a été effectuée.

## Étape 3 — capture loopback réelle confirmée

L’utilisateur a exécuté le validateur dans PowerShell élevé le 2026-10-06. Résultat fourni :

- Statut passé; interface Npcap \Device\NPF_Loopback; filtre udp and host 127.0.0.1.
- Un paquet vers 127.0.0.1:9/udp a produit un événement dans PacketPipeline.
- Horodatage observé : 2026-10-06T17:45:37.695328+00:00.
- Aucun stockage de paquet brut, aucune persistance SQLite et aucun adapter de réponse activé (BK_SECURITY_WINDOWS_RESPONSE=0).

Cela valide Npcap loopback → parsing → pipeline. Le premier script collecte l’événement en mémoire et ne le transmet pas à SecurityCore; il ne prouve donc pas à lui seul la détection/alerte réelle.

## Étapes 4–6 — validées sur le loopback réel

L’utilisateur a exécuté scripts/validate_live_loopback_soc.py en PowerShell élevé. Résultat fourni :

- Un événement réel UDP localhost vers le port 4444 a traversé le capture pipeline et créé une alerte SUSPICIOUS_NETWORK_BEHAVIOR de sévérité medium, liée à l’événement.
- Incident créé avec Threat Family tf-ec0dc1185abfa62e505c.
- Investigation AI intégrée valide, avec deux éléments de preuve et provenance alerte/événement/incident confirmée.
- Le plan a proposé BLOCK à la policy, avec une recommandation AI BLOCK. La policy medium l’a refusé (allowed=false) et a sélectionné ALERT. Le plan est resté dry-run; aucune exécution ni adapter n’a démarré.
- Le test a utilisé une base SQLite temporaire supprimée à sa fin, sans paquet brut ni trafic hors loopback.

Le test confirme que l’IA ne peut pas passer outre la décision de policy sur un signal live. Les tests automatisés et le canary couvrent aussi RBAC et les routes API, mais avec des événements simulés.

## État final et limites

Les critères de validation à zéro impact sont verts : suite complète et canary réussis, capture loopback réelle, détection→incident/Threat Family, investigation AI avec provenance et plan dry-run. Une capture endpoint Wi-Fi bornée est également passée le 2026-10-12; elle valide l’ingestion d’événements réseau réels dans le pipeline et `SecurityCore`, sans trafic de test ni action de réponse. RBAC, intégrité de la chaîne d’audit, échec de vérification, rollback et redémarrage ont été couverts par la suite et le canary avec données simulées. L’audit policy/plan a aussi été retrouvé dans la base temporaire du validateur loopback. Aucune action n’a été exécutée, donc la vérification post-action et le rollback d’un adapter réel n’ont pas été testés sur Windows. Aucun adapter Windows non destructif n’existe dans l’architecture actuelle; BLOCK, ISOLATE et TERMINATE_PROCESS ne seront pas testés réellement. Le démarrage live par le tableau, la visibilité des autres clients et l’activation de réponses restent hors validation. Un protocole préalable distinct est documenté dans docs/PHASE6_CONTROLLED_RESPONSE_ACTIVATION_PROTOCOL.md. Il est explicitement NO-GO sur le poste actuel et aucun adapter n'est activé.

## Reprise de validation du tableau et du Wi-Fi — 2026-10-12

- Le desktop installé était toujours connecté : le tableau SOC, le bouton `Sign out` et les compteurs étaient visibles. Aucun identifiant n’a été saisi.
- L’interface Windows locale `Wi-Fi` (`Intel(R) Dual Band Wireless-AC 8260`) était `Up`. Cette vérification d’interface ne prouve pas une capture Npcap.
- Le diagnostic Python en lecture seule a trouvé Npcap présent et Scapy disponible, mais `elevated=false` et `live_capture_available=false` dans le processus courant. Il n’a pas démarré de capture.
- La fenêtre contrôlable n’a exposé que la racine d’accessibilité. Les tentatives de défilement et de navigation clavier n’ont pas déplacé la page; le panneau `Packet capture` et son bouton n’ont donc pas été atteints. Aucun clic sur `Start live capture` n’a eu lieu et aucune capture Wi-Fi n’a démarré.
- L’inspection du code montre que le démarrage du tableau transmet l’interface choisie à l’API; `LivePacketCapture` utilise par défaut le filtre BPF `ip` et `AsyncSniffer(..., store=False)`. Le tableau ne propose ni filtre de capture ni limite de durée. Cela pourrait traiter tout le trafic IP livré à l’adaptateur et envoyer les observations dans le service installé. Ce test n’a pas été lancé sans une portée et une fenêtre bornées.
- Vérifications automatisées du même chemin, sans capture réelle : `tests/test_capture_pipeline.py`, `tests/test_platform_windows.py` et `tests/test_dashboard_contract.py` — **17 passed**; tests du tableau avec Node — **7 passed**; build Vite 8.3.3 — **17 modules transformed**, terminé, dans `work/dashboard-build-validation-20261012` pour préserver les assets existants.

Ces tests valident le contrat API, la sélection d’une interface Wi-Fi avec un capteur simulé, les tests de présentation et le build. Ils ne valident ni le clic du desktop empaqueté, ni une capture Wi-Fi réelle, ni la visibilité multi-client. La capture Wi-Fi réelle a été validée séparément ensuite, ci-dessous; le clic et la visibilité multi-client restent non validés.

## Contrôle Wi-Fi passif borné — 2026-10-12

- Ajout de `scripts/validate_live_wifi_capture.py`, qui sélectionne l’unique interface Npcap nommée `Wi-Fi`, vérifie qu’elle est active et possède une adresse IPv4, puis limite le filtre à `ip and host 192.168.1.121` (adresse relevée au préflight sur ce poste).
- La fenêtre est fixée à cinq secondes; aucun trafic de test n’est généré; `store=False` évite la rétention Scapy des paquets; les événements normalisés traversent `PacketPipeline` puis `SecurityCore` dans une base SQLite temporaire supprimée à la sortie. `BK_SECURITY_WINDOWS_RESPONSE=0` est obligatoire et les adapters doivent rester absents.
- Les tests du nouveau validateur passent (**11 passed**), la compilation Python passe, et la suite Python complète passe (**179 passed**).
- La première tentative directe s’est arrêtée avant capture car le processus n’était pas élevé (`Live Npcap capture needs an elevated PowerShell session; no capture was started.`); la demande Windows `RunAs` avait aussi été annulée avant le démarrage du processus élevé.
- L’utilisateur a ensuite exécuté le validateur dans PowerShell élevé et a fourni la sortie : `status=passed`, capture démarrée pendant cinq secondes, **202 événements `network.packet`** impliquant l’adresse Wi-Fi locale, base temporaire supprimée. L’interface capturée était `\Device\NPF_{A9A80D74-A358-43FF-937B-BB28C0AE3F1C}` (`Wi-Fi`, `192.168.1.121`), avec le filtre `ip and host 192.168.1.121`.
- La sortie confirme `raw_packet_storage=false`, `response_adapters_enabled=false` et `probe_traffic_generated=false`. Cela valide Npcap Wi-Fi → parsing → `PacketPipeline` → ingestion `SecurityCore` pour l’endpoint local. Elle ne prouve pas une alerte ou un incident pour le trafic observé, le démarrage depuis le tableau empaqueté ni la visibilité des autres clients du réseau.

## Recontrôle de disponibilité VM — 2026-10-20

Contrôle en lecture seule depuis la session Windows courante, sans élévation :

- Machine déclarée : Dell Latitude E7470; processeur Intel Core i5-6300U.
- `Win32_ComputerSystem.HypervisorPresent` vaut `True`, mais les propriétés processeur `VirtualizationFirmwareEnabled`, `VMMonitorModeExtensions` et `SecondLevelAddressTranslationExtensions` retournent `False`.
- `hvhost` et `vmcompute` sont `Running`; le service `vmms` et la commande Hyper-V `Get-VM` ne sont pas disponibles dans cette session.
- Les requêtes `Get-WindowsOptionalFeature` visant Hyper-V ont échoué car elles exigent une élévation. L’état exact des composants Hyper-V n’est donc pas vérifié.
- Mémoire physique libre observée : **1,241,136 KB** (~1.18 GiB). Cette mesure n’est pas une mesure permanente.

Ces résultats ne démontrent ni l’existence d’une VM jetable, ni son instantané restaurable, ni la capacité de lancer une VM de validation Windows. L’inventaire Hyper-V n’étant pas disponible et les indicateurs de virtualisation retournant `False`, le poste n’est pas considéré comme prêt pour la Phase 6. Garder `BK_SECURITY_WINDOWS_RESPONSE=0`; reprendre l’audit dans une session administrateur et sur une machine/VM de validation compatible. Ne pas contourner les contrôles de compatibilité Windows 11 pour qualifier le produit.

Le contrôle de compatibilité confirme aussi pourquoi une VM Windows 11 locale n’est pas une voie de validation acceptable ici : Microsoft exige que le processeur hôte satisfasse aux exigences processeur Windows 11, et indique au moins **4 GB** de mémoire pour la VM, Secure Boot et TPM virtuel. Le processeur hôte relevé est l’Intel Core i5-6300U, absent de la liste actuelle des processeurs Intel pris en charge; la machine n’a que 8 GB environ au total et moins de 1 GB libre pendant les contrôles. Voir les [exigences VM Windows 11](https://learn.microsoft.com/en-us/windows/whats-new/windows-11-requirements) et la [liste Microsoft des processeurs Intel pris en charge](https://learn.microsoft.com/en-us/windows-hardware/design/minimum/supported/windows-11-supported-intel-processors).

La voie matérielle à poursuivre est un hôte/ordinateur compatible ou une VM Windows hébergée sur un hôte compatible, avec assez de mémoire, TPM virtuel, Secure Boot, réseau isolé, console hors bande et instantané réellement restaurable. Cette voie n’a pas été créée dans ce contrôle. Même une telle VM ne lèvera pas à elle seule le NO-GO : le protocole Phase 6 exige encore un adapter de validation non destructif et réversible, une revue de portée et un rollback démontré.

