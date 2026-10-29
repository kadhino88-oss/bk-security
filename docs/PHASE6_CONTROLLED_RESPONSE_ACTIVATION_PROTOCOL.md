# Phase 6 — Protocole préalable à toute activation contrôlée des réponses

**État : NO-GO sur le poste actuel.** Ce document fixe les conditions d'une éventuelle validation ultérieure. Il n'autorise pas l'activation de réponses Windows et ne contient aucune commande d'activation.

## Motif du NO-GO actuel

- La validation Phase 6 est verte pour la chaîne à impact nul : capture Npcap limitée à `127.0.0.1`, détection, incident/Threat Family, investigation AI avec provenance et plan de réponse dry-run.
- `BK_SECURITY_WINDOWS_RESPONSE` est resté à `0`; aucun adapter réel n'a été lancé.
- Les seuls adapters Windows recensés sont BLOCK, ISOLATE et TERMINATE_PROCESS. Aucun adapter Windows non destructif et réversible n'est disponible pour un premier essai réel.
- Les validations RBAC, audit, échec de vérification, rollback, persistance et redémarrage couvrent l'architecture via tests, mocks et canary; elles ne constituent pas une preuve d'exécution réelle d'un adapter sur Windows.

## Conditions obligatoires avant d'envisager un essai

1. Exécuter d'abord l'essai dans une VM Windows jetable, jamais sur le poste principal; documenter l'image, l'identifiant de VM, l'instantané restaurable et l'accès console hors bande.
2. Garder les réponses Windows désactivées tant qu'une revue spécifique de l'adapter et de son code n'a pas confirmé sa portée, son idempotence, ses préconditions, ses contrôles post-action et son rollback.
3. Fournir un chemin de validation non destructif et réversible. Tant que seuls les adapters BLOCK, ISOLATE et TERMINATE_PROCESS existent, aucun test réel d'adapter n'est admissible.
4. Rejouer la suite complète, le canary de redémarrage/API et le preflight runtime sur le commit identifié; capturer leurs sorties et la configuration effective.
5. Vérifier en dry-run le plan, la cible exacte, la portée, les preuves, la raison, le risque, l'expiration, le contrôle policy et l'absence d'exécution.
6. Pour chaque essai réel futur, exiger une autorisation humaine distincte, limitée à un adapter, une cible de laboratoire et une fenêtre précises. L'approbateur et l'exécutant doivent être des identités séparées; aucune approbation IA ne remplace ces contrôles.
7. Préparer et tester un rollback indépendant avant l'essai; vérifier que le journal d'audit reste intègre et que l'état attendu est restauré. Définir à l'avance les critères d'arrêt et le retour à l'instantané de VM.
8. N'évaluer toute extension de portée qu'après l'examen des journaux et de la vérification post-action de l'essai précédent. Chaque action sensible nécessite une nouvelle décision et une nouvelle approbation explicite.

## Critères d'arrêt immédiat

Arrêter et conserver les réponses désactivées si la cible ou la portée est ambiguë, si l'approbation est absente/expirée, si le mode dry-run n'est pas confirmé, si la vérification échoue, si l'audit ou la preuve manque, si le rollback n'est pas démontré, ou si le comportement diffère du plan. Un résultat `FAILED` ou `DEGRADED` interdit toute extension de l'essai.

## Statut après Phase 6

Aucune commande PowerShell élevée supplémentaire n'est nécessaire pour clore le gate à impact nul. Toute future étape nécessitant des privilèges élevés, une activation temporaire ou une réponse réelle devra être soumise à l'utilisateur avec sa commande exacte et attendre une validation explicite avant exécution. Le présent protocole ne constitue pas cette validation.

## Exécution loopback à impact nul — 2026-10-12

Après autorisation explicite de l’utilisateur, `scripts/validate_live_loopback_soc.py` a été exécuté en PowerShell élevé avec `BK_SECURITY_WINDOWS_RESPONSE=0`. La sortie fournie indique `status=passed`, une capture sur `\Device\NPF_Loopback`, une alerte et un incident liés à l’événement, une investigation AI avec provenance, et un plan `ALERT` en dry-run. Aucun adapter n’a été démarré; la policy a refusé le `BLOCK` proposé. Le détail figure dans [la validation terrain Phase 6](PHASE6_REAL_WORLD_VALIDATION.md).

Cette preuve clôt uniquement la validation à impact nul sur loopback. Le présent protocole reste **NO-GO** pour toute activation de réponse Windows réelle.
