# BK Security source provenance status

The supplied BK Security snapshot has no Git metadata, so this workspace cannot verify line-by-line file history or identify the exact upstream commit from which each inherited file originated.

The upstream origin notice and license terms included with the snapshot are preserved as `NOTICE-ORIGINS.md` and `LICENSE-THIRD-PARTY-ORBIS.txt`, following Section 54 of the supplied BK Security V1 architecture document. An earlier record referred to a pre-consolidation backup at `work/provenance-review/pre-bk-native`; that path was not found under this project root during the 2026-10-20 check. The external sibling location was not checked, so its current presence is unverified. No source-base replacement or destructive cleanup was performed in that check.

The current BK Security runtime uses BK Security event, sensor, core, API, correlation and response modules. This statement describes the current architecture; it does not establish the legal provenance or licensing status of every source line. No file-by-file clean-room or license applicability review has been completed.

## 2026-10-20 release-gate check

- The official [PCYBOX Orbis upstream repository](https://github.com/Mister-iks/pcybox-orbis) was rechecked on 2026-10-20. Its project page identifies AGPL v3 and states that commercial use requires a separate license from the author. This agrees with the preserved local license text; it is not itself a commercial grant.
- The source tree still has no Git metadata, so exact inherited-file history and upstream revision cannot be established from this checkout.
- The source `NOTICE-ORIGINS.md` and `LICENSE-THIRD-PARTY-ORBIS.txt` SHA-256 hashes (`4736885F31F40AE567D921B6A16DF49E895FA12FB8B9618723709BD0332C10B1` and `09AEE2BDB2F6E065E62800263848AC75DB489A1A21C9B498C78E6D191542C0B3`) matched the copies in release candidate `dist/windows-20261018-230555-2ab368/win-unpacked/resources/legal/`.
- The dashboard source now displays the attribution text required by the preserved Orbis terms. The installed package has not been rebuilt with that UI change, so package-level display is unverified.
- The preserved terms state that commercial use of this derivative requires a separate commercial license. The reviewed files contain no separate grant. Commercial distribution is therefore not cleared by this record; obtain and verify that grant or complete a documented provenance and replacement review before sale.

The unchanged architecture specification is preserved at `docs/BK_SECURITY_V1_ARCHITECTURE_TECHNICAL_SPEC.txt`. Its Sections 51 and 54 govern completion claims and origin notices.
