# BK Security development instructions

Use `docs/BK_SECURITY_V1_ARCHITECTURE_TECHNICAL_SPEC.txt` as the canonical product specification. Follow its section 52 phase order when selecting the next block.

## Section 51 quality gate

For each feature, require all four before calling it complete:

1. **Implemented** in the product code.
2. **Tested** with matching unit/integration/end-to-end coverage as appropriate.
3. **Integrated** into the documented event, incident, API, dashboard or desktop path.
4. **Validated** by running the relevant tests or target-environment checks and recording their actual result.

Do not mark a feature complete based on files, stubs, plans, screenshots, or build configuration alone. State what remains unverified. Do not claim live capture, Electron, NSIS, packaging, performance, or provenance validation unless it was actually run and passed.

Preserve existing work and source notices. Before replacing a working base, make a recoverable copy. Keep `NOTICE-ORIGINS.md` and the associated provenance record with the product source.
