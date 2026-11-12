# Privileged response authorization

The API's approver and responder roles remain useful workflow checks, but the
privileged executor does not accept those claims as proof. It requires an
Ed25519 proof signed by two different trusted identities:

1. An approver signs `operation`, `action`, `target`, `execution_id`, expiry,
   and the expected responder key ID.
2. That responder signs the same scope and the approver signature.
3. The service verifies both keys against its public-key trust store and issues
   a short-lived, one-use grant. The API forwards the proof; it has no private
   signing key and no `issue_grant` IPC operation.

The grant lifetime is at most 120 seconds. The signed approval lifetime is at
most 300 seconds. Rollback requires a new proof with `operation=rollback`.

## Offline identity and proof commands

Install the project with its test/runtime dependencies, then run these commands
under separate Windows user identities. Keep each encrypted private key out of
the API account and protect the public trust store with the response service's
Windows ACLs.

```powershell
bk-security-approval generate-identity `
  --key-id approver-a --role approver `
  --private-key "$env:USERPROFILE\BK Security\approver-a.pem" `
  --public-entry "$env:USERPROFILE\BK Security\approver-a.public.json"

bk-security-approval generate-identity `
  --key-id responder-b --role responder `
  --private-key "$env:USERPROFILE\BK Security\responder-b.pem" `
  --public-entry "$env:USERPROFILE\BK Security\responder-b.public.json"
```

An administrator combines the two public entries into the service-owned trust
store JSON list. The approver signs the exact plan scope; the responder then
reviews and completes that envelope:

```powershell
bk-security-approval approve `
  --operation execute --action block --target 203.0.113.25 `
  --execution-id <plan-id> --approver-key-id approver-a `
  --executor-key-id responder-b `
  --private-key "$env:USERPROFILE\BK Security\approver-a.pem" `
  --output .\approval-envelope.json

bk-security-approval sign-execution `
  --approval-file .\approval-envelope.json --executor-key-id responder-b `
  --private-key "$env:USERPROFILE\BK Security\responder-b.pem" `
  --output .\authorization-proof.json
```

Send `authorization-proof.json` as `authorization_proof` in the API execute
request. Supply a newly signed rollback proof to the rollback request. The
dashboard remains dry-run only.

## Deployment gate

`ResponseExecutorService.with_trust_store()` wires the Ed25519 verifier into
the service. Windows service installation, service-account selection, ACL
validation for the state directory, audit file, trust store, IPC key, and named
pipe, plus an actual VM test, remain deployment gates. Until those gates pass,
production startup must leave Windows responses disabled. Do not use a
test-only verifier outside unit tests.

The Windows-hosted Python, Electron, and dashboard regression result is
recorded in [P0 Windows regression validation](P0_WINDOWS_REGRESSION_VALIDATION_20261112.md).
It does not close the service-installation or real-adapter validation gates.
