import json
import time

import pytest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from bk_security.policy.engine import Action
from bk_security.services.approval import (
    SignedApprovalVerifier,
    TrustedSigner,
    complete_approval_envelope,
    load_trusted_signers,
    make_approval_envelope,
)
from bk_security.services.response_service import DryRunAdapter, ResponseExecutorService


def identities():
    approver = Ed25519PrivateKey.generate()
    responder = Ed25519PrivateKey.generate()
    signers = {
        "alice-approver": TrustedSigner("alice-approver", "approver", approver.public_key()),
        "bob-responder": TrustedSigner("bob-responder", "responder", responder.public_key()),
    }
    return approver, responder, signers


def signed_proof(approver, responder, *, expires_at=1200, approver_id="alice-approver",
                 executor_id="bob-responder", issued_at=1000):
    envelope = make_approval_envelope(
        operation="execute", action=Action.BLOCK, target="203.0.113.25",
        execution_id="execution-001", approver_key_id=approver_id,
        executor_key_id=executor_id, approver_private_key=approver,
        issued_at=issued_at, expires_at=expires_at, nonce="n" * 24,
    )
    return complete_approval_envelope(envelope, executor_private_key=responder)


def scope(proof):
    return {
        "phase": "issue", "op": "execute", "action": "block",
        "target": "203.0.113.25", "execution_id": "execution-001", "approval": proof,
    }


def test_distinct_trusted_approver_and_responder_sign_exact_scope():
    approver, responder, signers = identities()
    verifier = SignedApprovalVerifier(signers, clock=lambda: 1100)
    assert verifier(scope(signed_proof(approver, responder))) is True


def test_signature_is_bound_to_operation_action_target_and_execution_id():
    approver, responder, signers = identities()
    verifier = SignedApprovalVerifier(signers, clock=lambda: 1100)
    now = time.time()
    proof = signed_proof(approver, responder, issued_at=now, expires_at=now + 120)
    for changed in (
        {"op": "rollback"}, {"action": "isolate"}, {"target": "203.0.113.26"},
        {"execution_id": "execution-002"},
    ):
        assert verifier({**scope(proof), **changed}) is False


def test_expired_or_overlong_proofs_are_refused():
    approver, responder, signers = identities()
    verifier = SignedApprovalVerifier(signers, clock=lambda: 1201)
    assert verifier(scope(signed_proof(approver, responder, expires_at=1200))) is False

    verifier = SignedApprovalVerifier(signers, clock=lambda: 1100, max_ttl_seconds=120)
    assert verifier(scope(signed_proof(approver, responder, expires_at=1300))) is False


def test_same_identity_wrong_role_unknown_identity_and_tampering_are_refused():
    approver, responder, signers = identities()
    verifier = SignedApprovalVerifier(signers, clock=lambda: 1100)
    assert verifier(scope(signed_proof(approver, responder, executor_id="alice-approver"))) is False
    assert verifier(scope(signed_proof(approver, responder, executor_id="unknown-responder"))) is False

    proof = signed_proof(approver, responder)
    proof["target"] = "203.0.113.26"
    assert verifier(scope(proof)) is False


def test_trust_store_loads_only_ed25519_public_identities(tmp_path):
    approver, _, _ = identities()
    pem = approver.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")
    trust_file = tmp_path / "trust.json"
    trust_file.write_text(json.dumps([{
        "key_id": "alice-approver", "role": "approver", "public_key_pem": pem,
    }]), encoding="utf-8")
    assert load_trusted_signers(trust_file)["alice-approver"].role == "approver"

    trust_file.write_text(json.dumps([
        {"key_id": "alice-approver", "role": "approver", "public_key_pem": pem},
        {"key_id": "alice-approver", "role": "approver", "public_key_pem": pem},
    ]), encoding="utf-8")
    try:
        load_trusted_signers(trust_file)
    except ValueError as exc:
        assert "duplicate" in str(exc)
    else:
        raise AssertionError("Duplicate trust identities must be rejected.")


def test_privileged_service_factory_wires_signed_proof_verifier(tmp_path):
    approver, responder, _ = identities()
    def pem(key):
        return key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("ascii")
    trust_store = tmp_path / "trusted.json"
    trust_store.write_text(json.dumps([
        {"key_id": "alice-approver", "role": "approver", "public_key_pem": pem(approver)},
        {"key_id": "bob-responder", "role": "responder", "public_key_pem": pem(responder)},
    ]), encoding="utf-8")
    service = ResponseExecutorService.with_trust_store(
        {Action.BLOCK: DryRunAdapter(Action.BLOCK)}, trust_store_path=str(trust_store),
        state_path=str(tmp_path / "state.db"), audit_path=str(tmp_path / "audit.jsonl"),
        clock=lambda: 1100,
    )
    now = time.time()
    proof = signed_proof(approver, responder, issued_at=now, expires_at=now + 120)
    assert service.authorization_verifier(scope(proof)) is True


def test_service_persists_and_rejects_reused_approval_nonce(tmp_path):
    approver, responder, signers = identities()
    now = time.time()
    proof = signed_proof(approver, responder, issued_at=now, expires_at=now + 120)
    service = ResponseExecutorService(
        {Action.BLOCK: DryRunAdapter(Action.BLOCK)},
        authorization_verifier=SignedApprovalVerifier(signers),
        state_path=str(tmp_path / "state.db"),
    )
    service.issue_grant(
        op="execute", action=Action.BLOCK, target="203.0.113.25",
        execution_id="execution-001", approval=proof,
    )
    with pytest.raises(PermissionError, match="approval_replayed"):
        service.issue_grant(
            op="execute", action=Action.BLOCK, target="203.0.113.25",
            execution_id="execution-001", approval=proof,
        )
