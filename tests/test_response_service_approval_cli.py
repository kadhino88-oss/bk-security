import json

from bk_security.services.approval import SignedApprovalVerifier, load_trusted_signers
from bk_security.services import approval_cli


def test_separate_approver_and_responder_cli_signatures_produce_verified_proof(tmp_path, monkeypatch):
    approver_private = tmp_path / "approver.pem"
    approver_public = tmp_path / "approver-public.json"
    responder_private = tmp_path / "responder.pem"
    responder_public = tmp_path / "responder-public.json"
    trust_store = tmp_path / "trusted.json"
    envelope_path = tmp_path / "approval-envelope.json"
    proof_path = tmp_path / "signed-proof.json"
    password = "correct horse battery staple"

    passwords = iter([password, password, password, password])
    monkeypatch.setattr(approval_cli.getpass, "getpass", lambda _prompt: next(passwords))
    assert approval_cli.main([
        "generate-identity", "--key-id", "approver-a", "--role", "approver",
        "--private-key", str(approver_private), "--public-entry", str(approver_public),
    ]) == 0
    assert approval_cli.main([
        "generate-identity", "--key-id", "responder-b", "--role", "responder",
        "--private-key", str(responder_private), "--public-entry", str(responder_public),
    ]) == 0

    trust_store.write_text(json.dumps([
        json.loads(approver_public.read_text(encoding="utf-8")),
        json.loads(responder_public.read_text(encoding="utf-8")),
    ]), encoding="utf-8")

    monkeypatch.setattr(approval_cli.getpass, "getpass", lambda _prompt: password)
    assert approval_cli.main([
        "approve", "--operation", "execute", "--action", "block", "--target", "203.0.113.25",
        "--execution-id", "execution-001", "--approver-key-id", "approver-a",
        "--executor-key-id", "responder-b", "--private-key", str(approver_private),
        "--expires-in", "120", "--output", str(envelope_path),
    ]) == 0
    assert approval_cli.main([
        "sign-execution", "--approval-file", str(envelope_path), "--executor-key-id", "responder-b",
        "--private-key", str(responder_private), "--output", str(proof_path),
    ]) == 0

    proof = json.loads(proof_path.read_text(encoding="utf-8"))
    verifier = SignedApprovalVerifier(load_trusted_signers(trust_store))
    assert verifier({
        "op": "execute", "action": "block", "target": "203.0.113.25",
        "execution_id": "execution-001", "approval": proof,
    }) is True
    assert approval_cli.main([
        "generate-identity", "--key-id", "approver-c", "--role", "approver",
        "--private-key", str(approver_private), "--public-entry", str(tmp_path / "unused.json"),
    ]) == 2
