import threading
import secrets

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from bk_security.policy.engine import Action
from bk_security.policy.response import ResponseEngine
from bk_security.services.approval import SignedApprovalVerifier, TrustedSigner, complete_approval_envelope, make_approval_envelope
from bk_security.services.response_client import RemoteResponseAdapter, ResponseServiceClient
from bk_security.services.response_service import ResponseExecutorService


class FakeClient:
    def __init__(self):
        self.authorizations = []
        self.requests = []

    def authorize(self, **scope):
        self.authorizations.append(scope)
        return f"grant-{scope['operation']}"

    def request(self, payload):
        self.requests.append(payload)
        if payload["op"] == "execute":
            return {"ok": True, "result": {"rule": "BK-Security-test", "reversible": True}}
        if payload["op"] == "verify":
            return {"ok": True, "result": {"verified": True}}
        if payload["op"] == "rollback":
            return {"ok": True, "result": {"removed": True}, "verification": {"verified": True}}
        raise AssertionError(payload)


def test_response_engine_transmits_approval_and_execution_scope_to_service():
    client = FakeClient()
    adapter = RemoteResponseAdapter(Action.BLOCK, client)
    engine = ResponseEngine(adapters={Action.BLOCK: adapter})
    plan = engine.plan("plan-remote-001", Action.BLOCK, "203.0.113.25", "test", dry_run=False)
    approved = engine.approve(plan["plan_id"], "approver-a", "approver")

    result = engine.execute(plan["plan_id"], plan["plan_id"], "responder-b", "responder", dry_run=False)

    assert result["status"] == "executed"
    assert client.authorizations == [{
        "operation": "execute", "action": Action.BLOCK, "target": "203.0.113.25",
        "execution_id": "plan-remote-001", "approval": approved["approval"],
    }]
    assert client.requests[0]["execution_id"] == "plan-remote-001"
    assert client.requests[0]["authorization_id"] == "grant-execute"


def test_remote_rollback_sends_distinct_approval_and_uses_service_verification():
    client = FakeClient()
    adapter = RemoteResponseAdapter(Action.BLOCK, client)
    execution = {
        "action": Action.BLOCK.value, "target": "203.0.113.25", "execution_id": "execution-001",
        "rollback_approval": {"actor": "approver-a", "role": "approver", "plan_id": "execution-001"},
    }

    result = adapter.rollback(execution)

    assert result == {"removed": True}
    assert client.authorizations[0]["operation"] == "rollback"
    assert client.requests[0]["execution_id"] == "execution-001"
    assert adapter.verify_rollback(execution, result) == {"verified": True}


def test_response_service_client_calls_authorize_operation_without_exposing_issue_grant(monkeypatch):
    client = ResponseServiceClient("unused", b"k" * 32)
    sent = []

    def fake_request(_self, payload):
        sent.append(payload)
        return {"ok": True, "authorization_id": "grant-from-service"}

    monkeypatch.setattr(ResponseServiceClient, "request", fake_request)
    grant = client.authorize(
        operation="execute", action=Action.BLOCK, target="203.0.113.25",
        execution_id="execution-001", approval={"actor": "approver-a"},
    )

    assert grant == "grant-from-service"
    assert sent == [{
        "op": "authorize", "mutation_op": "execute", "action": "block",
        "target": "203.0.113.25", "execution_id": "execution-001",
        "approval": {"actor": "approver-a"},
    }]


def test_response_engine_prefers_independent_proof_for_privileged_service():
    client = FakeClient()
    adapter = RemoteResponseAdapter(Action.BLOCK, client)
    engine = ResponseEngine(adapters={Action.BLOCK: adapter})
    plan = engine.plan("plan-proof-001", Action.BLOCK, "203.0.113.25", "test", dry_run=False)
    engine.approve(plan["plan_id"], "api-approver", "approver")
    proof = {"version": 1, "proof": "signed-outside-the-api"}

    result = engine.execute(
        plan["plan_id"], plan["plan_id"], "api-responder", "responder",
        dry_run=False, authorization_proof=proof,
    )

    assert result["status"] == "executed"
    assert client.authorizations[0]["approval"] == proof


def test_local_ipc_dry_run_path_covers_approval_execute_and_rollback(tmp_path):
    from bk_security.services.response_service import DryRunAdapter

    class VerifyingAdapter(DryRunAdapter):
        def verify(self, target, action, result):
            return {"verified": True}

        def verify_rollback(self, execution, result):
            return {"verified": True}

    approver_key, responder_key = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    verifier = SignedApprovalVerifier({
        "approver-a": TrustedSigner("approver-a", "approver", approver_key.public_key()),
        "responder-b": TrustedSigner("responder-b", "responder", responder_key.public_key()),
    }, clock=lambda: 1100)
    ipc_key_path = tmp_path / "response.key"
    ipc_key_path.write_text("test-only-response-key-file", encoding="utf-8")
    trust_store_path = tmp_path / "trust.json"
    trust_store_path.write_text("[]", encoding="utf-8")
    service = ResponseExecutorService(
        {Action.BLOCK: VerifyingAdapter(Action.BLOCK)},
        state_path=str(tmp_path / "state.db"), audit_path=str(tmp_path / "audit.jsonl"),
        authorization_verifier=verifier,
        ipc_key_path=str(ipc_key_path), trust_store_path=str(trust_store_path),
        windows_acl_validator=lambda *_args: True,
    )
    key = secrets.token_urlsafe(32).encode("ascii")
    from bk_security.services.protocol import default_address
    address = default_address(key)
    stop, ready = threading.Event(), threading.Event()
    server = threading.Thread(target=service.serve, args=(address, key, stop, ready), daemon=True)
    server.start()
    assert ready.wait(2)

    try:
        client = ResponseServiceClient(address, key, timeout=2)
        engine = ResponseEngine(adapters={Action.BLOCK: RemoteResponseAdapter(Action.BLOCK, client)})
        plan = engine.plan("plan-ipc-001", Action.BLOCK, "203.0.113.25", "test", dry_run=False)
        approved = engine.approve(plan["plan_id"], "approver-a", "approver")
        envelope = make_approval_envelope(
            operation="execute", action=Action.BLOCK, target=plan["target"],
            execution_id=plan["plan_id"], approver_key_id="approver-a",
            executor_key_id="responder-b", approver_private_key=approver_key,
            issued_at=1000, expires_at=1200, nonce="n" * 24,
        )
        proof = complete_approval_envelope(envelope, executor_private_key=responder_key)

        execution = engine.execute(
            plan["plan_id"], plan["plan_id"], "responder-b", "responder", dry_run=False,
            authorization_proof=proof,
        )
        assert execution["status"] == "executed"

        engine.approve(plan["plan_id"], "approver-a", "approver", rollback=True)
        rollback_envelope = make_approval_envelope(
            operation="rollback", action=Action.BLOCK, target=plan["target"],
            execution_id=plan["plan_id"], approver_key_id="approver-a",
            executor_key_id="responder-b", approver_private_key=approver_key,
            issued_at=1000, expires_at=1200, nonce="r" * 24,
        )
        rollback_proof = complete_approval_envelope(
            rollback_envelope, executor_private_key=responder_key,
        )
        rollback = engine.rollback(
            plan["plan_id"], "responder-b", "responder", authorization_proof=rollback_proof,
        )
        assert rollback["status"] == "rolled_back"
        assert service.audit.verify(str(tmp_path / "audit.jsonl")) is True
    finally:
        stop.set()
        server.join(timeout=2)
