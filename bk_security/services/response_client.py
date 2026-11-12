"""Client-side adapters for the privileged response executor."""
from __future__ import annotations

import os
import threading
from dataclasses import dataclass, field
from typing import Any

from ..policy.engine import Action
from .protocol import call, load_key, resolve_address


class ResponseServiceError(RuntimeError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(slots=True)
class ResponseServiceClient:
    address: str
    key: bytes
    timeout: float = 30.0

    @classmethod
    def from_environment(cls, env=None) -> "ResponseServiceClient":
        env = os.environ if env is None else env
        key = load_key(env)
        return cls(resolve_address(env, key), key)

    def request(self, payload: dict[str, Any]) -> dict[str, Any]:
        try:
            response = call(self.address, self.key, payload, self.timeout)
        except Exception as exc:
            raise ResponseServiceError("response_service_unavailable") from exc
        if not isinstance(response, dict):
            raise ResponseServiceError("invalid_response_service_reply")
        return response

    def authorize(self, *, operation: str, action: Action, target: str,
                  execution_id: str, approval: dict[str, Any]) -> str:
        response = self.request({
            "op": "authorize", "mutation_op": operation, "action": action.value,
            "target": target, "execution_id": execution_id, "approval": approval,
        })
        authorization_id = response.get("authorization_id")
        if response.get("ok") is not True or not isinstance(authorization_id, str):
            raise ResponseServiceError(str(response.get("error") or "authorization_refused"))
        return authorization_id


@dataclass(slots=True)
class RemoteResponseAdapter:
    """Proxy an OS adapter call through the privileged service.

    A dual-signed authorization proof is forwarded as evidence only. The service's
    independent verifier checks both trusted identities before issuing a one-use grant.
    """

    action: Action
    client: ResponseServiceClient
    requires_independent_authorization: bool = field(default=True, init=False)
    _rollback_verifications: dict[str, dict[str, Any]] = field(default_factory=dict, init=False)
    _lock: threading.Lock = field(default_factory=threading.Lock, init=False)

    def execute(self, target: str, action: Action, reason: str, *, execution_id: str,
                approval: dict[str, Any] | None = None) -> dict[str, Any]:
        if action != self.action:
            raise ResponseServiceError("action_mismatch")
        if not isinstance(approval, dict):
            raise ResponseServiceError("approval_evidence_required")
        authorization_id = self.client.authorize(
            operation="execute", action=action, target=target,
            execution_id=execution_id, approval=approval,
        )
        response = self.client.request({
            "op": "execute", "action": action.value, "target": target,
            "reason": reason, "execution_id": execution_id,
            "authorization_id": authorization_id,
        })
        if response.get("ok") is not True:
            raise ResponseServiceError(str(response.get("error") or "response_execution_refused"))
        if response.get("audit_error") is True:
            raise ResponseServiceError("effect_completed_but_audit_unavailable")
        result = response.get("result")
        if not isinstance(result, dict):
            raise ResponseServiceError("invalid_response_service_result")
        return result

    def verify(self, target: str, action: Action, result: dict[str, Any]) -> dict[str, Any]:
        response = self.client.request({
            "op": "verify", "action": action.value, "target": target, "result": result,
        })
        if response.get("ok") is not True or not isinstance(response.get("result"), dict):
            raise ResponseServiceError(str(response.get("error") or "response_verification_failed"))
        return response["result"]

    def rollback(self, execution: dict[str, Any]) -> dict[str, Any]:
        if execution.get("action") != self.action.value:
            raise ResponseServiceError("execution_mismatch")
        execution_id = execution.get("execution_id")
        target = execution.get("target")
        approval = execution.get("authorization_proof", execution.get("rollback_approval"))
        if not isinstance(execution_id, str) or not isinstance(target, str):
            raise ResponseServiceError("execution_context_missing")
        if not isinstance(approval, dict):
            raise ResponseServiceError("rollback_approval_evidence_required")
        authorization_id = self.client.authorize(
            operation="rollback", action=self.action, target=target,
            execution_id=execution_id, approval=approval,
        )
        response = self.client.request({
            "op": "rollback", "action": self.action.value,
            "execution_id": execution_id, "authorization_id": authorization_id,
        })
        if response.get("ok") is not True:
            raise ResponseServiceError(str(response.get("error") or "response_rollback_refused"))
        verification = response.get("verification")
        if not isinstance(verification, dict):
            verification = {"verified": False, "reason": "invalid_service_verification"}
        with self._lock:
            self._rollback_verifications[execution_id] = verification
        if response.get("audit_error") is True:
            raise ResponseServiceError("rollback_completed_but_audit_unavailable")
        result = response.get("result")
        if not isinstance(result, dict):
            raise ResponseServiceError("invalid_response_service_result")
        return result

    def verify_rollback(self, execution: dict[str, Any], result: dict[str, Any]) -> dict[str, Any]:
        execution_id = str(execution.get("execution_id") or "")
        with self._lock:
            verification = self._rollback_verifications.pop(execution_id, None)
        return verification or {"verified": False, "reason": "service_verification_unavailable"}


def build_remote_adapters(env=None) -> dict[Action, RemoteResponseAdapter]:
    client = ResponseServiceClient.from_environment(env)
    return {
        action: RemoteResponseAdapter(action, client)
        for action in (Action.BLOCK, Action.ISOLATE, Action.TERMINATE_PROCESS)
    }
