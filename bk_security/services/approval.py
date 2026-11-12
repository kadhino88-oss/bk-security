"""Dual-control approval proofs verified by the privileged response service.

The API may transport these proofs but cannot mint them: approval and responder
signing keys remain outside the API process. The service trust store contains
only Ed25519 public keys and must be protected by Windows ACLs at deployment.
"""
from __future__ import annotations

import base64
import json
import math
import re
import time
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from ..policy.engine import Action

_SIGNED_FIELDS = (
    "version", "operation", "action", "target", "execution_id", "issued_at", "expires_at",
    "nonce", "approver_key_id", "executor_key_id",
)
_PROOF_FIELDS = frozenset((*_SIGNED_FIELDS, "approver_signature", "executor_signature"))
_KEY_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.@-]{0,127}$")
_DOMAIN_APPROVER = b"BK-SECURITY-APPROVER-V1\0"
_DOMAIN_EXECUTOR = b"BK-SECURITY-EXECUTOR-V1\0"


@dataclass(frozen=True, slots=True)
class TrustedSigner:
    key_id: str
    role: str
    public_key: Ed25519PublicKey


def _canonical(value: Mapping[str, Any]) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
                      allow_nan=False).encode("ascii")


def _scope_fields(proof: Mapping[str, Any]) -> dict[str, Any]:
    return {key: proof[key] for key in _SIGNED_FIELDS}


def _signature_text(value: Any) -> bytes:
    if not isinstance(value, str) or not 80 <= len(value) <= 128:
        raise ValueError("invalid_signature")
    return base64.b64decode(value.encode("ascii"), validate=True)


def make_approval_envelope(*, operation: str, action: Action | str, target: str,
                           execution_id: str, approver_key_id: str, executor_key_id: str,
                           approver_private_key: Ed25519PrivateKey, issued_at: float | None = None,
                           expires_at: float | None = None, nonce: str) -> dict[str, Any]:
    """Create the approver-signed portion; the responder completes it separately."""
    issued = time.time() if issued_at is None else issued_at
    expiry = issued + 300 if expires_at is None else expires_at
    scope = {
        "version": 1, "operation": str(operation), "action": Action(action).value,
        "target": str(target), "execution_id": str(execution_id),
        "issued_at": issued, "expires_at": expiry, "nonce": str(nonce),
        "approver_key_id": str(approver_key_id), "executor_key_id": str(executor_key_id),
    }
    signature = base64.b64encode(approver_private_key.sign(_DOMAIN_APPROVER + _canonical(scope))).decode("ascii")
    return {**scope, "approver_signature": signature}


def complete_approval_envelope(envelope: Mapping[str, Any], *,
                                executor_private_key: Ed25519PrivateKey) -> dict[str, Any]:
    """Add the responder's signature after independently reviewing the approval envelope."""
    if set(envelope) != _PROOF_FIELDS - {"executor_signature"}:
        raise ValueError("invalid_approval_envelope")
    approver_signature = _signature_text(envelope.get("approver_signature"))
    data = _DOMAIN_EXECUTOR + _canonical(_scope_fields(envelope)) + b"\0" + approver_signature
    signature = base64.b64encode(executor_private_key.sign(data)).decode("ascii")
    return {**dict(envelope), "executor_signature": signature}


class SignedApprovalVerifier:
    """Verify distinct trusted approver and responder signatures over one exact scope."""

    def __init__(self, signers: Mapping[str, TrustedSigner], *, clock=time.time,
                 max_ttl_seconds: int = 300, allowed_clock_skew_seconds: int = 30) -> None:
        self.signers = dict(signers)
        self.clock = clock
        self.max_ttl_seconds = max_ttl_seconds
        self.allowed_clock_skew_seconds = allowed_clock_skew_seconds

    def __call__(self, scope: dict[str, Any]) -> bool:
        try:
            proof = scope.get("approval")
            if not isinstance(proof, dict) or set(proof) != _PROOF_FIELDS:
                return False
            if proof.get("version") != 1 or isinstance(proof.get("version"), bool):
                return False
            if proof.get("operation") != scope.get("op"):
                return False
            if proof.get("action") != scope.get("action"):
                return False
            if proof.get("target") != scope.get("target"):
                return False
            if proof.get("execution_id") != scope.get("execution_id"):
                return False
            if proof.get("operation") not in {"execute", "rollback"}:
                return False
            if proof.get("action") not in {item.value for item in Action}:
                return False
            if not isinstance(proof.get("target"), str) or not proof["target"]:
                return False
            if not isinstance(proof.get("execution_id"), str) or not proof["execution_id"]:
                return False
            nonce = proof.get("nonce")
            if not isinstance(nonce, str) or not 16 <= len(nonce) <= 128:
                return False
            issued, expires = proof.get("issued_at"), proof.get("expires_at")
            if (isinstance(issued, bool) or isinstance(expires, bool)
                    or not isinstance(issued, (int, float)) or not isinstance(expires, (int, float))
                    or not math.isfinite(issued) or not math.isfinite(expires)):
                return False
            now = self.clock()
            if issued > now + self.allowed_clock_skew_seconds or expires <= now:
                return False
            if expires <= issued or expires - issued > self.max_ttl_seconds:
                return False

            approver_id, executor_id = proof.get("approver_key_id"), proof.get("executor_key_id")
            if (not isinstance(approver_id, str) or not _KEY_ID_RE.fullmatch(approver_id)
                    or not isinstance(executor_id, str) or not _KEY_ID_RE.fullmatch(executor_id)
                    or approver_id == executor_id):
                return False
            approver, executor = self.signers.get(approver_id), self.signers.get(executor_id)
            if not approver or approver.role != "approver" or not executor or executor.role != "responder":
                return False

            fields = _scope_fields(proof)
            approver_sig = _signature_text(proof.get("approver_signature"))
            executor_sig = _signature_text(proof.get("executor_signature"))
            approver.public_key.verify(approver_sig, _DOMAIN_APPROVER + _canonical(fields))
            executor.public_key.verify(
                executor_sig, _DOMAIN_EXECUTOR + _canonical(fields) + b"\0" + approver_sig,
            )
            return True
        except (InvalidSignature, ValueError, TypeError, KeyError, UnicodeError):
            return False


def load_trusted_signers(path: str | Path) -> dict[str, TrustedSigner]:
    """Load public identities from service-owned JSON; caller must verify its ACL first."""
    raw = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(raw, list):
        raise ValueError("approval_trust_store_must_be_a_list")
    signers: dict[str, TrustedSigner] = {}
    for item in raw:
        if not isinstance(item, dict) or set(item) != {"key_id", "role", "public_key_pem"}:
            raise ValueError("invalid_approval_trust_entry")
        key_id, role = item["key_id"], item["role"]
        if not isinstance(key_id, str) or not _KEY_ID_RE.fullmatch(key_id) or role not in {"approver", "responder"}:
            raise ValueError("invalid_approval_trust_identity")
        if key_id in signers:
            raise ValueError("duplicate_approval_trust_identity")
        public_key = serialization.load_pem_public_key(str(item["public_key_pem"]).encode("ascii"))
        if not isinstance(public_key, Ed25519PublicKey):
            raise ValueError("approval_identity_must_use_ed25519")
        signers[key_id] = TrustedSigner(key_id, role, public_key)
    return signers
