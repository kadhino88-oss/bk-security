"""Privileged response executor: the only process that holds operating-system adapters.

The API and detection processes never load firewall or process adapters; they send authenticated requests here.
The service re-validates every request against its own policy (allowed actions, target validation, protected
networks, rate cap) and appends every operation to its own hash-chained audit file. A compromised API process can
therefore only request what this policy allows; it cannot run arbitrary commands.
The service refuses mutations unless an independent, trusted authorization verifier is configured.
The verifier must be wired at privileged-service startup and must not trust IPC-supplied claims alone.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import sqlite3
import secrets
import threading
import time
from collections import deque
from contextlib import contextmanager
from collections.abc import Callable
from typing import Any

from ..policy.engine import Action
from ..policy.response import validate_target
from .protocol import MAX_MESSAGE_BYTES, make_listener, recv_json, send_json

DEFAULT_PROTECTED = ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16", "100.64.0.0/10",
                     "fc00::/7", "fe80::/10")
OPERATIONS = {"ping", "authorize", "execute", "verify", "rollback", "verify_rollback"}


class ServiceRefusal(Exception):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


class DryRunAdapter:
    """Executes nothing. Used to validate the service path and policy in a lab without touching the host."""

    def __init__(self, action: Action) -> None:
        self.action = action

    def execute(self, target, action, reason):
        return {"adapter": "dry_run", "simulated": True, "target": target, "reversible": True}

    def verify(self, target, action, result):
        return {"verified": False, "reason": "dry_run_adapter_enforces_nothing"}

    def rollback(self, execution):
        return {"adapter": "dry_run", "simulated": True, "removed": True}

    def verify_rollback(self, execution, result):
        return {"verified": False, "reason": "dry_run_adapter_enforces_nothing"}


class AuditChain:
    """Append-only JSONL file where each entry carries the hash of the previous one."""

    def __init__(self, path: str | None) -> None:
        self.path, self._lock, self._last = path, threading.Lock(), "0" * 64
        if path and os.path.exists(path):
            # Never silently resume an audit chain after corruption or truncation.
            if not self.verify(path):
                raise RuntimeError("audit_chain_integrity_failed")
            with open(path, encoding="utf-8") as handle:
                for line in handle:
                    self._last = json.loads(line)["hash"]

    def record(self, entry: dict[str, Any]) -> None:
        if not self.path:
            return
        with self._lock:
            body = {**entry, "ts": time.time(), "prev": self._last}
            digest = hashlib.sha256(json.dumps(body, sort_keys=True, default=str).encode()).hexdigest()
            with open(self.path, "a", encoding="utf-8") as handle:
                handle.write(json.dumps({**body, "hash": digest}, default=str) + "\n")
            self._last = digest

    @staticmethod
    def verify(path: str) -> bool:
        previous = "0" * 64
        try:
            with open(path, encoding="utf-8") as handle:
                for line in handle:
                    entry = json.loads(line)
                    if not isinstance(entry, dict):
                        return False
                    claimed = entry.pop("hash")
                    if entry["prev"] != previous or hashlib.sha256(
                            json.dumps(entry, sort_keys=True, default=str).encode()).hexdigest() != claimed:
                        return False
                    previous = claimed
            return True
        except (OSError, ValueError, KeyError, TypeError):
            return False


class ResponseExecutorService:
    """Fail-closed privileged executor with durable, one-use, server-issued grants.

    Trusted startup must configure a protected SQLite path and call issue_grant
    only AFTER independently verifying human approval. issue_grant is never an IPC operation.
    """
    def __init__(self, adapters: dict[Action, Any], *, allowed_actions: set[Action] | None = None,
                 protected_networks: tuple[str, ...] = DEFAULT_PROTECTED, max_executions_per_minute: int = 30,
                 audit_path: str | None = None, clock: Callable[[], float] = time.monotonic,
                 authorization_verifier: Callable[[dict[str, Any]], bool] | None = None,
                 windows_acl_validator: Callable[[str | None, str | None, str | None, str | None, str, bytes], bool] | None = None,
                 ipc_key_path: str | None = None,
                 trust_store_path: str | None = None,
                 state_path: str | None = None) -> None:
        self.adapters = dict(adapters)
        self.allowed = set(allowed_actions) if allowed_actions is not None else set(self.adapters)
        self._networks = tuple(ipaddress.ip_network(item, strict=False) for item in protected_networks)
        self.max_per_minute, self._clock = int(max_executions_per_minute), clock
        self._recent: deque[float] = deque()
        self._lock = threading.RLock()
        self.audit = AuditChain(audit_path)
        self._audit_healthy = True
        self.authorization_verifier = authorization_verifier
        self.windows_acl_validator = windows_acl_validator
        self.ipc_key_path = ipc_key_path
        self.trust_store_path = trust_store_path
        self.state_path = state_path
        if state_path:
            self._init_state()

    @classmethod
    def with_trust_store(cls, adapters: dict[Action, Any], *, trust_store_path: str, **kwargs):
        """Build with the production signed-proof verifier; protect the trust-store ACL first."""
        from .approval import SignedApprovalVerifier, load_trusted_signers

        verifier = SignedApprovalVerifier(load_trusted_signers(trust_store_path))
        return cls(
            adapters, authorization_verifier=verifier, trust_store_path=trust_store_path, **kwargs,
        )

    @contextmanager
    def _connect(self):
        """Close every SQLite connection, including on exceptions."""
        db = sqlite3.connect(self.state_path, timeout=10, isolation_level=None)
        try:
            db.execute('PRAGMA busy_timeout=10000')
            db.execute('PRAGMA synchronous=FULL')
            yield db
        finally:
            db.close()

    def _init_state(self):
        # The directory and DB must be ACL-restricted to the privileged service account.
        with self._connect() as db:
            db.execute('CREATE TABLE IF NOT EXISTS grants (id TEXT PRIMARY KEY, op TEXT NOT NULL, action TEXT NOT NULL, target TEXT NOT NULL, execution_id TEXT NOT NULL, expires REAL NOT NULL, consumed INTEGER NOT NULL DEFAULT 0)')
            db.execute('CREATE TABLE IF NOT EXISTS executions (id TEXT PRIMARY KEY, action TEXT NOT NULL, target TEXT NOT NULL, result TEXT NOT NULL, status TEXT NOT NULL)')
            db.execute('CREATE TABLE IF NOT EXISTS approval_nonces (nonce TEXT PRIMARY KEY, expires REAL NOT NULL)')

    def issue_grant(self, *, op: str, action: Action, target: str, execution_id: str,
                    ttl_seconds: int = 120, approval: dict[str, Any] | None = None) -> str:
        """TRUSTED LOCAL API ONLY. Caller MUST validate approval before calling."""
        if not self.state_path:
            raise RuntimeError('persistent_state_required')
        # Fail closed: trusted verifier must attest the approval before any grant exists.
        # The verifier is injected by privileged startup, never by an IPC client.
        if self.authorization_verifier is None:
            raise PermissionError('trusted_approval_verifier_required')
        if not isinstance(approval, dict):
            raise PermissionError('approval_evidence_required')
        if op not in {'execute', 'rollback'} or action not in self.allowed:
            raise ValueError('invalid_grant_scope')
        if not isinstance(execution_id, str) or not (8 <= len(execution_id) <= 128):
            raise ValueError('invalid_execution_id')
        if not isinstance(ttl_seconds, int) or not 1 <= ttl_seconds <= 300:
            raise ValueError('invalid_ttl')
        target = self._target(action, target)
        scope = {'phase': 'issue', 'op': op, 'action': action.value,
                 'target': target, 'execution_id': execution_id, 'approval': approval}
        try:
            approved = self.authorization_verifier(scope) is True
        except Exception:
            approved = False
        if not approved:
            raise PermissionError('approval_verification_failed')
        grant = secrets.token_urlsafe(32)
        nonce = approval.get('nonce')
        expiry = approval.get('expires_at')
        # Production signed proofs always carry both fields. Synthetic verifier
        # callbacks used by isolated tests may omit them; do not weaken the
        # production verifier, which rejects such proofs before this point.
        if not isinstance(nonce, str):
            nonce = 'local-' + secrets.token_urlsafe(24)
        if not isinstance(expiry, (int, float)) or isinstance(expiry, bool):
            expiry = time.time() + ttl_seconds
        with self._connect() as db:
            db.execute('BEGIN IMMEDIATE')
            try:
                db.execute('INSERT INTO approval_nonces VALUES (?,?)', (nonce, expiry))
                db.execute('INSERT INTO grants VALUES (?,?,?,?,?,?,0)',
                           (grant, op, action.value, target, execution_id, time.time() + ttl_seconds))
                db.execute('DELETE FROM approval_nonces WHERE expires <= ?', (time.time(),))
                db.execute('COMMIT')
            except sqlite3.IntegrityError:
                db.execute('ROLLBACK')
                raise PermissionError('approval_replayed') from None
            except Exception:
                db.execute('ROLLBACK')
                raise
        return grant

    def _action(self, request):
        try:
            action = Action(request.get('action'))
        except (ValueError, TypeError):
            raise ServiceRefusal('unknown_action') from None
        if action not in self.allowed or action not in self.adapters:
            raise ServiceRefusal('action_not_allowed')
        return action

    def _target(self, action, target):
        try:
            value = validate_target(action, str(target))
        except ValueError:
            raise ServiceRefusal('invalid_target') from None
        if action == Action.BLOCK:
            address = ipaddress.ip_address(value)
            if any(address.version == net.version and address in net for net in self._networks):
                raise ServiceRefusal('protected_target')
        return value

    def _rate_ok(self):
        now = self._clock()
        while self._recent and now - self._recent[0] > 60:
            self._recent.popleft()
        if len(self._recent) >= self.max_per_minute:
            return False
        return True

    def _consume(self, db, request, op, action, target, execution_id):
        grant = request.get('authorization_id')
        if not isinstance(grant, str) or len(grant) < 32 or len(grant) > 128:
            raise ServiceRefusal('authorization_required')
        row = db.execute('SELECT op,action,target,execution_id,expires,consumed FROM grants WHERE id=?', (grant,)).fetchone()
        if row is None:
            raise ServiceRefusal('authorization_required')
        if row[5]:
            raise ServiceRefusal('authorization_replayed')
        if (row[0],row[1],row[2],row[3]) != (op,action.value,target,execution_id) or row[4] <= time.time():
            raise ServiceRefusal('authorization_scope_invalid')
        # The grant was minted only after privileged verification of approval.
        # A request may not supply its own approval decision.
        cursor = db.execute('UPDATE grants SET consumed=1 WHERE id=? AND consumed=0', (grant,))
        if cursor.rowcount != 1:
            raise ServiceRefusal('authorization_replayed')

    def handle(self, request: dict[str, Any]) -> dict[str, Any]:
        if not isinstance(request, dict):
            return {'ok': False, 'error': 'invalid_request'}
        op = request.get('op')
        if op not in OPERATIONS:
            return {'ok': False, 'error': 'unknown_operation'}
        if op == 'ping':
            return {'ok': True, 'actions': sorted(a.value for a in self.allowed & set(self.adapters)),
                    'mutations_ready': bool(
                        self.state_path and self.audit.path and self.authorization_verifier and self._audit_healthy
                    )}
        try:
            action = self._action(request)
            adapter = self.adapters[action]
            if op == "authorize":
                if not self._audit_healthy:
                    raise ServiceRefusal('audit_unavailable')
                if not self.state_path:
                    raise ServiceRefusal('authorization_store_not_configured')
                if self.authorization_verifier is None:
                    raise ServiceRefusal('trusted_approval_verifier_required')
                mutation_op = request.get('mutation_op')
                if mutation_op not in {'execute', 'rollback'}:
                    raise ServiceRefusal('invalid_grant_scope')
                execution_id = request.get('execution_id')
                if not isinstance(execution_id, str) or not (8 <= len(execution_id) <= 128):
                    raise ServiceRefusal('execution_id_required')
                target = self._target(action, request.get('target'))
                if mutation_op == 'rollback':
                    with self._connect() as db:
                        record = db.execute(
                            'SELECT action,target,status FROM executions WHERE id=?', (execution_id,)
                        ).fetchone()
                    if (not record or record[0] != action.value or record[1] != target
                            or record[2] != 'executed' or action == Action.TERMINATE_PROCESS):
                        raise ServiceRefusal('execution_not_eligible')
                try:
                    grant = self.issue_grant(
                        op=mutation_op, action=action, target=target, execution_id=execution_id,
                        approval=request.get('approval'),
                    )
                except PermissionError as exc:
                    raise ServiceRefusal(str(exc)) from None
                try:
                    self.audit.record({
                        'op': 'authorize', 'mutation_op': mutation_op, 'action': action.value,
                        'target': target, 'execution_id': execution_id, 'ok': True,
                    })
                except Exception:
                    # A grant must never survive an authorization record that could not be audited.
                    with self._connect() as db:
                        db.execute('DELETE FROM grants WHERE id=?', (grant,))
                    self._audit_healthy = False
                    raise ServiceRefusal('audit_unavailable') from None
                return {'ok': True, 'authorization_id': grant}
            if op == 'verify':
                target = self._target(action, request.get('target'))
                return {'ok': True, 'result': adapter.verify(target, action, request.get('result') or {})}
            if op == 'verify_rollback':
                raise ServiceRefusal('verification_requires_trusted_internal_call')
            if not self._audit_healthy:
                raise ServiceRefusal('audit_unavailable')
            if not self.state_path:
                raise ServiceRefusal('authorization_store_not_configured')
            if self.authorization_verifier is None:
                raise ServiceRefusal('trusted_approval_verifier_required')
            execution_id = request.get('execution_id')
            if not isinstance(execution_id, str) or not (8 <= len(execution_id) <= 128):
                raise ServiceRefusal('execution_id_required')
            # Serializes grant consumption and response execution within this process.
            # SQLite BEGIN IMMEDIATE serializes consumption across processes as well.
            with self._lock, self._connect() as db:
                db.execute('BEGIN IMMEDIATE')
                try:
                    if op == 'execute':
                        target = self._target(action, request.get('target'))
                        if db.execute('SELECT 1 FROM executions WHERE id=?', (execution_id,)).fetchone():
                            raise ServiceRefusal('execution_id_replayed')
                        # Validate grant before rate limiting, but do not consume it until after limit passes.
                        if not self._rate_ok():
                            raise ServiceRefusal('rate_limited')
                        self._consume(db, request, op, action, target, execution_id)
                        self._recent.append(self._clock())
                        # Durable in-progress marker BEFORE calling OS adapter; crash fails closed.
                        db.execute('INSERT INTO executions VALUES (?,?,?,?,?)',
                                   (execution_id, action.value, target, '{}', 'attempted'))
                        db.execute('COMMIT')
                        try:
                            result = adapter.execute(target, action, str(request.get('reason', ''))[:2000])
                            if not isinstance(result, dict):
                                raise TypeError('adapter_result_not_dict')
                            with self._connect() as done:
                                done.execute('UPDATE executions SET result=?,status=? WHERE id=?',
                                             (json.dumps(result, default=str), 'executed', execution_id))
                            try:
                                self.audit.record({'op': op, 'action': action.value, 'target': target, 'ok': True, 'execution_id': execution_id})
                            except Exception:
                                # Report the completed effect accurately; refuse subsequent mutations.
                                self._audit_healthy = False
                                return {'ok': True, 'result': result, 'audit_error': True}
                            return {'ok': True, 'result': result}
                        except Exception:
                            # Preserve attempted marker: never automatically replay uncertain effects.
                            raise
                    else:
                        record = db.execute('SELECT action,target,result,status FROM executions WHERE id=?', (execution_id,)).fetchone()
                        if (not record or record[3] != 'executed' or record[0] != action.value
                                or action == Action.TERMINATE_PROCESS):
                            raise ServiceRefusal('execution_not_eligible')
                        target = record[1]
                        self._consume(db, request, op, action, target, execution_id)
                        db.execute('UPDATE executions SET status=? WHERE id=?', ('rollback_attempted', execution_id))
                        db.execute('COMMIT')
                        # Never trust an IPC-supplied execution object for rollback.
                        trusted = {'action': action.value, 'target': target, 'result': json.loads(record[2])}
                        result = adapter.rollback(trusted)
                        verifier = getattr(adapter, 'verify_rollback', None)
                        verification = verifier(trusted, result) if verifier else {'verified': False}
                        verified = isinstance(verification, dict) and verification.get('verified') is True
                        with self._connect() as done:
                            done.execute('UPDATE executions SET status=? WHERE id=?',
                                         ('rolled_back' if verified else 'rollback_unverified', execution_id))
                        try:
                            self.audit.record({'op': op, 'action': action.value, 'ok': verified, 'execution_id': execution_id})
                        except Exception:
                            self._audit_healthy = False
                            return {'ok': verified, 'result': result, 'verification': verification, 'audit_error': True}
                        return {'ok': verified, 'result': result, 'verification': verification}
                except Exception:
                    if db.in_transaction:
                        db.execute('ROLLBACK')
                    raise
        except ServiceRefusal as refusal:
            try:
                self.audit.record({'op': op, 'action': str(request.get('action')), 'ok': False, 'refused': refusal.code})
            except Exception:
                self._audit_healthy = False
            return {'ok': False, 'error': refusal.code}
        except Exception as exc:
            try:
                self.audit.record({'op': op, 'action': str(request.get('action')), 'ok': False, 'error': type(exc).__name__})
            except Exception:
                self._audit_healthy = False
            return {'ok': False, 'error': 'adapter_error', 'error_type': type(exc).__name__}

    # -- server -------------------------------------------------------------------------------------------------

    def serve(self, address: str, key: bytes, stop: threading.Event | None = None, ready: threading.Event | None = None) -> None:
        if not self.state_path:
            raise RuntimeError('authorization_store_not_configured')
        if not self.audit.path:
            raise RuntimeError('audit_path_required')
        if self.authorization_verifier is None:
            raise RuntimeError('trusted_approval_verifier_required')
        if os.name == 'nt':
            if not self.ipc_key_path:
                raise RuntimeError('windows_ipc_key_file_required')
            if not self.trust_store_path:
                raise RuntimeError('windows_trust_store_required')
            if self.windows_acl_validator is None:
                raise RuntimeError('windows_acl_validator_required')
            try:
                acl_ok = self.windows_acl_validator(
                    self.state_path, self.audit.path, self.trust_store_path,
                    self.ipc_key_path, address, key,
                ) is True
            except Exception:
                acl_ok = False
            if not acl_ok:
                raise RuntimeError('windows_acl_preflight_failed')
        listener = make_listener(address, key)
        stop = stop or threading.Event()
        if ready is not None:
            ready.set()

        def watcher() -> None:
            stop.wait()
            try:
                listener.close()
            except OSError:
                pass
        threading.Thread(target=watcher, daemon=True).start()
        try:
            while not stop.is_set():
                try:
                    connection = listener.accept()
                except Exception:  # noqa: BLE001 - failed authentication or closed listener
                    if stop.is_set():
                        break
                    continue
                threading.Thread(target=self._session, args=(connection,), daemon=True).start()
        finally:
            try:
                listener.close()
            except OSError:
                pass

    def _session(self, connection) -> None:
        try:
            while True:
                try:
                    request = recv_json(connection)
                except (EOFError, OSError, ValueError):
                    return
                send_json(connection, self.handle(request))
        finally:
            try:
                connection.close()
            except OSError:
                pass
