"""Offline tooling for provisioning and signing dual-control response proofs.

Run approver and responder commands under their separate Windows identities.
Neither private key belongs in the API process or its environment.
"""
from __future__ import annotations

import argparse
import getpass
import json
import secrets
import sys
import time
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ..policy.engine import Action
from ..policy.response import validate_target
from .approval import complete_approval_envelope, make_approval_envelope


def _private_key(path: Path) -> Ed25519PrivateKey:
    password = getpass.getpass("Private key passphrase: ").encode("utf-8")
    key = serialization.load_pem_private_key(path.read_bytes(), password=password)
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError("The private key must be Ed25519.")
    return key


def _write_new(path: Path, contents: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("xb") as handle:
        handle.write(contents)


def _generate(args) -> None:
    private_path, public_path = Path(args.private_key), Path(args.public_entry)
    if private_path.resolve() == public_path.resolve() or private_path.exists() or public_path.exists():
        raise FileExistsError("Choose two new, distinct output paths; existing key files are never overwritten.")
    password = getpass.getpass("New private key passphrase: ")
    if len(password) < 12:
        raise ValueError("Use a passphrase with at least 12 characters.")
    if password != getpass.getpass("Repeat private key passphrase: "):
        raise ValueError("Passphrases do not match.")
    private_key = Ed25519PrivateKey.generate()
    private_pem = private_key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.BestAvailableEncryption(password.encode("utf-8")),
    )
    public_pem = private_key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")
    entry = {"key_id": args.key_id, "role": args.role, "public_key_pem": public_pem}
    _write_new(private_path, private_pem)
    try:
        _write_new(public_path, (json.dumps(entry, indent=2) + "\n").encode("utf-8"))
    except Exception:
        private_path.unlink(missing_ok=True)
        raise
    print(f"Created encrypted private key and public trust entry for {args.key_id}.")


def _approve(args) -> None:
    ttl = args.expires_in
    if not 1 <= ttl <= 300:
        raise ValueError("Approval expiry must be between 1 and 300 seconds.")
    if not 8 <= len(args.execution_id) <= 128:
        raise ValueError("Execution ID length must be between 8 and 128 characters.")
    action = Action(args.action)
    target = validate_target(action, args.target)
    issued_at = time.time()
    proof = make_approval_envelope(
        operation=args.operation, action=action, target=target,
        execution_id=args.execution_id, approver_key_id=args.approver_key_id,
        executor_key_id=args.executor_key_id, approver_private_key=_private_key(Path(args.private_key)),
        issued_at=issued_at, expires_at=issued_at + ttl, nonce=secrets.token_urlsafe(24),
    )
    _write_new(Path(args.output), (json.dumps(proof, indent=2) + "\n").encode("utf-8"))
    print("Wrote approver-signed scope. A separate responder must sign it before execution.")


def _sign_execution(args) -> None:
    envelope = json.loads(Path(args.approval_file).read_text(encoding="utf-8"))
    if envelope.get("executor_key_id") != args.executor_key_id:
        raise ValueError("The approval names a different responder key.")
    proof = complete_approval_envelope(envelope, executor_private_key=_private_key(Path(args.private_key)))
    _write_new(Path(args.output), (json.dumps(proof, indent=2) + "\n").encode("utf-8"))
    print("Wrote dual-signed proof. It is scoped and expires; it does not execute the response by itself.")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="bk-security-approval")
    commands = parser.add_subparsers(dest="command", required=True)

    keygen = commands.add_parser("generate-identity", help="Create an encrypted Ed25519 identity key")
    keygen.add_argument("--key-id", required=True)
    keygen.add_argument("--role", choices=("approver", "responder"), required=True)
    keygen.add_argument("--private-key", required=True)
    keygen.add_argument("--public-entry", required=True)
    keygen.set_defaults(run=_generate)

    approve = commands.add_parser("approve", help="Sign a single response scope as approver")
    approve.add_argument("--operation", choices=("execute", "rollback"), required=True)
    approve.add_argument("--action", choices=tuple(action.value for action in Action), required=True)
    approve.add_argument("--target", required=True)
    approve.add_argument("--execution-id", required=True)
    approve.add_argument("--approver-key-id", required=True)
    approve.add_argument("--executor-key-id", required=True)
    approve.add_argument("--private-key", required=True)
    approve.add_argument("--expires-in", type=int, default=300)
    approve.add_argument("--output", required=True)
    approve.set_defaults(run=_approve)

    execute = commands.add_parser("sign-execution", help="Add the distinct responder signature")
    execute.add_argument("--approval-file", required=True)
    execute.add_argument("--executor-key-id", required=True)
    execute.add_argument("--private-key", required=True)
    execute.add_argument("--output", required=True)
    execute.set_defaults(run=_sign_execution)

    args = parser.parse_args(argv)
    try:
        args.run(args)
        return 0
    except Exception as exc:  # safe CLI failure with no key material in the diagnostic
        print(f"Error: {type(exc).__name__}: {str(exc)}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
