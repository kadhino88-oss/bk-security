"""Shared helpers for POSIX response adapters: argv-only command execution and result checks."""
from __future__ import annotations

import subprocess
from collections.abc import Callable, Sequence
from typing import Any

from ..policy.engine import Action
from ..policy.response import validate_target

Runner = Callable[[Sequence[str], "str | None"], "subprocess.CompletedProcess[str]"]


class ResponseAdapterError(RuntimeError):
    pass


def run_command(argv: Sequence[str], input_text: str | None = None) -> "subprocess.CompletedProcess[str]":
    """Run a program with an argument vector (never a shell); stdin carries any generated rule text."""
    try:
        return subprocess.run(list(argv), input=input_text, capture_output=True, text=True, timeout=20, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ResponseAdapterError(str(exc)) from exc


def require_success(result: "subprocess.CompletedProcess[str]", message: str) -> None:
    if result.returncode != 0:
        raise ResponseAdapterError(result.stderr.strip()[:1000] or message)


def validated_ip(target: str) -> str:
    try:
        return validate_target(Action.BLOCK, target)
    except ValueError as exc:
        raise ResponseAdapterError(str(exc)) from exc


def verdict(observed: str, expected: str, **extra: Any) -> dict[str, Any]:
    return {"verified": observed == expected, "observed": observed, "expected": expected, **extra}
