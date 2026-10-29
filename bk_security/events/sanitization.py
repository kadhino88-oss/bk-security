from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any

REDACTED = "<redacted>"

_SENSITIVE_SUFFIXES = (
    "password", "passwd", "passphrase", "pwd", "secret", "secrets", "token",
    "apikey", "accesskey", "privatekey", "credential", "credentials",
    "authorization", "authheader", "authvalue", "cookie", "cookies", "sessionid",
    "cardnumber", "paymentcard", "cvv", "cvc", "iban", "bankaccount",
    "routingnumber", "socialsecuritynumber", "ssn", "jwt", "otp", "salt",
    "sessionkey", "signingkey", "encryptionkey", "authkey", "clientkey", "cardpan",
)
_SENSITIVE_KEY_MARKERS = (
    "password", "passwd", "passphrase", "secret", "privatekey", "authorization",
    "authheader", "authvalue", "credential", "cookie", "salt", "sessionkey",
    "signingkey", "encryptionkey", "authkey", "clientkey", "accesstoken",
    "refreshtoken", "idtoken", "sessiontoken", "bearertoken", "tokenvalue",
)
_SENSITIVE_WORD = (
    r"password|passwd|passphrase|pwd|client[_-]?secret|secret|secrets|"
    r"(?:access|refresh|id|session|bearer)[_-]?token|session[_-]?(?:id|key)|"
    r"signing[_-]?key|encryption[_-]?key|auth[_-]?key|client[_-]?key|token|api[_-]?key|"
    r"access[_-]?key|private[_-]?key|credential|credentials|authorization|"
    r"auth(?:[_-]?(?:token|header|value))?|proxy[_-]?authorization|cookie|cookies|"
    r"card[_-]?(?:number|pan)|payment[_-]?card|cvv|cvc|iban|bank[_-]?account|"
    r"routing[_-]?number|social[_-]?security[_-]?number|ssn|jwt|otp|pan"
)
_SENSITIVE_ASSIGNMENT = re.compile(
    rf"(?i)(?<![a-z0-9_?&])(?:{_SENSITIVE_WORD})(?![a-z0-9])\s*[:=]\s*"
    r"(?:\"[^\"]*\"|'[^']*'|[^\s,;&]+)"
)
_SENSITIVE_QUERY = re.compile(
    rf"(?i)([?&](?:{_SENSITIVE_WORD})=)[^&#\s]*"
)
_BEARER_CREDENTIAL = re.compile(r"(?i)(\bbearer\s+)[a-z0-9._~+/-]+=*")
_PRIVATE_KEY_BLOCK = re.compile(
    r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----",
    re.DOTALL | re.IGNORECASE,
)
_SECRET_ARGUMENT = re.compile(
    r"^(--?|/)([a-z0-9_-]*(?:password|passwd|passphrase|pwd|secret|token|"
    r"api[-_]?key|access[-_]?key|private[-_]?key|session[-_]?key|signing[-_]?key|"
    r"encryption[-_]?key|auth[-_]?key|client[-_]?key|authorization|cookie|credential)"
    r"[a-z0-9_-]*)(?:[=:](.*))?$",
    re.IGNORECASE,
)
_SECRET_ARGUMENT_WITH_VALUE = re.compile(
    r"(?i)((?:--?|/)[a-z0-9_-]*(?:password|passwd|passphrase|pwd|secret|token|"
    r"api[-_]?key|access[-_]?key|private[-_]?key|session[-_]?key|signing[-_]?key|"
    r"encryption[-_]?key|auth[-_]?key|client[-_]?key|authorization|cookie|credential)"
    r"[a-z0-9_-]*\s+)(?:\"[^\"]*\"|'[^']*'|[^\s,;]+)"
)
_COMMAND_LINE_FIELDS = {"cmdline", "commandline", "argv"}
_TEXT_MARKER = re.compile(
    r"(?i)password|passwd|passphrase|pwd|secret|token|key|credential|authoriz|"
    r"auth|bearer|cookie|card|cvv|cvc|iban|bank|routing|ssn|jwt|otp|session|"
    r"salt|privatekey|signingkey|encryptionkey|"
    r"(?<![a-z0-9])pan(?![a-z0-9])|-----begin"
)
_POSSIBLE_ARGUMENT = re.compile(r"(?:^|\s)(?:--?|/)[a-z0-9_-]+", re.IGNORECASE)


def _redact_text(value: str) -> str:
    lowered = value.lower()
    if _TEXT_MARKER.search(lowered) is None:
        return value
    if "-----begin" in lowered:
        value = _PRIVATE_KEY_BLOCK.sub(REDACTED, value)
    if "bearer" in lowered:
        value = _BEARER_CREDENTIAL.sub(rf"\1{REDACTED}", value)
    if "?" in value or "&" in value:
        value = _SENSITIVE_QUERY.sub(rf"\1{REDACTED}", value)
    value = _SENSITIVE_ASSIGNMENT.sub(REDACTED, value)
    if _POSSIBLE_ARGUMENT.search(value):
        value = _SECRET_ARGUMENT_WITH_VALUE.sub(rf"\1{REDACTED}", value)
    return value


def sanitize_command_line(value: Any) -> list[str] | None:
    """Bound process arguments and redact common secret-bearing flags and values."""
    if value is None:
        return None
    arguments = [str(item) for item in value] if isinstance(value, (tuple, list)) else [str(value)]
    safe: list[str] = []
    redact_next = False
    for argument in arguments[:128]:
        if redact_next:
            safe.append(REDACTED)
            redact_next = False
            continue
        match = _SECRET_ARGUMENT.match(argument)
        if match:
            safe.append(f"{match.group(1)}{match.group(2)}={REDACTED}")
            redact_next = match.group(3) is None
        else:
            safe.append(_redact_text(argument)[:512])
        if sum(len(item) for item in safe) >= 4096:
            break
    return safe


def sanitize_sensitive_payload(value: Any) -> Any:
    """Return a copy with credential-shaped fields and common inline tokens removed."""
    if isinstance(value, Mapping):
        sanitized = {}
        for key, item in value.items():
            normalized = re.sub(r"[^a-z0-9]", "", str(key).lower())
            if (
                normalized == "pan" or normalized == "key"
                or normalized.endswith(_SENSITIVE_SUFFIXES)
                or any(marker in normalized for marker in _SENSITIVE_KEY_MARKERS)
            ):
                sanitized[key] = REDACTED
            elif normalized in _COMMAND_LINE_FIELDS:
                sanitized[key] = sanitize_command_line(item)
            else:
                sanitized[key] = sanitize_sensitive_payload(item)
        return sanitized
    if isinstance(value, list):
        return [sanitize_sensitive_payload(item) for item in value]
    if isinstance(value, tuple):
        return tuple(sanitize_sensitive_payload(item) for item in value)
    if isinstance(value, str):
        return _redact_text(value)
    return value


def sanitize_security_event(event):
    """Scrub event payloads before detection, investigation, response, or storage."""
    event.data = sanitize_sensitive_payload(event.data)
    event.process = sanitize_sensitive_payload(event.process)
    event.network = sanitize_sensitive_payload(event.network)
    event.enrichment = sanitize_sensitive_payload(event.enrichment)
    return event
