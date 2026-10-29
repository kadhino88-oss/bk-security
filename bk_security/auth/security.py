from __future__ import annotations
import base64, hashlib, hmac, json, os, secrets, time
from dataclasses import dataclass
from ..deployment import DeploymentContext

@dataclass(frozen=True)
class Principal:
    username: str
    role: str
    token_id: str | None = None
    expires_at: int | None = None

class AuthError(Exception): pass

def _secret() -> bytes:
    secret = os.getenv('BK_SECURITY_AUTH_SECRET', 'CHANGE-ME-BK-SECURITY')
    encoded = secret.encode()
    if os.getenv('BK_SECURITY_ENV', '').strip().lower() == 'production':
        if secret == 'CHANGE-ME-BK-SECURITY':
            raise RuntimeError('BK_SECURITY_AUTH_SECRET must be configured in production')
        if len(encoded) < 32:
            raise RuntimeError('BK_SECURITY_AUTH_SECRET must contain at least 32 UTF-8 bytes in production')
    return encoded

def _deployment_context(context: DeploymentContext | None) -> DeploymentContext:
    configured = DeploymentContext.from_environment(os.environ)
    if (
        context is not None
        and configured.profile == "dedicated_customer"
        and context != configured
    ):
        raise ValueError("Authentication context cannot override the process's dedicated deployment identity.")
    return context if context is not None else configured

def issue_token(
    username: str,
    role: str,
    ttl: int = 3600,
    *,
    deployment_context: DeploymentContext | None = None,
) -> str:
    payload = {
        'sub': username,
        'role': role,
        'exp': int(time.time()) + ttl,
        'jti': secrets.token_urlsafe(24),
    }
    context = _deployment_context(deployment_context)
    if context.profile == "dedicated_customer":
        payload['customer_ref'] = context.customer_ref
        payload['deployment_id'] = context.deployment_id
    raw = base64.urlsafe_b64encode(json.dumps(payload, separators=(',', ':')).encode()).decode().rstrip('=')
    sig = hmac.new(_secret(), raw.encode(), hashlib.sha256).hexdigest()
    return f'{raw}.{sig}'

def verify_token(
    token: str,
    *,
    deployment_context: DeploymentContext | None = None,
) -> Principal:
    try:
        raw, sig = token.split('.', 1)
        expected = hmac.new(_secret(), raw.encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(sig, expected): raise AuthError('invalid token')
        payload = json.loads(base64.urlsafe_b64decode(raw + '=' * (-len(raw) % 4)))
        expires_at = int(payload['exp'])
        if expires_at <= int(time.time()): raise AuthError('expired token')
        token_id = payload.get('jti')
        if token_id is not None and (
            not isinstance(token_id, str) or not 16 <= len(token_id) <= 128
        ):
            raise AuthError('invalid token')
        context = _deployment_context(deployment_context)
        scoped = 'customer_ref' in payload or 'deployment_id' in payload
        if context.profile == "dedicated_customer":
            if (
                payload.get('customer_ref') != context.customer_ref
                or payload.get('deployment_id') != context.deployment_id
            ):
                raise AuthError('token deployment scope mismatch')
        elif scoped:
            raise AuthError('dedicated deployment token cannot be used in local V1')
        return Principal(
            str(payload['sub']), str(payload['role']), token_id, expires_at,
        )
    except (ValueError, KeyError, json.JSONDecodeError, TypeError):
        raise AuthError('invalid token')
