from __future__ import annotations

from collections import OrderedDict, deque
import threading
import time
from typing import Any, Awaitable, Callable


class SlidingWindowRateLimiter:
    """Small process-local limiter with bounded key and timestamp memory."""

    def __init__(self, limit: int, window_seconds: float, max_keys: int = 4096):
        self.limit = max(1, int(limit))
        self.window_seconds = max(0.1, float(window_seconds))
        self.max_keys = max(1, int(max_keys))
        self._hits: OrderedDict[str, deque[float]] = OrderedDict()
        self._lock = threading.Lock()

    def allow(self, key: str) -> tuple[bool, float]:
        now = time.monotonic()
        threshold = now - self.window_seconds
        normalized = str(key)[:256] or "unknown"
        with self._lock:
            hits = self._hits.setdefault(normalized, deque())
            while hits and hits[0] <= threshold:
                hits.popleft()
            self._hits.move_to_end(normalized)
            if len(hits) >= self.limit:
                return False, max(0.0, self.window_seconds - (now - hits[0]))
            hits.append(now)
            self._evict(now)
            return True, 0.0

    def reset(self, key: str) -> None:
        with self._lock:
            self._hits.pop(str(key)[:256] or "unknown", None)

    def _evict(self, now: float) -> None:
        threshold = now - self.window_seconds
        for key in list(self._hits):
            hits = self._hits[key]
            while hits and hits[0] <= threshold:
                hits.popleft()
            if not hits:
                self._hits.pop(key, None)
        while len(self._hits) > self.max_keys:
            self._hits.popitem(last=False)

    @property
    def tracked_keys(self) -> int:
        with self._lock:
            return len(self._hits)


class RequestSizeLimitMiddleware:
    """Reject oversized HTTP bodies before Pydantic or routes parse them."""

    def __init__(self, app, max_bytes: int = 1_048_576):
        self.app = app
        self.max_bytes = max(1024, int(max_bytes))

    async def __call__(self, scope: dict[str, Any], receive: Callable, send: Callable) -> None:
        if scope.get("type") != "http" or scope.get("method") not in {"POST", "PUT", "PATCH"}:
            await self.app(scope, receive, send)
            return

        headers = {key.lower(): value for key, value in scope.get("headers", [])}
        content_length = headers.get(b"content-length")
        if content_length:
            try:
                too_large = int(content_length) > self.max_bytes
            except ValueError:
                too_large = True
            if too_large:
                await self._reject(send)
                return

        body = bytearray()
        while True:
            message = await receive()
            if message["type"] == "http.disconnect":
                return
            body.extend(message.get("body", b""))
            if len(body) > self.max_bytes:
                await self._reject(send)
                return
            if not message.get("more_body", False):
                break

        consumed = False

        async def replay_body() -> dict[str, Any]:
            nonlocal consumed
            if not consumed:
                consumed = True
                return {"type": "http.request", "body": bytes(body), "more_body": False}
            return {"type": "http.disconnect"}

        await self.app(scope, replay_body, send)

    async def _reject(self, send: Callable) -> None:
        body = b'{"detail":"Request body too large"}'
        await send({
            "type": "http.response.start",
            "status": 413,
            "headers": [
                (b"content-type", b"application/json"),
                (b"content-length", str(len(body)).encode("ascii")),
                (b"connection", b"close"),
            ],
        })
        await send({"type": "http.response.body", "body": body, "more_body": False})


class SecurityHeadersMiddleware:
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope: dict[str, Any], receive: Callable, send: Callable) -> None:
        async def send_with_security_headers(message: dict[str, Any]) -> None:
            if message["type"] == "http.response.start":
                headers = list(message.get("headers", []))
                existing = {key.lower() for key, _ in headers}
                security_headers = (
                    (b"x-content-type-options", b"nosniff"),
                    (b"x-frame-options", b"DENY"),
                    (b"referrer-policy", b"no-referrer"),
                    (b"cross-origin-resource-policy", b"same-origin"),
                    (b"x-permitted-cross-domain-policies", b"none"),
                    (b"content-security-policy", b"default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'"),
                )
                headers.extend((key, value) for key, value in security_headers if key not in existing)
                message["headers"] = headers
            await send(message)

        await self.app(scope, receive, send_with_security_headers)
