from __future__ import annotations

from scripts import validate_packaged_backend


def test_packaged_backend_http_probe_allows_cold_start_latency(monkeypatch):
    observed = {}

    class Response:
        status = 200

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def read(self):
            return b"{}"

    def fake_urlopen(request, *, timeout):
        observed["url"] = request.full_url
        observed["timeout"] = timeout
        return Response()

    monkeypatch.setattr(validate_packaged_backend, "urlopen", fake_urlopen)

    assert validate_packaged_backend._request("http://127.0.0.1/health") == (200, b"{}")
    assert observed == {
        "url": "http://127.0.0.1/health",
        "timeout": validate_packaged_backend.HTTP_REQUEST_TIMEOUT_SECONDS,
    }
    assert observed["timeout"] >= 10
