from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_windows_production_setup_does_not_embed_secrets():
    script = (ROOT / 'scripts' / 'configure_windows_production.ps1').read_text(encoding='utf-8')
    assert 'Read-Host' in script
    assert 'SetEnvironmentVariable' in script
    assert 'BK_SECURITY_AUTH_SECRET' in script
    assert 'BK_SECURITY_ADMIN_PASSWORD' in script
    assert 'BK_SECURITY_ANALYST_PASSWORD' in script
    assert 'BK_SECURITY_VIEWER_PASSWORD' in script
    assert 'admin-dev-only' not in script
    assert 'CHANGE-ME' not in script
