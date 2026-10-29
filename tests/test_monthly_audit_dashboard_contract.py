from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_monthly_audit_is_integrated_with_the_authenticated_dashboard():
    source = (ROOT / "dashboard" / "src" / "main.jsx").read_text(encoding="utf-8")
    helper = (ROOT / "dashboard" / "src" / "monthly-audit.js").read_text(encoding="utf-8")
    assert "<MonthlyAuditReport token={token} />" in source
    assert "loadMonthlyAudit({ api: API, token, month })" in source
    assert "Deployment scope: {formatDeploymentScope(report.scope)}" in source
    assert "`${api}/api/v1/audit/monthly?month=${encodeURIComponent(month)}`" in helper
    assert "Authorization: `Bearer ${token}`" in helper
    assert "database binding only; host and region not attested" in helper


def test_monthly_report_does_not_claim_avoided_attacks_or_verified_threat_remediation():
    source = (ROOT / "dashboard" / "src" / "main.jsx").read_text(encoding="utf-8")
    backend = (ROOT / "bk_security" / "monthly_audit.py").read_text(encoding="utf-8")
    assert "Attacks avoided:</b> not measured" in source
    assert "not_tracked_as_verified_in_v1" in backend
    assert "retained local records only" in source
