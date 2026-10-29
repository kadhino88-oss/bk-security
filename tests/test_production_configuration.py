from bk_security.configuration import (
    ROLE_PASSWORDS, effective_capture_mode, production_configuration_errors,
)
from bk_security.auth.security import _secret
import pytest


def production_environment():
    env = {
        "BK_SECURITY_ENV": "production",
        "BK_SECURITY_AUTH_SECRET": "authentication-secret-with-at-least-32-bytes",
        "BK_SECURITY_CORS_ORIGINS": "",
        "BK_SECURITY_CAPTURE_MODE": "stopped",
        "BK_SECURITY_CAPTURE_INTERFACE": "",
        "BK_SECURITY_HOST": "127.0.0.1",
        "BK_SECURITY_WINDOWS_RESPONSE": "0",
    }
    env.update({name: f"role-password-{index}-long" for index, name in enumerate(ROLE_PASSWORDS)})
    return env


def test_complete_desktop_production_configuration_is_accepted():
    assert production_configuration_errors(production_environment()) == []


def test_production_never_starts_simulation_capture():
    env = production_environment()
    env["BK_SECURITY_CAPTURE_MODE"] = "simulation"

    assert effective_capture_mode(env) == "stopped"
    assert any("simulation is disabled" in error for error in production_configuration_errors(env))


def test_development_can_still_use_explicit_simulation_for_tests():
    assert effective_capture_mode({"BK_SECURITY_CAPTURE_MODE": "simulation"}) == "simulation"


def test_incomplete_or_weak_production_values_are_rejected_without_echoing_them():
    env = production_environment()
    env.pop("BK_SECURITY_CORS_ORIGINS")
    env["BK_SECURITY_AUTH_SECRET"] = "private-short-value"
    env[ROLE_PASSWORDS[0]] = "short"
    env[ROLE_PASSWORDS[1]] = env[ROLE_PASSWORDS[2]]
    errors = production_configuration_errors(env)
    assert any("CORS_ORIGINS" in error for error in errors)
    assert any("32 UTF-8 bytes" in error for error in errors)
    assert any("12 UTF-8 bytes" in error for error in errors)
    assert any("unique" in error for error in errors)
    assert all("private-short-value" not in error for error in errors)


def test_live_capture_requires_an_explicit_interface_and_loopback_api_binding():
    env = production_environment()
    env["BK_SECURITY_CAPTURE_MODE"] = "live"
    errors = production_configuration_errors(env)
    assert any("explicitly selected" in error for error in errors)
    env["BK_SECURITY_CAPTURE_INTERFACE"] = r"\Device\NPF_Loopback"
    env["BK_SECURITY_HOST"] = "0.0.0.0"
    errors = production_configuration_errors(env)
    assert not any("explicitly selected" in error for error in errors)
    assert any("loopback" in error for error in errors)


def test_production_rejects_wildcard_cors_and_enabled_windows_responses():
    env = production_environment()
    env["BK_SECURITY_CORS_ORIGINS"] = "*"
    env["BK_SECURITY_WINDOWS_RESPONSE"] = "1"
    errors = production_configuration_errors(env)
    assert any("Wildcard CORS" in error for error in errors)
    assert any("must remain 0" in error for error in errors)


def test_development_configuration_does_not_require_production_credentials():
    assert production_configuration_errors({"BK_SECURITY_ENV": "development"}) == []


def test_production_rejects_low_entropy_passwords_and_authentication_secret():
    env = production_environment()
    env[ROLE_PASSWORDS[0]] = "x" * 20
    env["BK_SECURITY_AUTH_SECRET"] = "s" * 48
    errors = production_configuration_errors(env)
    assert any("repeated-character" in error for error in errors)
    assert any("32 UTF-8 bytes" in error for error in errors)


def test_dedicated_data_plane_requires_valid_customer_deployment_identity():
    env = production_environment()
    env["BK_SECURITY_DEPLOYMENT_PROFILE"] = "dedicated_customer"
    errors = production_configuration_errors(env)
    assert any("missing required identity settings" in error for error in errors)

    env.update({
        "BK_SECURITY_CUSTOMER_REF": "customer-42",
        "BK_SECURITY_DEPLOYMENT_ID": "not-a-uuid",
        "BK_SECURITY_REGION": "eu-ch",
    })
    errors = production_configuration_errors(env)
    assert any("UUID deployment identifier" in error for error in errors)

    env["BK_SECURITY_DEPLOYMENT_ID"] = "03a449dd-6c62-4f88-986d-1f94e7423214"
    assert production_configuration_errors(env) == []


def test_auth_secret_weakness_check_cannot_be_bypassed_with_environment_case(monkeypatch):
    monkeypatch.setenv("BK_SECURITY_ENV", "Production")
    monkeypatch.setenv("BK_SECURITY_AUTH_SECRET", "short")
    with pytest.raises(RuntimeError, match="32 UTF-8 bytes"):
        _secret()
