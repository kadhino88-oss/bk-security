from types import SimpleNamespace
from subprocess import CompletedProcess

import pytest

import bk_security.core as core_module
import bk_security.policy.windows_adapters as adapters
from bk_security.policy.engine import Action
from bk_security.policy.response import validate_target


def test_target_validation_rejects_malformed_and_dangerous_values():
    assert validate_target(Action.BLOCK, "203.0.113.1") == "203.0.113.1"
    with pytest.raises(ValueError):
        validate_target(Action.BLOCK, "127.0.0.1")
    with pytest.raises(ValueError):
        validate_target(Action.BLOCK, "10.0.0.1; Remove-NetFirewallRule")
    assert validate_target(Action.TERMINATE_PROCESS, "123") == "123"
    for pid in ("0", "4", "-1", "2147483648", "1;Stop-Process"):
        with pytest.raises(ValueError):
            validate_target(Action.TERMINATE_PROCESS, pid)


def test_firewall_adapter_uses_bounded_arguments_and_verifies_state(monkeypatch):
    calls = []

    def fake_run(script, *args):
        calls.append((script, args))
        return CompletedProcess([], 0, "present\n", "")

    monkeypatch.setattr(adapters, "_run_ps", fake_run)
    adapter = adapters.WindowsFirewallBlockAdapter()
    result = adapter.execute("203.0.113.5", Action.BLOCK, "test")
    assert result["rule"].startswith("BK-Security-")
    assert result["target"] == "203.0.113.5"
    assert calls[0][1] == (result["rule"], "203.0.113.5")
    verification = adapter.verify("203.0.113.5", Action.BLOCK, result)
    assert verification["verified"] is True


def test_windows_adapters_validate_before_any_command(monkeypatch):
    monkeypatch.setattr(adapters, "_run_ps", lambda *_: pytest.fail("invalid target reached PowerShell"))
    with pytest.raises(adapters.WindowsResponseError):
        adapters.WindowsFirewallBlockAdapter().execute("invalid", Action.BLOCK, "test")
    with pytest.raises(adapters.WindowsResponseError):
        adapters.WindowsProcessTerminateAdapter().execute("4", Action.TERMINATE_PROCESS, "test")


def test_isolation_adapter_refuses_remote_host_and_uses_only_local_scope(monkeypatch):
    monkeypatch.setattr(adapters.socket, "gethostname", lambda: "bk-test-host")
    monkeypatch.setattr(adapters, "_run_ps", lambda *_: pytest.fail("remote target reached PowerShell"))
    with pytest.raises(adapters.WindowsResponseError, match="local Windows host"):
        adapters.WindowsIsolationAdapter().execute("remote-host", Action.ISOLATE, "test")


def test_windows_commands_are_off_by_default_even_on_windows(monkeypatch):
    monkeypatch.setattr(core_module, "os", SimpleNamespace(name="nt", getenv=lambda _name, default="0": default))
    core = core_module.SecurityCore()
    assert core.response.adapters == {}


def test_windows_response_wiring_uses_remote_service_not_in_process_adapters(monkeypatch):
    from bk_security.services.response_client import RemoteResponseAdapter

    monkeypatch.setattr(core_module, "os", SimpleNamespace(name="nt", getenv=lambda name, default="0": "1" if name == "BK_SECURITY_WINDOWS_RESPONSE" else default))
    monkeypatch.setenv("BK_SECURITY_RESPONSE_KEY", "k" * 40)
    adapters = core_module._response_adapters()
    assert set(adapters) == {Action.BLOCK, Action.ISOLATE, Action.TERMINATE_PROCESS}
    assert all(isinstance(adapter, RemoteResponseAdapter) for adapter in adapters.values())


def test_generic_os_response_flag_cannot_bypass_windows_service(monkeypatch):
    from bk_security.services.response_client import RemoteResponseAdapter

    monkeypatch.setattr(core_module, "os", SimpleNamespace(name="nt", getenv=lambda name, default="0": "1" if name == "BK_SECURITY_OS_RESPONSE" else default))
    monkeypatch.setenv("BK_SECURITY_RESPONSE_KEY", "k" * 40)
    adapters = core_module._response_adapters()
    assert all(isinstance(adapter, RemoteResponseAdapter) for adapter in adapters.values())
