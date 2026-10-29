from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from subprocess import CompletedProcess
from types import SimpleNamespace

import pytest

import bk_security.core as core_module
from bk_security.configuration import production_configuration_errors
from bk_security.platforms import current_provider, provider_for
from bk_security.platforms.adapter_support import ResponseAdapterError
from bk_security.platforms.linux_adapters import NftBlockAdapter, NftIsolationAdapter
from bk_security.platforms.macos_adapters import PfBlockAdapter, PfIsolationAdapter
from bk_security.platforms.process_adapter import ProcessTerminateAdapter
from bk_security.platforms.providers import LinuxProvider, MacOSProvider, has_capability
from bk_security.policy.engine import Action

ADAPTER_METHODS = ("execute", "verify", "rollback", "verify_rollback")
RUNTIME_KEYS = {"platform", "is_windows", "elevated", "npcap_present", "npcap_path", "capture_backend",
                "scapy_available", "capture_interfaces", "capture_devices", "loopback_interface",
                "loopback_available", "live_capture_available", "reasons"}


# ---- provider selection and contract -------------------------------------------------------------------------

@pytest.mark.parametrize("system,name", [("Windows", "windows"), ("Linux", "linux"), ("Darwin", "macos"),
                                         ("FreeBSD", "freebsd")])
def test_provider_selection_by_operating_system(system, name):
    assert provider_for(system).name == name


def test_unsupported_platform_is_not_ready_and_has_no_adapters():
    provider = provider_for("Plan9")
    assert provider.capture_prerequisites() and provider.response_adapters() == {}
    assert provider.capture_runtime()["live_capture_available"] is False


@pytest.mark.parametrize("system", ["Windows", "Linux", "Darwin"])
def test_every_provider_honours_the_same_contract(system):
    provider = provider_for(system)
    assert isinstance(provider.loopback_interface(), str) and provider.loopback_interface()
    assert provider.response_validated() is False  # nothing is claimed validated without a recorded lab run
    adapters = provider.response_adapters()
    assert set(adapters) == {Action.BLOCK, Action.ISOLATE, Action.TERMINATE_PROCESS}
    for adapter in adapters.values():
        assert all(callable(getattr(adapter, method, None)) for method in ADAPTER_METHODS)


def test_current_provider_reports_the_host_runtime_shape():
    runtime = current_provider().capture_runtime()
    assert RUNTIME_KEYS <= runtime.keys()
    assert isinstance(runtime["reasons"], list)


# ---- capture prerequisites ------------------------------------------------------------------------------------

def test_cap_net_raw_is_parsed_from_proc_status():
    assert has_capability("Name:\tx\nCapEff:\t0000000000002000\n", 13) is True
    assert has_capability("CapEff:\t0000000000000000\n", 13) is False
    assert has_capability("CapEff:\tnot-hex\n", 13) is False
    assert has_capability("", 13) is False


def test_linux_capture_requires_privilege_and_a_bpf_compiler():
    unprivileged = LinuxProvider(geteuid=lambda: 1000, read_status=lambda: "CapEff:\t0\n",
                                 find_bpf_compiler=lambda: False)
    assert len(unprivileged.capture_prerequisites()) == 2
    root = LinuxProvider(geteuid=lambda: 0, read_status=lambda: "", find_bpf_compiler=lambda: True)
    assert root.capture_prerequisites() == []
    capable = LinuxProvider(geteuid=lambda: 1000, read_status=lambda: "CapEff:\t0000000000002000\n",
                            find_bpf_compiler=lambda: True)
    assert capable.is_elevated() and capable.capture_prerequisites() == []
    assert capable.loopback_interface() == "lo"


def test_macos_capture_requires_root_or_bpf_access():
    assert MacOSProvider(geteuid=lambda: 501, bpf_readable=lambda: False).capture_prerequisites()
    assert MacOSProvider(geteuid=lambda: 501, bpf_readable=lambda: True).capture_prerequisites() == []
    assert MacOSProvider(geteuid=lambda: 0, bpf_readable=lambda: False).capture_prerequisites() == []
    assert MacOSProvider().loopback_interface() == "lo0"


# ---- fake command runners that keep real state -----------------------------------------------------------------

class FakeNft:
    """Tiny nftables simulator: tracks tables, sets and the isolation rule across calls."""

    def __init__(self):
        self.calls = []
        self.tables = set()
        self.sets = {"blocked4": set(), "blocked6": set()}
        self.rules = False
        self.isolation_rule = False

    def __call__(self, argv, input_text):
        self.calls.append((list(argv), input_text))
        assert isinstance(argv, list) and all(isinstance(part, str) for part in argv)
        ok = CompletedProcess(argv, 0, "", "")
        if argv[:2] == ["nft", "-f"]:
            for line in (input_text or "").splitlines():
                if line.startswith("add table"):
                    self.tables.add(line.split()[3])
                elif line.startswith("add rule inet bk_security output ip daddr"):
                    self.rules = True
                elif "oifname" in line:
                    self.isolation_rule = True
                elif line.startswith("add element"):
                    name, ip = line.split()[4], line.split("{")[1].split("}")[0].strip()
                    self.sets[name].add(ip)
                elif line.startswith("delete element"):
                    name, ip = line.split()[4], line.split("{")[1].split("}")[0].strip()
                    self.sets[name].discard(ip)
            return ok
        if argv[:4] == ["nft", "-j", "list", "set"]:
            elems = sorted(self.sets[argv[6]])
            return CompletedProcess(argv, 0, json.dumps({"nftables": [{"set": {"elem": elems}}]}), "")
        if argv[:3] == ["nft", "list", "chain"]:
            if argv[4] == "bk_security_isolation":
                alive = "bk_security_isolation" in self.tables
                return CompletedProcess(argv, 0 if alive else 1, "drop" if alive and self.isolation_rule else "", "")
            return CompletedProcess(argv, 0, "@blocked4 drop @blocked6 drop" if self.rules else "", "")
        if argv[:3] == ["nft", "list", "table"]:
            return CompletedProcess(argv, 0 if argv[4] in self.tables else 1, "", "")
        if argv[:3] == ["nft", "delete", "table"]:
            self.tables.discard(argv[4])
            self.isolation_rule = False
            return ok
        raise AssertionError(f"unexpected command {argv}")


def test_nft_block_lifecycle_is_idempotent_verified_and_reversible():
    nft = FakeNft()
    adapter = NftBlockAdapter(nft)
    result = adapter.execute("203.0.113.5", Action.BLOCK, "test")
    assert result["set"] == "blocked4" and result["reversible"] is True
    again = adapter.execute("203.0.113.5", Action.BLOCK, "test")
    assert again["target"] == "203.0.113.5"
    rule_scripts = [text for argv, text in nft.calls if text and "add rule" in text]
    assert len(rule_scripts) == 1  # forwarding rules are created once
    assert adapter.verify("203.0.113.5", Action.BLOCK, result)["verified"] is True
    removed = adapter.rollback({"result": result})
    assert removed["removed"] is True
    assert adapter.verify_rollback({"result": result}, removed)["verified"] is True
    assert adapter.verify("203.0.113.5", Action.BLOCK, result)["verified"] is False


def test_nft_block_uses_ipv6_set_and_rejects_foreign_state():
    nft = FakeNft()
    adapter = NftBlockAdapter(nft)
    result = adapter.execute("2001:db8::5", Action.BLOCK, "test")
    assert result["set"] == "blocked6" and "2001:db8::5" in nft.sets["blocked6"]
    with pytest.raises(ResponseAdapterError):
        adapter.rollback({"result": {"set": "blocked4", "target": "2001:db8::5"}})


@pytest.mark.parametrize("target", ["not-an-ip", "127.0.0.1", "10.0.0.1; nft flush ruleset", "", "0.0.0.0", "224.0.0.1"])
def test_posix_adapters_reject_bad_targets_before_running_anything(target):
    def forbidden(*_):
        pytest.fail("an invalid target reached a command runner")
    for adapter in (NftBlockAdapter(forbidden), PfBlockAdapter(forbidden)):
        with pytest.raises(ResponseAdapterError):
            adapter.execute(target, Action.BLOCK, "test")


def test_adapters_refuse_the_wrong_action():
    for adapter, action in ((NftBlockAdapter(FakeNft()), Action.ISOLATE), (NftIsolationAdapter(FakeNft()), Action.BLOCK),
                            (PfBlockAdapter(lambda *_: pytest.fail("ran")), Action.TERMINATE_PROCESS),
                            (PfIsolationAdapter(lambda *_: pytest.fail("ran")), Action.BLOCK),
                            (ProcessTerminateAdapter(), Action.BLOCK)):
        with pytest.raises(ResponseAdapterError):
            adapter.execute("local", action, "test")


def test_nft_isolation_is_local_only_and_removes_its_own_table():
    nft = FakeNft()
    adapter = NftIsolationAdapter(nft)
    with pytest.raises(ResponseAdapterError, match="local host"):
        adapter.execute("some-other-host", Action.ISOLATE, "test")
    assert nft.calls == []
    result = adapter.execute("local", Action.ISOLATE, "test")
    assert adapter.verify("local", Action.ISOLATE, result)["verified"] is True
    adapter.rollback({"result": result})
    assert adapter.verify_rollback({"result": result}, result)["verified"] is True
    assert "bk_security_isolation" not in nft.tables
    with pytest.raises(ResponseAdapterError):
        adapter.rollback({"result": {"table": "filter"}})


class FakePf:
    def __init__(self, enabled=True, anchor_referenced=True):
        self.table, self.loaded, self.isolation = set(), False, False
        self.enabled, self.anchor_referenced = enabled, anchor_referenced
        self.calls = []

    def __call__(self, argv, input_text):
        self.calls.append(list(argv))
        ok = CompletedProcess(argv, 0, "", "")
        if argv[:3] == ["pfctl", "-a", "bk-security"] and argv[3:5] == ["-s", "rules"]:
            return CompletedProcess(argv, 0, "block drop out quick to <bk_blocked>" if self.loaded else "", "")
        if argv[:3] == ["pfctl", "-a", "bk-security"] and argv[3] == "-f":
            self.loaded = True
            return ok
        if "-T" in argv and argv[argv.index("-T") + 1] == "add":
            self.table.add(argv[-1])
            return ok
        if "-T" in argv and argv[argv.index("-T") + 1] == "delete":
            self.table.discard(argv[-1])
            return ok
        if "-T" in argv and argv[argv.index("-T") + 1] == "show":
            return CompletedProcess(argv, 0, "".join(f"   {ip}\n" for ip in sorted(self.table)), "")
        if argv[:3] == ["pfctl", "-s", "info"]:
            return CompletedProcess(argv, 0, "Status: Enabled" if self.enabled else "Status: Disabled", "")
        if argv[:3] == ["pfctl", "-s", "rules"]:
            names = ('anchor "bk-security"\nanchor "bk-security-isolation"' if self.anchor_referenced else "")
            return CompletedProcess(argv, 0, names, "")
        if argv[:3] == ["pfctl", "-a", "bk-security-isolation"]:
            if argv[3] == "-f":
                self.isolation = True
            elif argv[3] == "-F":
                self.isolation = False
            elif argv[3:5] == ["-s", "rules"]:
                return CompletedProcess(argv, 0, "block drop out quick on ! lo0 all" if self.isolation else "", "")
            return ok
        raise AssertionError(f"unexpected command {argv}")


def test_pf_block_lifecycle_and_honest_verification_when_anchor_is_inactive():
    pf = FakePf()
    adapter = PfBlockAdapter(pf)
    result = adapter.execute("203.0.113.9", Action.BLOCK, "test")
    assert adapter.verify("203.0.113.9", Action.BLOCK, result)["verified"] is True
    inactive = FakePf(anchor_referenced=False)
    inactive_adapter = PfBlockAdapter(inactive)
    result = inactive_adapter.execute("203.0.113.9", Action.BLOCK, "test")
    verdict = inactive_adapter.verify("203.0.113.9", Action.BLOCK, result)
    assert verdict["verified"] is False and verdict["observed"] == "anchor_not_active"
    adapter.rollback({"result": result})
    assert adapter.verify_rollback({"result": result}, result)["verified"] is True
    with pytest.raises(ResponseAdapterError):
        adapter.rollback({"result": {"anchor": "other", "table": "t", "target": "203.0.113.9"}})


def test_pf_isolation_lifecycle():
    pf = FakePf()
    adapter = PfIsolationAdapter(pf)
    with pytest.raises(ResponseAdapterError, match="local host"):
        adapter.execute("remote", Action.ISOLATE, "test")
    result = adapter.execute("local", Action.ISOLATE, "test")
    assert adapter.verify("local", Action.ISOLATE, result)["verified"] is True
    adapter.rollback({"result": result})
    assert adapter.verify_rollback({"result": result}, result)["verified"] is True


# ---- process termination against a real child process --------------------------------------------------------

def test_process_adapter_terminates_a_real_child_and_verifies_absence():
    child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])
    try:
        adapter = ProcessTerminateAdapter(grace_seconds=5)
        assert adapter.verify(str(child.pid), Action.TERMINATE_PROCESS, {})["observed"] == "present"
        result = adapter.execute(str(child.pid), Action.TERMINATE_PROCESS, "test")
        assert result["pid"] == child.pid and result["reversible"] is False
        deadline = time.monotonic() + 5
        while child.poll() is None and time.monotonic() < deadline:
            time.sleep(0.05)
        assert child.poll() is not None
        assert adapter.verify(str(child.pid), Action.TERMINATE_PROCESS, result)["verified"] is True
        assert adapter.verify_rollback({}, {})["verified"] is False
    finally:
        if child.poll() is None:
            child.kill()


def test_process_adapter_refuses_itself_its_parent_init_and_bad_pids():
    adapter = ProcessTerminateAdapter()
    for pid in (os.getpid(), os.getppid(), 1):
        with pytest.raises(ResponseAdapterError):
            adapter.execute(str(pid), Action.TERMINATE_PROCESS, "test")
    for pid in ("0", "-5", "abc", "12; reboot"):
        with pytest.raises(ResponseAdapterError):
            adapter.execute(pid, Action.TERMINATE_PROCESS, "test")


def test_process_adapter_refuses_protected_names():
    class Fake:
        STATUS_ZOMBIE = "zombie"
        NoSuchProcess = AccessDenied = TimeoutExpired = type("E", (Exception,), {})

        class Process:
            def __init__(self, pid):
                pass

            def name(self):
                return "systemd"

            def terminate(self):
                pytest.fail("a protected process was terminated")

    with pytest.raises(ResponseAdapterError, match="protected"):
        ProcessTerminateAdapter(Fake).execute("4242", Action.TERMINATE_PROCESS, "test")


# ---- wiring into the core and production configuration --------------------------------------------------------

def test_os_response_is_off_by_default_and_uses_the_platform_provider_when_enabled(monkeypatch):
    monkeypatch.delenv("BK_SECURITY_OS_RESPONSE", raising=False)
    monkeypatch.delenv("BK_SECURITY_WINDOWS_RESPONSE", raising=False)
    assert core_module._response_adapters() == {}
    sentinel = {Action.BLOCK: object()}
    import bk_security.platforms as platforms
    monkeypatch.setattr(platforms, "current_provider", lambda: SimpleNamespace(response_adapters=lambda: sentinel))
    monkeypatch.setenv("BK_SECURITY_OS_RESPONSE", "1")
    assert core_module._response_adapters() is sentinel


def test_production_refuses_enabling_os_response():
    env = {"BK_SECURITY_ENV": "production", "BK_SECURITY_OS_RESPONSE": "1"}
    assert any("BK_SECURITY_OS_RESPONSE" in error for error in production_configuration_errors(env))
