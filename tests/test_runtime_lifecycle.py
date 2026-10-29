from bk_security.runtime import RuntimeLifecycle

def test_runtime_lifecycle_starts_running():
    runtime = RuntimeLifecycle()
    assert runtime.stopping is False

def test_runtime_lifecycle_requests_stop():
    runtime = RuntimeLifecycle()
    runtime.request_stop()
    assert runtime.stopping is True
