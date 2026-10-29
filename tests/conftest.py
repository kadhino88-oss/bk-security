import atexit
import os
import tempfile

import pytest


# The API module owns a process-level core, so give it a session-only database
# before test modules import it. Other cores get an isolated per-test database.
_session_db_dir = tempfile.TemporaryDirectory(prefix="bk-security-tests-")
os.environ["BK_SECURITY_DB"] = os.path.join(_session_db_dir.name, "api.sqlite3")
atexit.register(_session_db_dir.cleanup)


@pytest.fixture(autouse=True)
def isolate_core_database(tmp_path, monkeypatch):
    monkeypatch.setenv("BK_SECURITY_DB", str(tmp_path / "core.sqlite3"))
