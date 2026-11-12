import pytest
from bk_security.services import protocol


class FakeConnection:
    def __init__(self, data=b''):
        self.data = data
        self.sent = None
    def recv_bytes(self, max_length):
        assert max_length == protocol.MAX_MESSAGE_BYTES
        return self.data
    def send_bytes(self, data):
        self.sent = data


def test_roundtrip():
    c = FakeConnection()
    protocol.send_json(c, {'op': 'ping', 'nested': {'a': 2}})
    c.data = c.sent
    assert protocol.recv_json(c)['nested']['a'] == 2


def test_oversized_outgoing_message_refused():
    c = FakeConnection()
    with pytest.raises(ValueError, match='maximum size'):
        protocol.send_json(c, {'data': 'x' * protocol.MAX_MESSAGE_BYTES})
    assert c.sent is None


def test_duplicate_json_fields_refused():
    with pytest.raises(ValueError, match='Duplicate'):
        protocol.recv_json(FakeConnection(b'{"op":"ping","op":"execute"}'))


@pytest.mark.parametrize('value', [b'{"n":NaN}', b'{"n":Infinity}', b'{"n":-Infinity}'])
def test_nonfinite_incoming_refused(value):
    with pytest.raises(ValueError, match='Non-finite'):
        protocol.recv_json(FakeConnection(value))


def test_nonfinite_outgoing_refused():
    with pytest.raises(ValueError):
        protocol.send_json(FakeConnection(), {'n': float('nan')})


def test_non_json_object_refused():
    with pytest.raises(ValueError, match='Malformed'):
        protocol.recv_json(FakeConnection(b'[1,2,3]'))


def test_non_serializable_data_refused():
    with pytest.raises(TypeError):
        protocol.send_json(FakeConnection(), {'n': object()})


def test_ipc_key_can_be_read_from_protected_file(tmp_path):
    key_path = tmp_path / "ipc.key"
    key_path.write_text("k" * protocol.MIN_KEY_CHARS, encoding="utf-8")
    assert protocol.load_key({"BK_SECURITY_RESPONSE_KEY_FILE": str(key_path)}) == b"k" * protocol.MIN_KEY_CHARS


def test_missing_ipc_key_file_fails_closed(tmp_path):
    with pytest.raises(protocol.ServiceKeyError, match="could not be read"):
        protocol.load_key({"BK_SECURITY_RESPONSE_KEY_FILE": str(tmp_path / "missing.key")})
