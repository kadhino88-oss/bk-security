import json
import pytest
from bk_security.services.response_service import AuditChain


def test_audit_chain_valid_after_restart(tmp_path):
    p = tmp_path / 'audit.jsonl'
    chain = AuditChain(str(p))
    chain.record({'op': 'execute', 'ok': False})
    restarted = AuditChain(str(p))
    restarted.record({'op': 'rollback', 'ok': False})
    assert AuditChain.verify(str(p))


def test_tampered_audit_fails_closed(tmp_path):
    p = tmp_path / 'audit.jsonl'
    chain = AuditChain(str(p))
    chain.record({'op': 'execute', 'ok': True})
    record = json.loads(p.read_text())
    record['ok'] = False
    p.write_text(json.dumps(record) + '\n')
    assert AuditChain.verify(str(p)) is False
    with pytest.raises(RuntimeError, match='audit_chain_integrity_failed'):
        AuditChain(str(p))


def test_malformed_audit_fails_closed(tmp_path):
    p = tmp_path / 'audit.jsonl'
    p.write_text('{not-json}\n')
    assert AuditChain.verify(str(p)) is False
    with pytest.raises(RuntimeError, match='audit_chain_integrity_failed'):
        AuditChain(str(p))
