from bk_security.policy.engine import Action
from bk_security.services.response_service import ResponseExecutorService
from test_response_service_hardening import Adapter, TARGET, service


def test_audit_failure_does_not_misreport_os_success(tmp_path):
    a = Adapter()
    s = service(tmp_path / 'state.db', a)
    def broken(_):
        raise OSError('audit disk unavailable')
    s.audit.record = broken
    grant = s.issue_grant(op='execute', action=Action.BLOCK, target=TARGET,
                          execution_id='execution-001', approval={'test_only': True})
    req = {'op': 'execute', 'action': 'block', 'target': TARGET,
           'execution_id': 'execution-001', 'authorization_id': grant}
    result = s.handle(req)
    assert result['ok'] is True and result['audit_error'] is True
    assert a.calls == 1
    assert s.handle({'op': 'ping'})['mutations_ready'] is False
    assert s.handle(req)['error'] == 'audit_unavailable'


def test_audit_failure_does_not_misreport_rollback(tmp_path):
    a = Adapter()
    s = service(tmp_path / 'state.db', a)
    g = s.issue_grant(op='execute', action=Action.BLOCK, target=TARGET,
                      execution_id='execution-001', approval={'test_only': True})
    assert s.handle({'op': 'execute', 'action': 'block', 'target': TARGET,
                     'execution_id': 'execution-001', 'authorization_id': g})['ok']
    s.audit.record = lambda _: (_ for _ in ()).throw(OSError('disk full'))
    r = s.issue_grant(op='rollback', action=Action.BLOCK, target=TARGET,
                      execution_id='execution-001', approval={'test_only': True})
    response = s.handle({'op': 'rollback', 'action': 'block',
                         'execution_id': 'execution-001', 'authorization_id': r})
    assert response['ok'] is True and response['audit_error'] is True
    assert len(a.rollbacks) == 1


def test_database_connections_closed(tmp_path, monkeypatch):
    import sqlite3
    import bk_security.services.response_service as mod
    real_connect = sqlite3.connect
    counts = {'opened': 0, 'closed': 0}
    class TrackingConnection(sqlite3.Connection):
        def close(self):
            counts['closed'] += 1
            return super().close()
    def connect(*args, **kwargs):
        counts['opened'] += 1
        kwargs['factory'] = TrackingConnection
        return real_connect(*args, **kwargs)
    monkeypatch.setattr(mod.sqlite3, 'connect', connect)
    s = service(tmp_path / 'state.db')
    g = s.issue_grant(op='execute', action=Action.BLOCK, target=TARGET,
                      execution_id='execution-001', approval={'test_only': True})
    assert s.handle({'op': 'execute', 'action': 'block', 'target': TARGET,
                     'execution_id': 'execution-001', 'authorization_id': g})['ok']
    assert counts['opened'] == counts['closed']
