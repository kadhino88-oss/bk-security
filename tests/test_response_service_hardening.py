import tempfile
from pathlib import Path
from bk_security.policy.engine import Action
from bk_security.services.response_service import ResponseExecutorService, DryRunAdapter

TARGET='203.0.113.10'
class Adapter(DryRunAdapter):
    def __init__(self):
        super().__init__(Action.BLOCK)
        self.calls=0
        self.rollbacks=[]
    def execute(self, target, action, reason):
        self.calls+=1
        return {'rule':'BK-Security-test','reversible':True}
    def verify_rollback(self, execution, result):
        return {'verified': True}
    def rollback(self, execution):
        self.rollbacks.append(execution)
        return {'removed':True}

def service(path, adapter=None, **kw):
    return ResponseExecutorService({Action.BLOCK:adapter or Adapter()},state_path=str(path), authorization_verifier=kw.pop('authorization_verifier', lambda scope: scope.get('approval', {}).get('test_only') is True), **kw)

def test_denied_without_store():
    s=ResponseExecutorService({Action.BLOCK:Adapter()})
    assert s.handle({'op':'execute','action':'block','target':TARGET,'execution_id':'execution-001'})['ok'] is False

def test_ipc_authorize_uses_injected_verifier_and_never_exposes_issue_grant(tmp_path):
    from bk_security.services.response_service import OPERATIONS
    s=service(tmp_path/'db', authorization_verifier=lambda scope:
             scope.get('approval', {}).get('proof') == 'trusted-test-proof')
    authorization=s.handle({
        'op':'authorize', 'mutation_op':'execute', 'action':'block', 'target':TARGET,
        'execution_id':'execution-001', 'approval':{'proof':'trusted-test-proof'},
    })
    assert authorization['ok'] is True
    assert 'issue_grant' not in OPERATIONS
    execution=s.handle({
        'op':'execute', 'action':'block', 'target':TARGET,
        'execution_id':'execution-001', 'authorization_id':authorization['authorization_id'],
    })
    assert execution['ok'] is True

def test_ipc_authorize_refuses_untrusted_claims(tmp_path):
    s=service(tmp_path/'db', authorization_verifier=lambda _scope: False)
    response=s.handle({
        'op':'authorize', 'mutation_op':'execute', 'action':'block', 'target':TARGET,
        'execution_id':'execution-001', 'approval':{'test_only':True},
    })
    assert response == {'ok':False, 'error':'approval_verification_failed'}

def test_service_startup_requires_durable_state_audit_and_trusted_verifier(tmp_path):
    import threading
    import pytest

    missing_audit=ResponseExecutorService(
        {Action.BLOCK:Adapter()}, state_path=str(tmp_path/'db'),
        authorization_verifier=lambda _scope: True,
    )
    with pytest.raises(RuntimeError, match='audit_path_required'):
        missing_audit.serve('unused', b'k'*32, stop=threading.Event())

    missing_verifier=ResponseExecutorService(
        {Action.BLOCK:Adapter()}, state_path=str(tmp_path/'db2'), audit_path=str(tmp_path/'audit.jsonl'),
    )
    with pytest.raises(RuntimeError, match='trusted_approval_verifier_required'):
        missing_verifier.serve('unused', b'k'*32, stop=threading.Event())

def test_windows_service_refuses_start_without_acl_preflight(tmp_path, monkeypatch):
    import threading
    import types
    import pytest
    import bk_security.services.response_service as response_service

    service_instance=ResponseExecutorService(
        {Action.BLOCK:Adapter()}, state_path=str(tmp_path/'db'),
        audit_path=str(tmp_path/'audit.jsonl'), ipc_key_path=str(tmp_path/'ipc.key'),
        trust_store_path=str(tmp_path/'trusted.json'),
        authorization_verifier=lambda _scope: True,
    )
    monkeypatch.setattr(response_service, 'os', types.SimpleNamespace(name='nt'))
    with pytest.raises(RuntimeError, match='windows_acl_validator_required'):
        service_instance.serve('unused', b'k'*32, stop=threading.Event())

def test_no_grant_denied(tmp_path):
    s=service(tmp_path/'db')
    assert s.handle({'op':'execute','action':'block','target':TARGET,'execution_id':'execution-001'})['error']=='authorization_required'

def test_persistent_replay(tmp_path):
    db=tmp_path/'db'; a=Adapter(); s=service(db,a)
    grant=s.issue_grant(op='execute',action=Action.BLOCK,target=TARGET,execution_id='execution-001',approval={'test_only':True})
    req={'op':'execute','action':'block','target':TARGET,'execution_id':'execution-001','authorization_id':grant}
    assert s.handle(req)['ok']
    assert service(db,a).handle(req)['error']=='execution_id_replayed'
    assert a.calls==1

def test_wrong_scope_does_not_consume(tmp_path):
    s=service(tmp_path/'db')
    grant=s.issue_grant(op='execute',action=Action.BLOCK,target=TARGET,execution_id='execution-001',approval={'test_only':True})
    req={'op':'execute','action':'block','target':'203.0.113.11','execution_id':'execution-001','authorization_id':grant}
    assert s.handle(req)['error']=='authorization_scope_invalid'
    req['target']=TARGET
    assert s.handle(req)['ok']

def test_rate_limit_does_not_consume(tmp_path):
    db=tmp_path/'db'; s=service(db,max_executions_per_minute=0)
    grant=s.issue_grant(op='execute',action=Action.BLOCK,target=TARGET,execution_id='execution-001',approval={'test_only':True})
    req={'op':'execute','action':'block','target':TARGET,'execution_id':'execution-001','authorization_id':grant}
    assert s.handle(req)['error']=='rate_limited'
    assert service(db).handle(req)['ok']

def test_rollback_only_known_execution(tmp_path):
    s=service(tmp_path/'db')
    grant=s.issue_grant(op='rollback',action=Action.BLOCK,target=TARGET,execution_id='execution-001',approval={'test_only':True})
    req={'op':'rollback','action':'block','execution_id':'execution-001','authorization_id':grant,'execution':{'action':'block','result':{'rule':'forged'}}}
    assert s.handle(req)['error']=='execution_not_eligible'

def test_rollback_uses_stored_result(tmp_path):
    a=Adapter(); s=service(tmp_path/'db',a)
    g=s.issue_grant(op='execute',action=Action.BLOCK,target=TARGET,execution_id='execution-001',approval={'test_only':True})
    assert s.handle({'op':'execute','action':'block','target':TARGET,'execution_id':'execution-001','authorization_id':g})['ok']
    r=s.issue_grant(op='rollback',action=Action.BLOCK,target=TARGET,execution_id='execution-001',approval={'test_only':True})
    req={'op':'rollback','action':'block','execution_id':'execution-001','authorization_id':r,'execution':{'result':{'rule':'forged'}}}
    assert s.handle(req)['ok']
    assert a.rollbacks[0]['result']['rule']=='BK-Security-test'
    assert s.handle(req)['error']=='execution_not_eligible'

def test_protected_network(tmp_path):
    s=service(tmp_path/'db')
    try:
        s.issue_grant(op='execute',action=Action.BLOCK,target='192.168.1.1',execution_id='execution-001',approval={'test_only':True})
    except Exception:
        pass
    else:
        assert False


def test_no_verifier_cannot_mint_grant(tmp_path):
    s=ResponseExecutorService({Action.BLOCK:Adapter()},state_path=str(tmp_path/'db'))
    import pytest
    with pytest.raises(PermissionError, match='trusted_approval_verifier_required'):
        s.issue_grant(op='execute',action=Action.BLOCK,target=TARGET,execution_id='execution-001',approval={'test_only':True})

def test_no_approval_cannot_mint_grant(tmp_path):
    import pytest
    s=service(tmp_path/'db')
    with pytest.raises(PermissionError, match='approval_evidence_required'):
        s.issue_grant(op='execute',action=Action.BLOCK,target=TARGET,execution_id='execution-001')

def test_verifier_denial_cannot_mint_grant(tmp_path):
    import pytest
    s=service(tmp_path/'db',authorization_verifier=lambda scope: False)
    with pytest.raises(PermissionError, match='approval_verification_failed'):
        s.issue_grant(op='execute',action=Action.BLOCK,target=TARGET,execution_id='execution-001',approval={'test_only':True})

def test_expired_grant_is_rejected(tmp_path):
    import sqlite3
    s=service(tmp_path/'db')
    grant=s.issue_grant(op='execute',action=Action.BLOCK,target=TARGET,execution_id='execution-001',approval={'test_only':True})
    with sqlite3.connect(tmp_path/'db') as db:
        db.execute('UPDATE grants SET expires=0 WHERE id=?',(grant,))
    response=s.handle({'op':'execute','action':'block','target':TARGET,'execution_id':'execution-001','authorization_id':grant})
    assert response['error']=='authorization_scope_invalid'

def test_grant_cannot_change_execution_id(tmp_path):
    s=service(tmp_path/'db')
    grant=s.issue_grant(op='execute',action=Action.BLOCK,target=TARGET,execution_id='execution-001',approval={'test_only':True})
    response=s.handle({'op':'execute','action':'block','target':TARGET,'execution_id':'execution-002','authorization_id':grant})
    assert response['error']=='authorization_scope_invalid'

def test_concurrent_replay_only_executes_once(tmp_path):
    from concurrent.futures import ThreadPoolExecutor
    adapter=Adapter()
    db=tmp_path/'db'
    s1=service(db,adapter)
    s2=service(db,adapter)
    grant=s1.issue_grant(op='execute',action=Action.BLOCK,target=TARGET,execution_id='execution-001',approval={'test_only':True})
    req={'op':'execute','action':'block','target':TARGET,'execution_id':'execution-001','authorization_id':grant}
    with ThreadPoolExecutor(max_workers=2) as pool:
        responses=list(pool.map(lambda s:s.handle(req),[s1,s2]))
    assert sum(r['ok'] for r in responses)==1
    assert adapter.calls==1

def test_failed_execution_cannot_be_replayed(tmp_path):
    class BrokenAdapter(Adapter):
        def execute(self, target, action, reason):
            self.calls+=1
            raise RuntimeError('simulated_failure')
    adapter=BrokenAdapter()
    s=service(tmp_path/'db',adapter)
    grant=s.issue_grant(op='execute',action=Action.BLOCK,target=TARGET,execution_id='execution-001',approval={'test_only':True})
    req={'op':'execute','action':'block','target':TARGET,'execution_id':'execution-001','authorization_id':grant}
    assert s.handle(req)['error']=='adapter_error'
    assert s.handle(req)['error']=='execution_id_replayed'
    assert adapter.calls==1

def test_ping_not_ready_without_verifier(tmp_path):
    s=ResponseExecutorService({Action.BLOCK:Adapter()},state_path=str(tmp_path/'db'))
    assert s.handle({'op':'ping'})['mutations_ready'] is False


def test_existing_grant_rejected_when_verifier_missing(tmp_path):
    db=tmp_path/'db'
    s=service(db)
    grant=s.issue_grant(op='execute',action=Action.BLOCK,target=TARGET,execution_id='execution-001',approval={'test_only':True})
    restarted=ResponseExecutorService({Action.BLOCK:Adapter()},state_path=str(db))
    req={'op':'execute','action':'block','target':TARGET,'execution_id':'execution-001','authorization_id':grant}
    assert restarted.handle(req)['error']=='trusted_approval_verifier_required'

def test_invalid_grant_does_not_exhaust_rate_limit(tmp_path):
    s=service(tmp_path/'db',max_executions_per_minute=1)
    invalid={'op':'execute','action':'block','target':TARGET,'execution_id':'execution-002','authorization_id':'x'*40}
    for _ in range(4):
        assert s.handle(invalid)['error']=='authorization_required'
    grant=s.issue_grant(op='execute',action=Action.BLOCK,target=TARGET,execution_id='execution-001',approval={'test_only':True})
    assert s.handle({**invalid,'execution_id':'execution-001','authorization_id':grant})['ok']

def test_approval_verifier_exception_fails_closed(tmp_path):
    import pytest
    def broken(_):
        raise RuntimeError('unavailable')
    s=service(tmp_path/'db',authorization_verifier=broken)
    with pytest.raises(PermissionError, match='approval_verification_failed'):
        s.issue_grant(op='execute',action=Action.BLOCK,target=TARGET,execution_id='execution-001',approval={'test_only':True})
