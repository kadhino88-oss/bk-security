import test from 'node:test';
import assert from 'node:assert/strict';
import {
  incidentEvidenceIds,
  loadResponseActivity,
  prepareIncidentDryRun,
  responseOutcomeLabel,
} from './response-activity.js';

test('response activity reads the protected actions and audit endpoints with bearer auth', async () => {
  const calls = [];
  const data = await loadResponseActivity({
    api: 'http://127.0.0.1:8000',
    token: 'session-token',
    fetchImpl: async (url, options) => {
      calls.push({ url, options });
      return {
        ok: true,
        json: async () => url.endsWith('/actions')
          ? { actions: [{ plan_id: 'plan-1' }] }
          : { audit: [{ action: 'response_plan' }] },
      };
    },
  });

  assert.deepEqual(data, {
    actions: [{ plan_id: 'plan-1' }],
    audit: [{ action: 'response_plan' }],
  });
  assert.deepEqual(calls.map(({ url }) => url).sort(), [
    'http://127.0.0.1:8000/api/v1/response/actions',
    'http://127.0.0.1:8000/api/v1/response/audit',
  ]);
  assert.ok(calls.every(({ options }) => options.headers.Authorization === 'Bearer session-token'));
});

test('incident plan request is policy-selected, linked, and always dry-run', async () => {
  let request;
  const plan = await prepareIncidentDryRun({
    api: 'http://127.0.0.1:8000',
    token: 'session-token',
    incident: {
      incident_id: 'incident-17',
      host_id: 'host-17',
      title: 'Suspicious outbound network behavior',
      severity: 'CRITICAL',
      risk_score: 98,
      alert_ids: ['alert-17a', 'alert-17b', 'alert-17a'],
    },
    fetchImpl: async (url, options) => {
      request = { url, options };
      return { ok: true, json: async () => ({ plan_id: 'plan-17', dry_run: true }) };
    },
  });

  assert.equal(plan.plan_id, 'plan-17');
  assert.equal(request.url, 'http://127.0.0.1:8000/api/v1/response/plan');
  assert.equal(request.options.method, 'POST');
  assert.equal(request.options.headers.Authorization, 'Bearer session-token');
  const body = JSON.parse(request.options.body);
  assert.equal(body.dry_run, true);
  assert.equal(body.action, undefined);
  assert.equal(body.target, 'host-17');
  assert.equal(body.incident_id, 'incident-17');
  assert.deepEqual(body.evidence_ids, ['alert-17a', 'alert-17b']);
  assert.equal(body.risk_level, 'critical');
  assert.equal(body.risk_score, 98);
});

test('incident dry-run refuses an unlinked target before making a request', async () => {
  let called = false;
  await assert.rejects(() => prepareIncidentDryRun({
    api: 'http://127.0.0.1:8000',
    token: 'session-token',
    incident: { incident_id: 'incident-1', title: 'Missing host' },
    fetchImpl: async () => { called = true; },
  }), /recorded host target/);
  assert.equal(called, false);
});

test('incident dry-run refuses incidents without linked alert evidence', async () => {
  let called = false;
  await assert.rejects(() => prepareIncidentDryRun({
    api: 'http://127.0.0.1:8000',
    token: 'session-token',
    incident: { incident_id: 'incident-2', host_id: 'host-2' },
    fetchImpl: async () => { called = true; },
  }), /linked alert evidence/);
  assert.equal(called, false);
  assert.deepEqual(incidentEvidenceIds({ alert_ids: [' alert-1 ', '', 'alert-1', null] }), ['alert-1']);
});

test('response labels never call an unverified outcome verified', () => {
  assert.equal(responseOutcomeLabel({ status: 'dry_run', dry_run: true }), 'DRY-RUN · NO ACTION EXECUTED');
  assert.equal(responseOutcomeLabel({ status: 'executed', verification: { verified: true } }), 'EXECUTED · VERIFIED');
  assert.equal(responseOutcomeLabel({ status: 'executed' }), 'EXECUTION RECORDED · VERIFICATION UNCONFIRMED');
  assert.equal(responseOutcomeLabel({ status: 'degraded' }), 'REVIEW REQUIRED · DEGRADED');
});
