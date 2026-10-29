import test from 'node:test';
import assert from 'node:assert/strict';
import { formatDeploymentScope, loadMonthlyAudit, previousCompletedUtcMonth } from './monthly-audit.js';

test('previous completed month handles the UTC year boundary', () => {
  assert.equal(previousCompletedUtcMonth(new Date('2026-01-10T03:00:00.000Z')), '2025-12');
});

test('deployment scope distinguishes the dedicated database binding from verified isolation', () => {
  assert.equal(
    formatDeploymentScope({
      profile: 'dedicated_customer', customer_ref: 'client-42', region: 'eu-ch',
      scope_enforcement: 'database_startup_binding_only',
    }),
    'Dedicated customer data plane · client-42 · eu-ch · database binding only; host and region not attested',
  );
  assert.match(formatDeploymentScope({ profile: 'local_v1' }), /single local instance/);
});

test('monthly audit uses the selected UTC month and bearer authentication', async () => {
  let request;
  const report = { period: { month: '2026-10', timezone: 'UTC' } };
  const result = await loadMonthlyAudit({
    api: 'https://bk.example', token: 'test-token', month: '2026-10',
    fetchImpl: async (url, options) => {
      request = { url, options };
      return { ok: true, status: 200, json: async () => report };
    },
  });
  assert.equal(request.url, 'https://bk.example/api/v1/audit/monthly?month=2026-10');
  assert.equal(request.options.headers.Authorization, 'Bearer test-token');
  assert.equal(result.period.timezone, 'UTC');
});

test('invalid months are rejected before making a request', async () => {
  let called = false;
  await assert.rejects(
    loadMonthlyAudit({ api: '/api', token: 'x', month: '2026-13', fetchImpl: async () => { called = true; } }),
    /valid month/,
  );
  assert.equal(called, false);
});

test('monthly audit surfaces API errors without hiding their status', async () => {
  await assert.rejects(
    loadMonthlyAudit({
      api: '/api', token: 'x', month: '2026-10',
      fetchImpl: async () => ({ ok: false, status: 503, json: async () => ({ detail: 'Audit temporarily unavailable.' }) }),
    }),
    /Audit temporarily unavailable/,
  );
});
