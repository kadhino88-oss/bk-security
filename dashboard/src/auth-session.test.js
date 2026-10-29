import test from 'node:test';
import assert from 'node:assert/strict';
import { revokeAuthSession } from './auth-session.js';

test('logout asks the backend to revoke the bearer session', async () => {
  const calls = [];
  const revoked = await revokeAuthSession(async (...args) => {
    calls.push(args);
    return { ok: true, json: async () => ({ status: 'logged_out', revoked: true }) };
  }, 'http://127.0.0.1:8000', 'session-token');

  assert.equal(revoked, true);
  assert.equal(calls.length, 1);
  assert.equal(calls[0][0], 'http://127.0.0.1:8000/api/v1/auth/logout');
  assert.equal(calls[0][1].method, 'POST');
  assert.equal(calls[0][1].headers.Authorization, 'Bearer session-token');
});

test('logout reports failure if the backend cannot confirm revocation', async () => {
  assert.equal(await revokeAuthSession(async () => ({ ok: false }), 'http://local', 'token'), false);
  assert.equal(await revokeAuthSession(async () => { throw new Error('offline'); }, 'http://local', 'token'), false);
  assert.equal(await revokeAuthSession(async () => ({ ok: true, json: async () => ({ revoked: false }) }), 'http://local', 'token'), false);
});
