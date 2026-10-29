import test from 'node:test';
import assert from 'node:assert/strict';
import { loadActiveAuthSessions, revokeUserSessions } from './admin-sessions.js';

test('admin session list uses the authenticated API and returns session summaries', async () => {
  const calls = [];
  const sessions = [{ username: 'analyst', active_sessions: 2, latest_expiration: 1900000000 }];
  const result = await loadActiveAuthSessions(async (...args) => {
    calls.push(args);
    return { ok: true, json: async () => ({ sessions }) };
  }, 'http://localhost', 'admin-token');

  assert.deepEqual(result, sessions);
  assert.equal(calls[0][0], 'http://localhost/api/v1/auth/sessions');
  assert.equal(calls[0][1].headers.Authorization, 'Bearer admin-token');
});

test('admin session revocation URL-encodes the username and posts the bearer token', async () => {
  const calls = [];
  const result = await revokeUserSessions(async (...args) => {
    calls.push(args);
    return { ok: true, json: async () => ({ username: 'security admin', revoked_sessions: 3 }) };
  }, 'http://localhost', 'admin-token', 'security admin');

  assert.deepEqual(result, { username: 'security admin', revoked_sessions: 3 });
  assert.equal(calls[0][0], 'http://localhost/api/v1/auth/sessions/security%20admin/revoke');
  assert.equal(calls[0][1].method, 'POST');
  assert.equal(calls[0][1].headers.Authorization, 'Bearer admin-token');
});

test('admin session helpers reject failed API responses', async () => {
  const failedFetch = async () => ({ ok: false, status: 403 });
  await assert.rejects(() => loadActiveAuthSessions(failedFetch, 'http://local', 'token'), /403/);
  await assert.rejects(() => revokeUserSessions(failedFetch, 'http://local', 'token', 'analyst'), /403/);
});
