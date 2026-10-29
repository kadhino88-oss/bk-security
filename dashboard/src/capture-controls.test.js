import test from 'node:test';
import assert from 'node:assert/strict';
import {
  canStartCapture,
  canStopCapture,
  captureRoleLabel,
  captureStatusExplanation,
  captureStatusLabel,
  isCaptureDeviceReady,
  preferredCaptureDevice,
  requestCaptureStart,
  requestCaptureStop,
} from './capture-controls.js';

test('prefers an active Wi-Fi interface, then a usable fallback', () => {
  const devices = [
    { name: 'ethernet', status: 'up' },
    { name: 'wifi-down', is_wireless: true, status: 'down' },
    { name: 'wifi-up', is_wireless: true, status: 'up' },
  ];
  assert.equal(preferredCaptureDevice(devices).name, 'wifi-up');
  assert.equal(preferredCaptureDevice([{ name: 'loopback', is_loopback: true, status: 'up' }]).name, 'loopback');
  assert.equal(preferredCaptureDevice([]), null);
});

test('requires live-capture capability and an up interface, except loopback', () => {
  const capabilities = { live_capture_available: true };
  assert.equal(isCaptureDeviceReady(capabilities, { name: 'wifi', status: 'up' }), true);
  assert.equal(isCaptureDeviceReady(capabilities, { name: 'wifi', status: 'down' }), false);
  assert.equal(isCaptureDeviceReady(capabilities, { name: 'wifi', status: 'unknown' }), false);
  assert.equal(isCaptureDeviceReady(capabilities, { name: 'wifi' }), false);
  assert.equal(isCaptureDeviceReady(capabilities, { name: 'loopback', status: 'down', is_loopback: true }), true);
  assert.equal(isCaptureDeviceReady({ live_capture_available: false }, { name: 'wifi', status: 'up' }), false);
  assert.equal(isCaptureDeviceReady(capabilities, null), false);
});

test('capture cannot start while readiness or an existing capture blocks it', () => {
  assert.equal(canStartCapture({ canManage: true, busy: false, runningSelected: false, otherLiveCapture: false, ready: true }), true);
  assert.equal(canStartCapture({ canManage: false, busy: false, runningSelected: false, otherLiveCapture: false, ready: true }), false);
  for (const blocker of ['busy', 'runningSelected', 'otherLiveCapture', 'ready']) {
    const state = { canManage: true, busy: false, runningSelected: false, otherLiveCapture: false, ready: true };
    state[blocker] = blocker === 'ready' ? false : true;
    assert.equal(canStartCapture(state), false, `${blocker} should block capture start`);
  }
});

test('capture stop is offered only to an authorized idle operator while a capture is running', () => {
  assert.equal(canStopCapture({ canManage: true, busy: false, running: true }), true);
  assert.equal(canStopCapture({ canManage: false, busy: false, running: true }), false);
  assert.equal(canStopCapture({ canManage: true, busy: true, running: true }), false);
  assert.equal(canStopCapture({ canManage: true, busy: false, running: false }), false);
});

test('live capture start posts the selected interface with bearer authorization', async () => {
  const calls = [];
  const result = await requestCaptureStart({
    api: 'http://127.0.0.1:8000',
    token: 'session-token',
    interfaceName: 'wifi-npcap',
    fetchImpl: async (url, options) => {
      calls.push({ url, options });
      return { ok: true, status: 200, json: async () => ({ running: true }) };
    },
  });

  assert.deepEqual(result, { running: true });
  assert.equal(calls.length, 1);
  assert.equal(calls[0].url, 'http://127.0.0.1:8000/api/v1/capture/start');
  assert.equal(calls[0].options.method, 'POST');
  assert.equal(calls[0].options.headers.Authorization, 'Bearer session-token');
  assert.deepEqual(JSON.parse(calls[0].options.body), { mode: 'live', interface: 'wifi-npcap', scope: 'endpoint' });
});

test('live capture can explicitly select mirrored-network scope', async () => {
  let body;
  await requestCaptureStart({
    api: 'http://127.0.0.1:8000',
    token: 'session-token',
    interfaceName: 'span-npcap',
    scope: 'mirror',
    fetchImpl: async (_url, options) => {
      body = JSON.parse(options.body);
      return { ok: true, status: 200, json: async () => ({ running: true, capture_scope: 'mirror' }) };
    },
  });
  assert.deepEqual(body, { mode: 'live', interface: 'span-npcap', scope: 'mirror' });
});

test('capture replacement must stop the current session before starting live capture', async () => {
  const calls = [];
  await requestCaptureStart({
    api: 'http://127.0.0.1:8000',
    token: 'session-token',
    interfaceName: 'wifi-npcap',
    replaceExisting: true,
    fetchImpl: async (url, options) => {
      calls.push({ url, options });
      return url.endsWith('/stop')
        ? { ok: true, status: 200 }
        : { ok: true, status: 200, json: async () => ({ running: true }) };
    },
  });

  assert.equal(calls.length, 2);
  assert.match(calls[0].url, /\/capture\/stop$/);
  assert.match(calls[1].url, /\/capture\/start$/);
});

test('capture start failure stops replacement before issuing any start request', async () => {
  const calls = [];
  await assert.rejects(() => requestCaptureStart({
    api: 'http://127.0.0.1:8000',
    token: 'session-token',
    interfaceName: 'wifi-npcap',
    replaceExisting: true,
    fetchImpl: async (url) => {
      calls.push(url);
      return { ok: false, status: 409 };
    },
  }), /Current capture could not be stopped \(409\)/);
  assert.equal(calls.length, 1);
  assert.match(calls[0], /\/capture\/stop$/);
});

test('capture stop reports API failures to the dashboard action', async () => {
  await assert.rejects(() => requestCaptureStop({
    api: 'http://127.0.0.1:8000',
    token: 'session-token',
    fetchImpl: async () => ({ ok: false, status: 503 }),
  }), /Capture stop failed \(503\)/);
});

test('session role is displayed separately from whether packet capture is stopped', () => {
  assert.equal(captureRoleLabel('admin'), 'SIGNED IN · ADMIN');
  assert.equal(captureRoleLabel('analyst'), 'SIGNED IN · ANALYST');
  assert.equal(captureStatusLabel({ running: false }), 'CAPTURE STOPPED');
  assert.match(captureStatusExplanation('analyst', { running: false }), /Session role: analyst/);
  assert.match(captureStatusExplanation('analyst', { running: false }), /no interface is currently collecting packets/);
  assert.equal(captureStatusLabel({ running: true, mode: 'live' }), 'LIVE · RUNNING');
  assert.equal(captureRoleLabel('unexpected'), 'SIGNED IN · UNKNOWN');
});
