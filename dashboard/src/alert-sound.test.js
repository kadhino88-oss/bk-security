import assert from 'node:assert/strict';
import test from 'node:test';
import { playCriticalAlarm, trackCriticalAlertActivity } from './alert-sound.js';

test('critical alarm activity is triggered only by new or escalated critical alerts', () => {
  const seen = new Map();
  assert.equal(trackCriticalAlertActivity([{ alert_id: 'a1', severity: 'HIGH' }], seen), false);
  assert.equal(trackCriticalAlertActivity([{ alert_id: 'a1', severity: 'CRITICAL' }], seen), true);
  assert.equal(trackCriticalAlertActivity([{ alert_id: 'a1', severity: 'CRITICAL' }], seen), false);
  assert.equal(trackCriticalAlertActivity([{ alert_id: 'a2', severity: 'LOW' }], seen), false);
});

test('critical alarm tracker ignores malformed entries and bounds retained alert history', () => {
  const seen = new Map();
  assert.equal(trackCriticalAlertActivity([null, {}, { title: 'no identity' }], seen), false);
  const alerts = Array.from({ length: 2100 }, (_, index) => ({ alert_id: `alert-${index}`, severity: 'LOW' }));
  assert.equal(trackCriticalAlertActivity(alerts, seen), false);
  assert.equal(seen.size, 2000);
  assert.equal(seen.has('alert-0'), false);
  assert.equal(seen.has('alert-2099'), true);
});

test('critical siren schedules four bounded, short tones and stays silent for a closed context', () => {
  const started = [];
  const stopped = [];
  const frequencyValues = [];
  const gainValues = [];
  const audioContext = {
    state: 'running',
    currentTime: 10,
    destination: {},
    createOscillator() {
      return {
        frequency: { setValueAtTime: (value) => frequencyValues.push(value) },
        connect() {},
        start: (time) => started.push(time),
        stop: (time) => stopped.push(time),
      };
    },
    createGain() {
      return {
        gain: {
          setValueAtTime: (value) => gainValues.push(value),
          linearRampToValueAtTime: (value) => gainValues.push(value),
          exponentialRampToValueAtTime: (value) => gainValues.push(value),
        },
        connect() {},
      };
    },
  };

  assert.equal(playCriticalAlarm(audioContext, { gain: 2 }), true);
  assert.deepEqual(frequencyValues, [880, 660, 880, 660]);
  assert.equal(started.length, 4);
  assert.equal(stopped.length, 4);
  assert.ok(gainValues.every((value) => value <= 0.75));
  assert.equal(playCriticalAlarm({ state: 'closed' }), false);
});
