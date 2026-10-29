import assert from 'node:assert/strict';
import test from 'node:test';
import { buildTrafficTriage, trafficLevelFor } from './traffic-triage.js';

test('traffic classification preserves normal, interesting, suspicious, and critical thresholds', () => {
  assert.equal(trafficLevelFor({}), 'normal');
  assert.equal(trafficLevelFor({ severity: 'MEDIUM' }), 'interesting');
  assert.equal(trafficLevelFor({ events: 8 }), 'interesting');
  assert.equal(trafficLevelFor({ bytes: 1_048_576 }), 'interesting');
  assert.equal(trafficLevelFor({ severity: 'HIGH' }), 'suspicious');
  assert.equal(trafficLevelFor({ risk: 50 }), 'suspicious');
  assert.equal(trafficLevelFor({ severity: 'CRITICAL' }), 'critical');
  assert.equal(trafficLevelFor({ risk: 80 }), 'critical');
});

test('traffic summary counts each observed flow and its existing event count by level', () => {
  const { trafficSummary } = buildTrafficTriage({
    edges: [
      { level: 'normal', events: 2 },
      { level: 'interesting', events: 4 },
      { level: 'suspicious', events: 8 },
      { level: 'critical', events: 1 },
    ],
  });

  assert.deepEqual(trafficSummary, {
    normal: { flows: 1, events: 2 },
    interesting: { flows: 1, events: 4 },
    suspicious: { flows: 1, events: 8 },
    critical: { flows: 1, events: 1 },
  });
});

test('open incidents link only through suspicious alert or traffic hosts and keep their own Threat Family IDs', () => {
  const result = buildTrafficTriage({
    nodes: [
      { id: 'host-node-a', type: 'host', host_id: 'host-a' },
      { id: 'process-node-b', type: 'process', host_id: 'host-b' },
      { id: 'destination-b', type: 'destination' },
      { id: 'host-node-c', type: 'host', host_id: 'host-c' },
    ],
    edges: [{ source: 'process-node-b', target: 'destination-b', level: 'suspicious', events: 3 }],
    alerts: [
      { host_id: 'host-a', severity: 'HIGH', risk_score: 60 },
      { host_id: 'host-c', severity: 'LOW', risk_score: 10 },
    ],
    incidents: [
      { incident_id: 'inc-a', host_id: 'host-a', status: 'INVESTIGATING', threat_family_id: 'tf-a' },
      { incident_id: 'inc-b', host_id: 'host-b', status: 'NEW', threat_family_id: 'tf-b' },
      { incident_id: 'inc-closed', host_id: 'host-a', status: 'CLOSED', threat_family_id: 'tf-closed' },
      { incident_id: 'inc-self-only', host_id: 'host-c', status: 'NEW', severity: 'CRITICAL', threat_family_id: 'tf-self-only' },
      { incident_id: 'inc-unrelated', host_id: 'host-d', status: 'NEW', threat_family_id: 'tf-unrelated' },
    ],
  });

  assert.deepEqual(
    result.linkedIncidents.map(({ incident_id, threat_family_id }) => ({ incident_id, threat_family_id })),
    [
      { incident_id: 'inc-a', threat_family_id: 'tf-a' },
      { incident_id: 'inc-b', threat_family_id: 'tf-b' },
    ],
  );
});

test('an incident alone cannot classify its own host as suspicious traffic', () => {
  const result = buildTrafficTriage({
    nodes: [{ id: 'host-node', type: 'host', host_id: 'incident-only-host' }],
    incidents: [{ incident_id: 'inc-only', host_id: 'incident-only-host', status: 'NEW', severity: 'CRITICAL' }],
  });

  assert.deepEqual(result.linkedIncidents, []);
});
