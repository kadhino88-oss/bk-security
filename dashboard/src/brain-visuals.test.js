import assert from 'node:assert/strict';
import test from 'node:test';
import { BINARY_GLYPH_COUNT, brainFlowDuration, brainSphereFlowPath, brainSpherePoint } from './brain-visuals.js';

test('Security Brain uses a dense binary field and places endpoints on the visible globe', () => {
  assert.equal(BINARY_GLYPH_COUNT, 840);
  for (const id of ['host-a', 'process-b', 'destination-c']) {
    const point = brainSpherePoint(id);
    const radius = Math.hypot(point.x - 230, point.y - 230);
    assert.ok(radius >= 150 && radius <= 205);
  }
});

test('observed network flows produce stable curved paths between their real endpoint IDs', () => {
  const edge = { id: 'flow-1', source: 'host-a', target: 'destination-c', level: 'interesting', events: 8 };
  const path = brainSphereFlowPath(edge);
  const from = brainSpherePoint(edge.source);
  const to = brainSpherePoint(edge.target);
  assert.match(path, /^M /);
  assert.ok(path.includes(`${from.x.toFixed(1)} ${from.y.toFixed(1)}`));
  assert.ok(path.endsWith(`${to.x.toFixed(1)} ${to.y.toFixed(1)}`));
  assert.equal(path, brainSphereFlowPath(edge));
});

test('flow markers move faster for higher severity and increased observed events', () => {
  const durations = ['normal', 'interesting', 'suspicious', 'critical'].map((level) =>
    brainFlowDuration({ level, events: 0 }),
  );
  assert.deepEqual([...durations].sort((a, b) => b - a), durations);
  assert.ok(brainFlowDuration({ level: 'normal', events: 32 }) < brainFlowDuration({ level: 'normal', events: 0 }));
});
