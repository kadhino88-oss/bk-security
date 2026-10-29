'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { EventEmitter } = require('node:events');
const { BackendSupervisor } = require('../backend-supervisor');

class FakeChild extends EventEmitter {
  constructor() {
    super();
    this.pid = 4321;
    this.exitCode = null;
    this.killed = false;
  }

  kill() {
    this.killed = true;
    this.exitCode = 0;
    this.emit('close', 0, null);
    return true;
  }
}

test('backend supervisor waits for authenticated graceful close before returning', async () => {
  const child = new FakeChild();
  const supervisor = new BackendSupervisor({ spawnProcess: () => child });
  assert.equal(supervisor.start('backend.exe', [], {}).pid, 4321);
  child.emit('spawn');
  assert.equal(supervisor.running, true);
  let shutdownRequested = false;
  const stopped = await supervisor.stop(async () => {
    shutdownRequested = true;
    child.exitCode = 0;
    child.emit('close', 0, null);
  }, { graceMs: 50, forceMs: 10 });
  assert.equal(shutdownRequested, true);
  assert.equal(stopped, true);
  assert.equal(child.killed, false);
  assert.equal(supervisor.state, 'stopped');
  assert.equal(supervisor.running, false);
});

test('unexpected backend exit clears the stale child and allows a clean restart', () => {
  const children = [new FakeChild(), new FakeChild()];
  const exits = [];
  const supervisor = new BackendSupervisor({
    spawnProcess: () => children.shift(),
    onExit: exit => exits.push(exit),
  });
  const first = supervisor.start('backend.exe', [], {});
  first.emit('spawn');
  first.exitCode = 9;
  first.emit('close', 9, null);
  assert.equal(supervisor.running, false);
  assert.equal(supervisor.state, 'stopped');
  assert.equal(exits[0].expected, false);
  const second = supervisor.start('backend.exe', [], {});
  second.emit('spawn');
  assert.equal(supervisor.running, true);
});

test('backend supervisor force-stops only after graceful shutdown times out', async () => {
  const child = new FakeChild();
  const supervisor = new BackendSupervisor({ spawnProcess: () => child });
  supervisor.start('backend.exe', [], {});
  const stopped = await supervisor.stop(async () => {}, { graceMs: 5, forceMs: 20 });
  assert.equal(stopped, true);
  assert.equal(child.killed, true);
  assert.equal(supervisor.state, 'stopped');
});
