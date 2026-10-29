'use strict';

const { spawn } = require('node:child_process');

class BackendSupervisor {
  constructor({ spawnProcess = spawn, onExit = () => {}, logger = () => {} } = {}) {
    this.spawnProcess = spawnProcess;
    this.onExit = onExit;
    this.logger = logger;
    this.child = null;
    this.state = 'stopped';
    this.closed = Promise.resolve({ closed: true, code: null, signal: null });
  }

  get running() {
    return Boolean(this.child) && (this.state === 'starting' || this.state === 'running');
  }

  start(command, args, options) {
    if (this.running) return this.child;
    if (this.state === 'stopping') throw new Error('Backend shutdown is still in progress.');

    const child = this.spawnProcess(command, args, options);
    this.child = child;
    this.state = 'starting';
    let resolveClosed;
    let settled = false;
    this.closed = new Promise(resolve => { resolveClosed = resolve; });

    child.once('spawn', () => {
      if (this.child === child && this.state === 'starting') this.state = 'running';
      this.logger('backend_spawned', { pid: child.pid });
    });

    child.once('error', error => {
      if (this.child === child) this.state = 'failed';
      this.logger('backend_spawn_error', { code: error && error.code });
    });

    child.once('close', (code, signal) => {
      const expected = this.state === 'stopping';
      if (this.child === child) {
        this.child = null;
        this.state = 'stopped';
      }
      const result = { closed: true, code, signal };
      if (!settled) {
        settled = true;
        resolveClosed(result);
      }
      this.logger('backend_closed', { code, signal, expected });
      this.onExit({ ...result, expected });
    });

    return child;
  }

  async stop(requestShutdown, { graceMs = 5000, forceMs = 1500 } = {}) {
    const child = this.child;
    if (!child) {
      this.state = 'stopped';
      return true;
    }
    if (this.state === 'stopping') return this._waitForClose(this.closed, graceMs + forceMs);

    this.state = 'stopping';
    try {
      await requestShutdown(child);
    } catch (_error) {
      this.logger('backend_graceful_shutdown_unavailable', {});
    }

    if (await this._waitForClose(this.closed, graceMs)) return true;
    if (this.child === child && child.exitCode == null) {
      try {
        child.kill();
        this.logger('backend_force_stop_requested', {});
      } catch (_error) {
        this.logger('backend_force_stop_failed', {});
      }
    }
    return this._waitForClose(this.closed, forceMs);
  }

  async _waitForClose(closed, timeoutMs) {
    let timer;
    const timeout = new Promise(resolve => {
      timer = setTimeout(() => resolve(false), timeoutMs);
    });
    const result = await Promise.race([closed.then(() => true), timeout]);
    clearTimeout(timer);
    return result;
  }
}

module.exports = { BackendSupervisor };
