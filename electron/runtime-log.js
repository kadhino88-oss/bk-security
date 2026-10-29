'use strict';

const fs = require('node:fs');
const path = require('node:path');

const SAFE_DETAIL_KEYS = new Set(['code', 'signal', 'pid', 'version', 'buildId', 'retry', 'expected']);

class RuntimeLogger {
  constructor(directory, { filename = 'bk-security-runtime.jsonl', maxBytes = 1024 * 1024, backups = 3 } = {}) {
    this.directory = directory;
    this.file = path.join(directory, filename);
    this.maxBytes = Math.max(4096, Number(maxBytes) || 1024 * 1024);
    this.backups = Math.max(1, Math.min(5, Number(backups) || 3));
    fs.mkdirSync(directory, { recursive: true, mode: 0o700 });
  }

  write(level, event, details = {}) {
    const safeDetails = {};
    for (const [key, value] of Object.entries(details || {})) {
      if (!SAFE_DETAIL_KEYS.has(key)) continue;
      if (['string', 'number', 'boolean'].includes(typeof value)) {
        safeDetails[key] = String(value).slice(0, 128);
      }
    }
    const record = JSON.stringify({
      timestamp: new Date().toISOString(),
      level: ['info', 'warning', 'error'].includes(level) ? level : 'info',
      event: String(event).replace(/[^a-z0-9_.-]/gi, '_').slice(0, 80),
      details: safeDetails,
    }) + '\n';
    const bytes = Buffer.byteLength(record, 'utf8');
    try {
      const currentBytes = fs.existsSync(this.file) ? fs.statSync(this.file).size : 0;
      if (currentBytes + bytes > this.maxBytes) this._rotate();
      fs.appendFileSync(this.file, record, { encoding: 'utf8', mode: 0o600 });
    } catch (_error) {
      // Runtime diagnostics must never prevent startup or shutdown.
    }
  }

  _rotate() {
    for (let index = this.backups; index >= 1; index -= 1) {
      const source = index === 1 ? this.file : `${this.file}.${index - 1}`;
      const destination = `${this.file}.${index}`;
      if (!fs.existsSync(source)) continue;
      try { fs.rmSync(destination, { force: true }); } catch (_error) {}
      try { fs.renameSync(source, destination); } catch (_error) {}
    }
  }
}

module.exports = { RuntimeLogger };
