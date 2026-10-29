'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { RuntimeLogger } = require('../runtime-log');

test('runtime log rotates bounded operational records and drops sensitive fields', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'bk-security-log-'));
  try {
    const logger = new RuntimeLogger(root, { maxBytes: 4096, backups: 2 });
    for (let index = 0; index < 80; index += 1) {
      logger.write('info', 'backend_restarted', {
        version: '1.0.0', retry: index, password: 'must-not-be-written', token: 'must-not-be-written',
      });
    }
    assert.equal(fs.existsSync(`${logger.file}.1`), true);
    const files = [logger.file, `${logger.file}.1`, `${logger.file}.2`].filter(fs.existsSync);
    assert.equal(files.every(filename => fs.statSync(filename).size <= 4096), true);
    const contents = files.map(filename => fs.readFileSync(filename, 'utf8')).join('');
    assert.equal(contents.includes('must-not-be-written'), false);
    for (const line of fs.readFileSync(logger.file, 'utf8').trim().split('\n')) assert.doesNotThrow(() => JSON.parse(line));
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});
