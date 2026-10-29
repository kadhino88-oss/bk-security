'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { verifyInstalledRelease } = require('../integrity-manifest');

function hash(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
}

function fixture() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'bk-security-integrity-'));
  const resources = path.join(root, 'resources');
  const app = path.join(root, 'app');
  const files = {
    'backend/bk-security-backend.exe': 'backend',
    'dashboard/static/index.html': 'dashboard',
    'dashboard/static/assets/main.js': 'asset',
    'docs/WINDOWS_PRODUCTION_SETUP.md': 'operator setup',
    'legal/NOTICE-ORIGINS.md': 'origin notice',
  };
  for (const [relative, value] of Object.entries(files)) {
    const destination = path.join(resources, ...relative.split('/'));
    fs.mkdirSync(path.dirname(destination), { recursive: true });
    fs.writeFileSync(destination, value);
  }
  fs.mkdirSync(app);
  fs.writeFileSync(path.join(app, 'main.js'), 'electron-main');
  const manifest = {
    schema_version: 1,
    version: '1.0.0',
    build_id: 'v1-test',
    app_id: 'com.bkentreprise.bksecurity',
    capture_mode_default: 'stopped',
    windows_response_enabled: false,
    resource_files: Object.fromEntries(Object.entries(files).map(([name, value]) => [name, hash(value)])),
    electron_files: { 'main.js': hash('electron-main') },
  };
  const manifestPath = path.join(resources, 'release-manifest.json');
  fs.writeFileSync(manifestPath, JSON.stringify(manifest));
  return { root, resources, app, manifestPath, manifest };
}

test('release manifest verifies version identity and critical packaged file hashes', () => {
  const item = fixture();
  try {
    const actual = verifyInstalledRelease({
      manifestPath: item.manifestPath,
      resourcesPath: item.resources,
      appPath: item.app,
      version: '1.0.0',
      appId: 'com.bkentreprise.bksecurity',
    });
    assert.equal(actual.build_id, 'v1-test');
  } finally {
    fs.rmSync(item.root, { recursive: true, force: true });
  }
});

test('release manifest rejects resource tampering, extra files and path traversal', () => {
  const item = fixture();
  try {
    fs.writeFileSync(path.join(item.resources, 'dashboard/static/index.html'), 'tampered');
    assert.throws(() => verifyInstalledRelease({
      manifestPath: item.manifestPath, resourcesPath: item.resources, appPath: item.app,
      version: '1.0.0', appId: 'com.bkentreprise.bksecurity',
    }), /integrity check failed/);
    item.manifest.resource_files['backend/../outside'] = hash('bad');
    fs.writeFileSync(item.manifestPath, JSON.stringify(item.manifest));
    assert.throws(() => verifyInstalledRelease({
      manifestPath: item.manifestPath, resourcesPath: item.resources, appPath: item.app,
      version: '1.0.0', appId: 'com.bkentreprise.bksecurity',
    }), /inventory|escapes/);
  } finally {
    fs.rmSync(item.root, { recursive: true, force: true });
  }
});

test('release manifest rejects a mismatched package version and enabled Windows response', () => {
  const item = fixture();
  try {
    assert.throws(() => verifyInstalledRelease({
      manifestPath: item.manifestPath, resourcesPath: item.resources, appPath: item.app,
      version: '2.0.0', appId: 'com.bkentreprise.bksecurity',
    }), /identity/);
    item.manifest.windows_response_enabled = true;
    fs.writeFileSync(item.manifestPath, JSON.stringify(item.manifest));
    assert.throws(() => verifyInstalledRelease({
      manifestPath: item.manifestPath, resourcesPath: item.resources, appPath: item.app,
      version: '1.0.0', appId: 'com.bkentreprise.bksecurity',
    }), /policy/);
  } finally {
    fs.rmSync(item.root, { recursive: true, force: true });
  }
});
