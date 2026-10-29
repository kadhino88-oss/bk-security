'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('path');
const { pathToFileURL } = require('url');
const { isTrustedNavigation } = require('../security-policy');
const { resolveBackendCommand, backendEnvironment } = require('../backend-command');

const origin = 'http://127.0.0.1:8000';
const fallback = path.resolve(__dirname, '../../dashboard/static/index.html');

test('allows the configured local SOC origin', () => {
  assert.equal(isTrustedNavigation(`${origin}/`, origin, fallback), true);
  assert.equal(isTrustedNavigation(`${origin}/api/v1/overview`, origin, fallback), true);
});

test('rejects external origins, alternate ports and embedded credentials', () => {
  assert.equal(isTrustedNavigation('https://example.org/', origin, fallback), false);
  assert.equal(isTrustedNavigation('http://127.0.0.1:8001/', origin, fallback), false);
  assert.equal(isTrustedNavigation('http://admin@127.0.0.1:8000/', origin, fallback), false);
});

test('allows only the local dashboard fallback file', () => {
  assert.equal(isTrustedNavigation(pathToFileURL(fallback).href, origin, fallback), true);
  assert.equal(isTrustedNavigation(pathToFileURL(path.resolve('README.md')).href, origin, fallback), false);
});

test('packaged Electron resolves its colocated backend executable', () => {
  const result = resolveBackendCommand({
    isPackaged: true,
    resourcesPath: 'C:/Program Files/BK Security/resources',
    env: { BK_SECURITY_PYTHON: 'python-custom' },
    config: { command: 'python', args: ['-m', 'bk_security.desktop_backend'] },
    developmentRoot: 'C:/dev/bk-security',
  });
  assert.match(result.command, /resources[\\/]backend[\\/]bk-security-backend\.exe$/i);
  assert.deepEqual(result.args, []);
  assert.equal(result.packaged, true);
});

test('packaged backend runs fail-closed production mode without inventing secrets', () => {
  const result = backendEnvironment({
    isPackaged: true, env: {}, host: '127.0.0.1', port: 8000,
  });
  assert.equal(result.BK_SECURITY_ENV, 'production');
  assert.equal(result.BK_SECURITY_HOST, '127.0.0.1');
  assert.equal(result.BK_SECURITY_PORT, '8000');
  assert.equal(result.BK_SECURITY_CAPTURE_MODE, 'stopped');
  assert.equal(result.BK_SECURITY_WINDOWS_RESPONSE, '0');
  assert.equal(result.BK_SECURITY_CORS_ORIGINS, '');
  assert.equal('BK_SECURITY_AUTH_SECRET' in result, false);
  assert.equal('BK_SECURITY_ADMIN_PASSWORD' in result, false);
});

test('packaged environment filters inherited secrets and requires an interface for live capture', () => {
  const result = backendEnvironment({
    isPackaged: true,
    env: {
      BK_SECURITY_ADMIN_PASSWORD: 'must-not-inherit',
      BK_SECURITY_INTERNAL_SHUTDOWN_TOKEN: 'must-not-inherit',
      BK_SECURITY_CAPTURE_MODE: 'stopped',
      BK_SECURITY_RESPONSE_ENABLED: '1',
      ProgramFiles: 'C:/Program Files',
      ProgramData: 'must-not-inherit',
    },
    host: '127.0.0.1', port: 8000, version: '1.0.0', buildId: 'v1-test',
    databasePath: 'C:/Users/test/AppData/Roaming/BK Security/security.db',
    shutdownToken: 'runtime-only-token',
  });
  assert.equal(result.BK_SECURITY_VERSION, '1.0.0');
  assert.equal(result.BK_SECURITY_BUILD_ID, 'v1-test');
  assert.equal(result.BK_SECURITY_DB.endsWith('security.db'), true);
  assert.equal(result.BK_SECURITY_INTERNAL_SHUTDOWN_TOKEN, 'runtime-only-token');
  assert.equal(result.BK_SECURITY_WINDOWS_RESPONSE, '0');
  assert.equal(result.ProgramFiles, 'C:/Program Files');
  assert.equal('ProgramData' in result, false);
  assert.equal('BK_SECURITY_ADMIN_PASSWORD' in result, false);
  assert.equal('BK_SECURITY_RESPONSE_ENABLED' in result, false);
  assert.throws(() => backendEnvironment({
    isPackaged: true, env: { BK_SECURITY_CAPTURE_MODE: 'live' }, host: '127.0.0.1', port: 8000,
  }), /explicitly selected/);
  assert.doesNotThrow(() => backendEnvironment({
    isPackaged: true,
    env: { BK_SECURITY_CAPTURE_MODE: 'live', BK_SECURITY_CAPTURE_INTERFACE: '\\Device\\NPF_Loopback' },
    host: '127.0.0.1', port: 8000,
  }));
  const staleSimulation = backendEnvironment({
    isPackaged: true,
    env: { BK_SECURITY_CAPTURE_MODE: 'simulation', BK_SECURITY_CAPTURE_SCENARIO: 'PORT_SCAN' },
    host: '127.0.0.1', port: 8000,
  });
  assert.equal(staleSimulation.BK_SECURITY_CAPTURE_MODE, 'stopped');
  assert.equal('BK_SECURITY_CAPTURE_SCENARIO' in staleSimulation, false);
});

test('development Electron keeps the configurable Python launch path', () => {
  const result = resolveBackendCommand({
    isPackaged: false, resourcesPath: '', env: { BK_SECURITY_PYTHON: 'python-custom' },
    config: { command: 'python', args: ['-m', 'bk_security.desktop_backend'] },
    developmentRoot: 'C:/dev/bk-security',
  });
  assert.equal(result.command, 'python-custom');
  assert.deepEqual(result.args, ['-m', 'bk_security.desktop_backend']);
  assert.equal(result.cwd, 'C:/dev/bk-security');
  assert.equal(result.packaged, false);
  assert.equal(backendEnvironment({ isPackaged: false, env: {}, host: '127.0.0.1', port: 8001 }).BK_SECURITY_CAPTURE_MODE, 'stopped');
  assert.equal(backendEnvironment({
    isPackaged: false, env: { BK_SECURITY_ENV: 'test' }, host: '127.0.0.1', port: 8001,
  }).BK_SECURITY_ENV, 'test');
});
