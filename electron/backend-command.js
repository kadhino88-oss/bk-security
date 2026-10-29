'use strict';

const path = require('path');

function resolveBackendCommand({ isPackaged, resourcesPath, env, config, developmentRoot }) {
  if (isPackaged) {
    return {
      command: path.join(resourcesPath, 'backend', 'bk-security-backend.exe'),
      args: [],
      cwd: path.join(resourcesPath, 'backend'),
      packaged: true,
    };
  }
  return {
    command: env.BK_SECURITY_PYTHON || config.command,
    args: [...(config.args || [])],
    cwd: developmentRoot,
    packaged: false,
  };
}

function backendEnvironment({
  isPackaged, env, host, port, version = '1.0.0', buildId = 'development',
  databasePath = '', shutdownToken = '',
}) {
  if (!isPackaged) {
    const captureMode = String(env.BK_SECURITY_CAPTURE_MODE || 'stopped').toLowerCase();
    const captureInterface = String(env.BK_SECURITY_CAPTURE_INTERFACE || '').trim();
    if (!['live', 'simulation', 'stopped'].includes(captureMode)) {
      throw new Error('BK_SECURITY_CAPTURE_MODE must be live, simulation or stopped.');
    }
    if (captureMode === 'live' && !captureInterface) {
      throw new Error('Live capture requires an explicitly selected BK_SECURITY_CAPTURE_INTERFACE.');
    }
    return {
      ...env,
      BK_SECURITY_ENV: env.BK_SECURITY_ENV || 'development',
      BK_SECURITY_HOST: host,
      BK_SECURITY_PORT: String(port),
      BK_SECURITY_CAPTURE_MODE: captureMode,
      BK_SECURITY_CAPTURE_INTERFACE: captureInterface,
      BK_SECURITY_WINDOWS_RESPONSE: '0',
    };
  }

  const safeEnvironment = {};
  for (const name of [
    'PATH', 'Path', 'SystemRoot', 'WINDIR', 'TEMP', 'TMP', 'LOCALAPPDATA',
    'APPDATA', 'USERPROFILE', 'HOMEDRIVE', 'HOMEPATH', 'ProgramFiles',
  ]) {
    if (env[name] !== undefined) safeEnvironment[name] = env[name];
  }

  for (const name of [
    'BK_SECURITY_CAPTURE_MODE', 'BK_SECURITY_CAPTURE_INTERFACE',
    'BK_SECURITY_CAPTURE_SCENARIO', 'BK_SECURITY_MAX_EVENTS_PER_SECOND',
    'BK_SECURITY_MAX_REQUEST_BYTES', 'BK_SECURITY_CORS_ORIGINS',
  ]) {
    if (env[name] !== undefined) safeEnvironment[name] = env[name];
  }
  delete safeEnvironment.BK_SECURITY_CAPTURE_SCENARIO;

  const configuredCaptureMode = String(env.BK_SECURITY_CAPTURE_MODE || 'stopped').toLowerCase();
  const captureMode = configuredCaptureMode === 'simulation' ? 'stopped' : configuredCaptureMode;
  const captureInterface = String(env.BK_SECURITY_CAPTURE_INTERFACE || '').trim();
  if (!['live', 'stopped'].includes(captureMode)) {
    throw new Error('Packaged BK_SECURITY_CAPTURE_MODE must be live or stopped.');
  }
  if (captureMode === 'live' && !captureInterface) {
    throw new Error('Live capture requires an explicitly selected BK_SECURITY_CAPTURE_INTERFACE.');
  }

  return {
    ...safeEnvironment,
    BK_SECURITY_ENV: 'production',
    BK_SECURITY_HOST: host,
    BK_SECURITY_PORT: String(port),
    BK_SECURITY_VERSION: String(version),
    BK_SECURITY_BUILD_ID: String(buildId),
    BK_SECURITY_CAPTURE_MODE: captureMode,
    BK_SECURITY_CAPTURE_INTERFACE: captureInterface,
    BK_SECURITY_CORS_ORIGINS: env.BK_SECURITY_CORS_ORIGINS || '',
    BK_SECURITY_WINDOWS_RESPONSE: '0',
    BK_SECURITY_INTERNAL_SHUTDOWN_TOKEN: String(shutdownToken),
    ...(databasePath ? { BK_SECURITY_DB: String(databasePath) } : {}),
  };
}

module.exports = { resolveBackendCommand, backendEnvironment };
