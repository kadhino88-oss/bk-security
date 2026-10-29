'use strict';

const { app, BrowserWindow, ipcMain, safeStorage, dialog } = require('electron');
const { spawn } = require('child_process');
const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { isTrustedNavigation } = require('./security-policy');
const { resolveBackendCommand, backendEnvironment } = require('./backend-command');
const { BackendSupervisor } = require('./backend-supervisor');
const { RuntimeLogger } = require('./runtime-log');
const { verifyInstalledRelease } = require('./integrity-manifest');
const { buildDashboardUrl } = require('./dashboard-url');

const appRoot = app.getAppPath();
const APP_ID = 'com.bkentreprise.bksecurity';
const cfg = JSON.parse(fs.readFileSync(path.join(appRoot, 'config.json'), 'utf8'));
const host = cfg.backend.host;
const port = Number(cfg.backend.port);
if (!['127.0.0.1', 'localhost'].includes(host) || !Number.isInteger(port) || port < 1024 || port > 65535) {
  throw new Error('BK Security desktop backend must use a valid loopback host and port.');
}

const trustedOrigin = `http://${host}:${port}`;
const developmentRoot = path.resolve(__dirname, '..');
const fallbackDashboard = app.isPackaged
  ? path.join(process.resourcesPath, 'dashboard', 'static', 'index.html')
  : path.resolve(developmentRoot, 'dashboard', 'static', 'index.html');
const setupPage = path.join(appRoot, 'setup.html');
const userData = app.getPath('userData');
const credentialFile = path.join(userData, 'credentials.dat');

let mainWindow = null;
let runtimeLogger = null;
let releaseManifest = null;
let activeShutdownToken = '';
let applicationQuitting = false;
let quitAllowed = false;
let quitPromise = null;
let restartTimer = null;
const restartTimes = [];

function log(level, event, details = {}) {
  if (runtimeLogger) runtimeLogger.write(level, event, details);
}

let scheduleBackendRestart = () => {};
const backendSupervisor = new BackendSupervisor({
  logger: (event, details) => log(event.includes('error') || event.includes('failed') ? 'warning' : 'info', event, details),
  onExit: result => {
    if (!result.expected && !applicationQuitting) scheduleBackendRestart(result);
  },
});

function validateCredentials(credentials) {
  const values = [
    credentials.adminPassword,
    credentials.analystPassword,
    credentials.viewerPassword,
    credentials.approverPassword,
    credentials.responderPassword,
  ];
  if (values.some(value => typeof value !== 'string' || Buffer.byteLength(value, 'utf8') < 12 || new Set(value).size < 6 || value.endsWith('-dev-only'))) {
    throw new Error('Each of the five role passwords must contain at least 12 characters and at least 6 distinct characters.');
  }
  if (new Set(values).size !== values.length) {
    throw new Error('The five role passwords must be different.');
  }
  if (typeof credentials.authSecret !== 'string' || Buffer.byteLength(credentials.authSecret, 'utf8') < 32) {
    throw new Error('Authentication secret is invalid.');
  }
}

function inspectCredentialStore() {
  if (!fs.existsSync(credentialFile)) return { status: 'missing' };
  if (!safeStorage.isEncryptionAvailable()) return { status: 'unavailable' };
  try {
    const raw = fs.readFileSync(credentialFile);
    const credentials = JSON.parse(safeStorage.decryptString(raw));
    validateCredentials(credentials);
    return { status: 'valid', credentials };
  } catch (error) {
    return { status: 'invalid', error };
  }
}

function generateAuthSecret() {
  return crypto.randomBytes(48).toString('base64url');
}

function encryptCredentials(credentials) {
  if (!safeStorage.isEncryptionAvailable()) throw new Error('Windows secure storage is unavailable.');
  return safeStorage.encryptString(JSON.stringify(credentials));
}

function decryptCredentials() {
  const inspected = inspectCredentialStore();
  if (inspected.status === 'missing') return null;
  if (inspected.status === 'unavailable') throw new Error('Windows secure storage is unavailable.');
  if (inspected.status === 'invalid') throw new Error('The BK Security credential store is invalid or corrupted.');
  return inspected.credentials;
}

function saveCredentials(credentials) {
  const encrypted = encryptCredentials(credentials);
  fs.mkdirSync(path.dirname(credentialFile), { recursive: true });
  const temporary = `${credentialFile}.tmp`;
  fs.writeFileSync(temporary, encrypted, { mode: 0o600 });
  fs.renameSync(temporary, credentialFile);
}

function credentialsFromEnvironment() {
  const env = process.env;
  const names = {
    adminPassword: 'BK_SECURITY_ADMIN_PASSWORD',
    analystPassword: 'BK_SECURITY_ANALYST_PASSWORD',
    viewerPassword: 'BK_SECURITY_VIEWER_PASSWORD',
    approverPassword: 'BK_SECURITY_APPROVER_PASSWORD',
    responderPassword: 'BK_SECURITY_RESPONDER_PASSWORD',
    authSecret: 'BK_SECURITY_AUTH_SECRET',
  };
  if (Object.values(names).every(name => env[name])) {
    const credentials = Object.fromEntries(Object.entries(names).map(([key, name]) => [key, env[name]]));
    validateCredentials(credentials);
    return credentials;
  }
  return null;
}

function loadCredentials() {
  const stored = decryptCredentials();
  if (stored) {
    validateCredentials(stored);
    return stored;
  }
  const migrated = credentialsFromEnvironment();
  if (migrated) {
    saveCredentials(migrated);
    return migrated;
  }
  return null;
}

function credentialsExist() {
  const inspected = inspectCredentialStore();
  if (inspected.status === 'valid') return true;
  if (inspected.status === 'missing') return false;
  log('warning', 'credential_store_unavailable', { status: inspected.status });
  return false;
}

function createSetupWindow() {
  mainWindow = new BrowserWindow({
    width: 720,
    height: 820,
    minWidth: 620,
    minHeight: 720,
    resizable: true,
    backgroundColor: '#090909',
    webPreferences: {
      preload: path.join(appRoot, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true,
    },
  });
  mainWindow.webContents.setWindowOpenHandler(() => ({ action: 'deny' }));
  mainWindow.on('closed', () => { mainWindow = null; });
  mainWindow.loadFile(setupPage);
}

function createMainWindow() {
  mainWindow = new BrowserWindow({
    width: 1500,
    height: 950,
    minWidth: 1100,
    minHeight: 700,
    backgroundColor: '#090909',
    webPreferences: {
      preload: path.join(appRoot, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true,
    },
  });
  mainWindow.webContents.setWindowOpenHandler(() => ({ action: 'deny' }));
  mainWindow.webContents.on('will-navigate', (event, targetUrl) => {
    if (!isTrustedNavigation(targetUrl, trustedOrigin, fallbackDashboard)) event.preventDefault();
  });
  mainWindow.webContents.on('will-attach-webview', event => event.preventDefault());
  mainWindow.on('closed', () => { mainWindow = null; });
  return mainWindow;
}

function verifyPackagedIdentity() {
  if (!app.isPackaged) return;
  releaseManifest = verifyInstalledRelease({
    manifestPath: path.join(process.resourcesPath, 'release-manifest.json'),
    resourcesPath: process.resourcesPath,
    appPath: appRoot,
    version: app.getVersion(),
    appId: APP_ID,
  });
}

function backendCommand() {
  return resolveBackendCommand({
    isPackaged: app.isPackaged,
    resourcesPath: process.resourcesPath,
    env: process.env,
    config: cfg.backend,
    developmentRoot,
  });
}

function startBackend() {
  if (backendSupervisor.running) return backendSupervisor.child;
  const credentials = loadCredentials();
  if (!credentials) throw new Error('BK Security has not been initialized.');

  const command = backendCommand();
  activeShutdownToken = crypto.randomBytes(32).toString('hex');
  const env = backendEnvironment({
    isPackaged: command.packaged,
    env: process.env,
    host,
    port,
    version: app.getVersion(),
    buildId: releaseManifest ? releaseManifest.build_id : 'development',
    databasePath: path.join(userData, 'security.db'),
    shutdownToken: activeShutdownToken,
  });
  env.BK_SECURITY_AUTH_SECRET = credentials.authSecret;
  env.BK_SECURITY_ADMIN_PASSWORD = credentials.adminPassword;
  env.BK_SECURITY_ANALYST_PASSWORD = credentials.analystPassword;
  env.BK_SECURITY_VIEWER_PASSWORD = credentials.viewerPassword;
  env.BK_SECURITY_APPROVER_PASSWORD = credentials.approverPassword;
  env.BK_SECURITY_RESPONDER_PASSWORD = credentials.responderPassword;

  const child = backendSupervisor.start(command.command, command.args, {
    cwd: command.cwd,
    windowsHide: true,
    stdio: ['ignore', 'pipe', 'pipe'],
    env,
  });
  // Drain pipes without retaining backend event data, credentials or request details in Electron logs.
  child.stdout?.on('data', () => {});
  let stderrNoted = false;
  child.stderr?.on('data', () => {
    if (!stderrNoted) {
      stderrNoted = true;
      log('warning', 'backend_emitted_stderr');
    }
  });
  return child;
}

function requestBackend(method, route, shutdownToken = '') {
  return new Promise(resolve => {
    const request = http.request({
      hostname: host,
      port,
      path: route,
      method,
      headers: shutdownToken ? { 'X-BK-Internal-Shutdown': shutdownToken } : {},
      timeout: 1500,
    }, response => {
      let body = '';
      response.setEncoding('utf8');
      response.on('data', chunk => {
        body += chunk;
        if (body.length > 65536) request.destroy();
      });
      response.on('end', () => {
        try {
          resolve({ statusCode: response.statusCode, body: JSON.parse(body) });
        } catch (_error) {
          resolve(null);
        }
      });
    });
    request.on('timeout', () => request.destroy());
    request.on('error', () => resolve(null));
    request.end();
  });
}

async function checkBackend() {
  const response = await requestBackend('GET', '/health');
  if (!response || response.statusCode !== 200) return null;
  const expectedBuildId = releaseManifest ? releaseManifest.build_id : 'development';
  const health = response.body;
  if (
    health.status !== 'ok'
    || health.product !== 'BK Security'
    || health.version !== app.getVersion()
    || health.build_id !== expectedBuildId
  ) return null;
  return health;
}

async function waitForBackend(timeoutMs = 30000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const health = await checkBackend();
    if (health) return health;
    await new Promise(resolve => setTimeout(resolve, 250));
  }
  throw new Error(`BK Security backend identity check timed out on ${host}:${port}.`);
}

async function requestGracefulBackendStop(token) {
  const response = await requestBackend('POST', '/internal/shutdown', token);
  if (!response || response.statusCode !== 200 || response.body.status !== 'shutdown_requested') {
    throw new Error('Authenticated backend shutdown request failed.');
  }
}

async function stopBackend() {
  const token = activeShutdownToken;
  const stopped = await backendSupervisor.stop(
    () => requestGracefulBackendStop(token),
    { graceMs: 8000, forceMs: 2000 },
  );
  activeShutdownToken = '';
  if (!stopped) log('error', 'backend_did_not_close_after_force_stop');
  return stopped;
}

scheduleBackendRestart = result => {
  if (applicationQuitting || restartTimer) return;
  const now = Date.now();
  while (restartTimes.length && now - restartTimes[0] > 60000) restartTimes.shift();
  if (restartTimes.length >= 3) {
    log('error', 'backend_restart_limit_reached', { code: result.code, signal: result.signal });
    if (mainWindow && !mainWindow.isDestroyed()) {
      dialog.showMessageBox(mainWindow, {
        type: 'error',
        title: 'BK Security - Backend',
        message: 'Le backend s’est arrêté plusieurs fois.',
        detail: 'Redémarrez BK Security et consultez le journal local de diagnostic.',
      });
    }
    return;
  }
  const retry = restartTimes.length;
  restartTimes.push(now);
  const delay = [500, 2000, 5000][retry];
  restartTimer = setTimeout(async () => {
    restartTimer = null;
    if (applicationQuitting) return;
    try {
      startBackend();
      await waitForBackend();
      log('info', 'backend_restarted', { retry, version: app.getVersion(), buildId: releaseManifest?.build_id || 'development' });
      if (mainWindow && !mainWindow.isDestroyed()) await mainWindow.loadURL(buildDashboardUrl(trustedOrigin, releaseManifest?.build_id));
    } catch (_error) {
      log('warning', 'backend_restart_attempt_failed', { retry });
      await stopBackend();
      scheduleBackendRestart({ code: null, signal: null });
    }
  }, delay);
};

ipcMain.handle('backend:status', () => ({
  running: backendSupervisor.running,
  state: backendSupervisor.state,
  host,
  port,
  version: app.getVersion(),
  buildId: releaseManifest ? releaseManifest.build_id : 'development',
}));

ipcMain.handle('backend:restart', async () => {
  await stopBackend();
  startBackend();
  const health = await waitForBackend();
  return { running: true, version: health.version, buildId: health.build_id };
});

ipcMain.handle('credentials:status', () => ({ configured: credentialsExist() }));

ipcMain.handle('credentials:initialize', async (_event, input) => {
  if (!input || typeof input !== 'object') throw new Error('Invalid initialization request.');
  const storeStatus = inspectCredentialStore();
  if (storeStatus.status !== 'missing') {
    if (storeStatus.status === 'unavailable') {
      throw new Error('Windows secure storage is temporarily unavailable. No credential data was changed.');
    }
    if (storeStatus.status === 'valid') {
      throw new Error('BK Security est deja initialise. Utilisez le mode reparation pour modifier les identifiants.');
    }
    throw new Error('Le coffre des identifiants existe mais est illisible. Aucune donnée n’a été écrasée. Utilisez explicitement le mode réparation.');
  }
  const credentials = {
    adminPassword: String(input.adminPassword || ''),
    analystPassword: String(input.analystPassword || ''),
    viewerPassword: String(input.viewerPassword || ''),
    approverPassword: String(input.approverPassword || ''),
    responderPassword: String(input.responderPassword || ''),
    authSecret: generateAuthSecret(),
  };
  validateCredentials(credentials);
  saveCredentials(credentials);
  try {
    startBackend();
    await waitForBackend();
    if (mainWindow && !mainWindow.isDestroyed()) await mainWindow.loadURL(buildDashboardUrl(trustedOrigin, releaseManifest?.build_id));
  } catch (_error) {
    await stopBackend();
    log('error', 'backend_start_after_initialization_failed');
    throw new Error('Les identifiants sont stockes de façon securisee, mais le backend n’a pas demarre. Redemarrez BK Security et consultez le journal local.');
  }
  log('info', 'credentials_initialized', { version: app.getVersion() });
  return { configured: true, authSecretGenerated: true };
});

ipcMain.handle('credentials:repair', async () => {
  await stopBackend();
  const inspected = inspectCredentialStore();
  if (inspected.status === 'unavailable') {
    throw new Error('Windows secure storage is unavailable. The existing credential store was left untouched.');
  }
  if (inspected.status !== 'missing') {
    const backup = `${credentialFile}.backup-${Date.now()}`;
    fs.renameSync(credentialFile, backup);
    log('warning', 'credential_store_backed_up_for_repair', { status: inspected.status });
  }
  if (mainWindow && !mainWindow.isDestroyed()) await mainWindow.loadFile(setupPage);
  return { configured: false };
});

async function launchApplication() {
  if (process.argv.includes('--repair')) {
    createSetupWindow();
    return;
  }
  let credentials;
  try {
    credentials = loadCredentials();
  } catch (_error) {
    log('error', 'credential_store_error');
    await dialog.showMessageBox({
      type: 'error',
      title: 'BK Security',
      message: 'Impossible de lire la configuration de sécurité.',
      detail: 'Utilisez le mode réparation --repair ou restaurez le coffre sécurisé Windows.',
    });
    createSetupWindow();
    return;
  }
  if (!credentials) {
    createSetupWindow();
    return;
  }

  createMainWindow();
  try {
    startBackend();
    await waitForBackend();
    await mainWindow.loadURL(buildDashboardUrl(trustedOrigin, releaseManifest?.build_id));
    log('info', 'desktop_started', { version: app.getVersion(), buildId: releaseManifest?.build_id || 'development' });
  } catch (_error) {
    await stopBackend();
    log('error', 'backend_startup_failed');
    await dialog.showMessageBox({
      type: 'error',
      title: 'BK Security - Backend',
      message: 'Le moteur de sécurité n’a pas démarré.',
      detail: 'Vérifiez la disponibilité du port local et le journal de diagnostic BK Security.',
    });
    await mainWindow.loadFile(fallbackDashboard);
  }
}

app.whenReady().then(async () => {
  try {
    runtimeLogger = new RuntimeLogger(userData, { filename: 'bk-security-runtime.jsonl' });
  } catch (_error) {
    runtimeLogger = null;
  }
  try {
    verifyPackagedIdentity();
    log('info', 'package_integrity_verified', { version: app.getVersion(), buildId: releaseManifest?.build_id || 'development' });
    await launchApplication();
  } catch (_error) {
    log('error', 'package_integrity_failed');
    await dialog.showMessageBox({
      type: 'error',
      title: 'BK Security - Intégrité',
      message: 'Les fichiers de BK Security ne correspondent pas au manifeste de version.',
      detail: 'Réinstallez le package depuis une source de confiance.',
    });
    app.quit();
  }
}).catch(() => app.quit());

app.on('before-quit', event => {
  if (quitAllowed) return;
  event.preventDefault();
  if (quitPromise) return;
  applicationQuitting = true;
  if (restartTimer) clearTimeout(restartTimer);
  log('info', 'desktop_shutdown_started');
  quitPromise = stopBackend().finally(() => {
    quitAllowed = true;
    app.quit();
  });
});

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') app.quit();
});
