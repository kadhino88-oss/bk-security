'use strict';

const fs = require('node:fs');
const path = require('node:path');

const dashboardSource = process.env.BK_SECURITY_DASHBOARD_DIR;
const documentationSource = process.env.BK_SECURITY_DOCUMENTATION_DIR;
const legalSource = process.env.BK_SECURITY_LEGAL_DIR;
const backendSource = process.env.BK_SECURITY_BACKEND_DIR;
const releaseManifest = process.env.BK_SECURITY_RELEASE_MANIFEST;
const installerOutput = process.env.BK_SECURITY_INSTALLER_OUTPUT;
for (const [label, value] of Object.entries({
  BK_SECURITY_DASHBOARD_DIR: dashboardSource,
  BK_SECURITY_DOCUMENTATION_DIR: documentationSource,
  BK_SECURITY_LEGAL_DIR: legalSource,
  BK_SECURITY_BACKEND_DIR: backendSource,
  BK_SECURITY_RELEASE_MANIFEST: releaseManifest,
  BK_SECURITY_INSTALLER_OUTPUT: installerOutput,
})) {
  if (!value || !fs.existsSync(value)) throw new Error(`${label} must point to a prepared release input.`);
}

const config = {
  appId: 'com.bkentreprise.bksecurity',
  productName: 'BK Security',
  asar: true,
  files: [
    'main.js', 'preload.js', 'security-policy.js', 'dashboard-url.js', 'backend-command.js',
    'backend-supervisor.js', 'runtime-log.js', 'integrity-manifest.js',
    'config.json', 'setup.html', 'package.json',
  ],
  extraResources: [
    { from: backendSource, to: 'backend', filter: ['**/*'] },
    { from: dashboardSource, to: 'dashboard/static', filter: ['**/*'] },
    { from: documentationSource, to: 'docs', filter: ['**/*'] },
    { from: legalSource, to: 'legal', filter: ['**/*'] },
    { from: releaseManifest, to: 'release-manifest.json' },
  ],
  directories: { output: installerOutput },
  win: {
    target: [{ target: 'nsis', arch: ['x64'] }],
    requestedExecutionLevel: 'requireAdministrator',
    artifactName: '${productName} Setup ${version}.${ext}',
  },
  nsis: {
    oneClick: false,
    perMachine: true,
    allowToChangeInstallationDirectory: true,
    createDesktopShortcut: true,
    createStartMenuShortcut: true,
    shortcutName: 'BK Security',
    deleteAppDataOnUninstall: false,
  },
};

const icon = path.join(__dirname, 'assets', 'icon.ico');
if (fs.existsSync(icon)) config.win.icon = icon;

module.exports = config;
