'use strict';

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

function sha256(filename) {
  return crypto.createHash('sha256').update(fs.readFileSync(filename)).digest('hex');
}

function containedPath(root, relative) {
  if (typeof relative !== 'string' || !relative || path.isAbsolute(relative)) {
    throw new Error('Release manifest contains an invalid path.');
  }
  const absoluteRoot = path.resolve(root);
  const absoluteFile = path.resolve(absoluteRoot, relative);
  if (absoluteFile !== absoluteRoot && !absoluteFile.startsWith(`${absoluteRoot}${path.sep}`)) {
    throw new Error('Release manifest path escapes its package directory.');
  }
  return absoluteFile;
}

function verifyMap(root, files, group) {
  if (!files || typeof files !== 'object' || Array.isArray(files) || Object.keys(files).length === 0) {
    throw new Error(`Release manifest has no ${group} inventory.`);
  }
  for (const [relative, expected] of Object.entries(files)) {
    if (!/^[a-f0-9]{64}$/i.test(expected)) throw new Error(`Release manifest has an invalid ${group} digest.`);
    const absolute = containedPath(root, relative);
    if (!fs.statSync(absolute).isFile() || sha256(absolute) !== expected.toLowerCase()) {
      throw new Error(`Installed ${group} integrity check failed: ${relative}`);
    }
  }
}

function inventory(directory, prefix = '') {
  const found = [];
  for (const item of fs.readdirSync(directory, { withFileTypes: true })) {
    const relative = prefix ? `${prefix}/${item.name}` : item.name;
    const absolute = path.join(directory, item.name);
    if (item.isSymbolicLink()) throw new Error(`Installed package contains a symbolic link: ${relative}`);
    if (item.isDirectory()) found.push(...inventory(absolute, relative));
    else if (item.isFile()) found.push(relative.replace(/\\/g, '/'));
  }
  return found.sort();
}

function verifyResourceInventory(root, files) {
  const expected = Object.keys(files).sort();
  const actual = ['backend', 'dashboard/static', 'docs', 'legal'].flatMap(prefix => {
    const directory = path.join(root, ...prefix.split('/'));
    if (!fs.existsSync(directory)) throw new Error(`Installed resource directory is missing: ${prefix}`);
    return inventory(directory).map(relative => `${prefix}/${relative}`);
  }).sort();
  if (JSON.stringify(actual) !== JSON.stringify(expected)) {
    throw new Error('Installed backend/dashboard inventory does not match the release manifest.');
  }
}

function verifyInstalledRelease({ manifestPath, resourcesPath, appPath, version, appId }) {
  const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
  if (manifest.schema_version !== 1 || manifest.version !== version || manifest.app_id !== appId) {
    throw new Error('Installed BK Security release identity does not match the package.');
  }
  if (typeof manifest.build_id !== 'string' || !manifest.build_id || manifest.windows_response_enabled !== false) {
    throw new Error('Installed BK Security release policy is invalid.');
  }
  if (manifest.capture_mode_default !== 'stopped') {
    throw new Error('Installed BK Security capture default is invalid.');
  }
  verifyResourceInventory(resourcesPath, manifest.resource_files);
  verifyMap(resourcesPath, manifest.resource_files, 'resource');
  verifyMap(appPath, manifest.electron_files, 'Electron');
  return manifest;
}

module.exports = { containedPath, sha256, verifyInstalledRelease, verifyResourceInventory };
