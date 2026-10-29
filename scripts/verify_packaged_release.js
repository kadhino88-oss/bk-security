'use strict';

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const asar = require(path.join(__dirname, '..', 'electron', 'node_modules', '@electron', 'asar'));

function digest(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
}

function inventory(directory, prefix = '') {
  const found = [];
  for (const item of fs.readdirSync(directory, { withFileTypes: true })) {
    const relative = prefix ? `${prefix}/${item.name}` : item.name;
    const absolute = path.join(directory, item.name);
    if (item.isSymbolicLink()) throw new Error(`Package contains a symbolic link: ${relative}`);
    if (item.isDirectory()) found.push(...inventory(absolute, relative));
    else if (item.isFile()) found.push(relative.replace(/\\/g, '/'));
  }
  return found.sort();
}

function verifyResources(resourcesRoot, manifest) {
  const expected = manifest.resource_files;
  const expectedNames = Object.keys(expected).sort();
  const prefixes = ['backend', 'dashboard/static', 'docs', 'legal'];
  const actual = prefixes.flatMap(prefix => {
    const directory = path.join(resourcesRoot, ...prefix.split('/'));
    if (!fs.existsSync(directory)) throw new Error(`Packaged resource directory is missing: ${prefix}`);
    return inventory(directory).map(name => `${prefix}/${name}`);
  }).sort();
  if (JSON.stringify(actual) !== JSON.stringify(expectedNames)) {
    throw new Error('Packaged backend/dashboard file inventory differs from the release manifest.');
  }
  for (const [relative, expectedHash] of Object.entries(expected)) {
    const bytes = fs.readFileSync(path.join(resourcesRoot, ...relative.split('/')));
    if (digest(bytes) !== expectedHash) throw new Error(`Packaged resource hash mismatch: ${relative}`);
    if (/\.(?:html|js|css|json|md|txt)$/i.test(relative)) {
      const text = bytes.toString('utf8');
      const secretPatterns = [
        /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/,
        /\bAKIA[0-9A-Z]{16}\b/,
        /\b(?:gh[pousr]_[A-Za-z0-9_]{30,}|github_pat_[A-Za-z0-9_]{50,})\b/,
        /\bsk-(?:live|proj)-[A-Za-z0-9_-]{20,}\b/,
      ];
      if (secretPatterns.some(pattern => pattern.test(text))) {
        throw new Error(`Known secret pattern detected in packaged resources: ${relative}`);
      }
    }
  }
}

function verifyAsar(asarPath, manifest) {
  const expectedFiles = [...Object.keys(manifest.electron_files), 'package.json'].sort();
  const actualFiles = asar.listPackage(asarPath).map(name => name.replace(/\\/g, '/').replace(/^\/+/, '')).sort();
  if (JSON.stringify(actualFiles) !== JSON.stringify(expectedFiles)) {
    throw new Error('Electron app.asar contains files outside the declared release inventory.');
  }
  const packageJson = JSON.parse(asar.extractFile(asarPath, 'package.json').toString('utf8'));
  if (packageJson.version !== manifest.version || manifest.app_id !== 'com.bkentreprise.bksecurity') {
    throw new Error('Electron package version/appId do not match the release manifest.');
  }
  const packageText = JSON.stringify(packageJson);
  const sensitivePackagePatterns = [
    /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/,
    /\bAKIA[0-9A-Z]{16}\b/,
    /\b(?:gh[pousr]_[A-Za-z0-9_]{30,}|github_pat_[A-Za-z0-9_]{50,})\b/,
    /\bsk-(?:live|proj)-[A-Za-z0-9_-]{20,}\b/,
  ];
  if (sensitivePackagePatterns.some(pattern => pattern.test(packageText))) {
    throw new Error('Known secret pattern detected in Electron package metadata.');
  }
  for (const [relative, expectedHash] of Object.entries(manifest.electron_files)) {
    const bytes = asar.extractFile(asarPath, relative);
    if (digest(bytes) !== expectedHash) throw new Error(`Electron app.asar hash mismatch: ${relative}`);
    const text = bytes.toString('utf8');
    const secretPatterns = [
      /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/,
      /\bAKIA[0-9A-Z]{16}\b/,
      /\b(?:gh[pousr]_[A-Za-z0-9_]{30,}|github_pat_[A-Za-z0-9_]{50,})\b/,
      /\bsk-(?:live|proj)-[A-Za-z0-9_-]{20,}\b/,
    ];
    if (secretPatterns.some(pattern => pattern.test(text))) {
      throw new Error(`Known secret pattern detected in Electron app.asar: ${relative}`);
    }
  }
}

function main() {
  const [asarPath, manifestPath, resourcesRoot] = process.argv.slice(2);
  if (!asarPath || !manifestPath || !resourcesRoot) {
    throw new Error('Usage: node verify_packaged_release.js <app.asar> <manifest.json> <resources-directory>');
  }
  const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
  if (manifest.schema_version !== 1 || manifest.app_id !== 'com.bkentreprise.bksecurity' || manifest.windows_response_enabled !== false || manifest.capture_mode_default !== 'stopped') {
    throw new Error('Packaged release policy metadata is invalid.');
  }
  verifyResources(resourcesRoot, manifest);
  verifyAsar(asarPath, manifest);
  process.stdout.write(`Packaged Electron/resources verified: ${manifest.version} (${manifest.build_id})\n`);
}

if (require.main === module) {
  try { main(); } catch (error) {
    process.stderr.write(`Packaged release verification failed: ${error.message}\n`);
    process.exitCode = 1;
  }
}

module.exports = { inventory, verifyAsar, verifyResources };
