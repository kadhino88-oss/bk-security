'use strict';

const fs = require('node:fs');
const path = require('node:path');

function loadModule(filename) {
  const absolute = path.resolve(filename);
  const module = { exports: {} };
  const localRequire = (specifier) => {
    if (!specifier.startsWith('.')) return require(specifier);
    const resolved = path.resolve(path.dirname(absolute), specifier);
    const candidate = path.extname(resolved) ? resolved : `${resolved}.js`;
    return loadModule(candidate);
  };
  const source = fs.readFileSync(absolute, 'utf8');
  new Function('require', 'module', 'exports', '__dirname', '__filename', source)(
    localRequire, module, module.exports, path.dirname(absolute), absolute,
  );
  return module.exports;
}

loadModule(path.join(__dirname, 'security-policy.test.js'));
loadModule(path.join(__dirname, 'backend-supervisor.test.js'));
loadModule(path.join(__dirname, 'integrity-manifest.test.js'));
loadModule(path.join(__dirname, 'runtime-log.test.js'));
loadModule(path.join(__dirname, 'dashboard-url.test.js'));
