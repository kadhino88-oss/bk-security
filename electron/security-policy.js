'use strict';

const path = require('path');
const { fileURLToPath } = require('url');

function isTrustedNavigation(targetUrl, trustedOrigin, fallbackFile) {
  try {
    const target = new URL(targetUrl);
    const origin = new URL(trustedOrigin);
    if (target.protocol === 'http:' || target.protocol === 'https:') {
      return target.origin === origin.origin && target.username === '' && target.password === '';
    }
    if (target.protocol === 'file:' && fallbackFile) {
      const actual = path.normalize(fileURLToPath(target));
      const expected = path.normalize(fallbackFile);
      return process.platform === 'win32'
        ? actual.toLowerCase() === expected.toLowerCase()
        : actual === expected;
    }
  } catch (_error) {
    return false;
  }
  return false;
}

module.exports = { isTrustedNavigation };
