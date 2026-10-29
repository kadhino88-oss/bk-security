'use strict';

const assert = require('node:assert/strict');
const { buildDashboardUrl } = require('../dashboard-url');

assert.equal(
  buildDashboardUrl('http://127.0.0.1:8000', 'v1.0.0-build-123'),
  'http://127.0.0.1:8000/?bk_build=v1.0.0-build-123',
);
assert.equal(
  buildDashboardUrl('http://127.0.0.1:8000/old?stale=1#anchor', ''),
  'http://127.0.0.1:8000/?bk_build=development',
);
