'use strict';

function buildDashboardUrl(origin, buildId) {
  const url = new URL(origin);
  url.pathname = '/';
  url.search = '';
  url.hash = '';
  url.searchParams.set('bk_build', buildId || 'development');
  return url.toString();
}

module.exports = { buildDashboardUrl };
