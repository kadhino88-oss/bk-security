const MONTH_PATTERN = /^\d{4}-(0[1-9]|1[0-2])$/;

export function previousCompletedUtcMonth(now = new Date()) {
  const date = new Date(now);
  const firstOfPreviousMonth = new Date(Date.UTC(date.getUTCFullYear(), date.getUTCMonth() - 1, 1));
  return firstOfPreviousMonth.toISOString().slice(0, 7);
}

export function formatDeploymentScope(scope) {
  const profile = scope?.profile === 'dedicated_customer' ? 'Dedicated customer data plane' : 'Local V1 instance';
  const details = [scope?.customer_ref, scope?.region].filter((value) => typeof value === 'string' && value.trim());
  const enforcement = scope?.scope_enforcement === 'database_startup_binding_only'
    ? 'database binding only; host and region not attested'
    : 'single local instance';
  return `${profile}${details.length ? ` · ${details.join(' · ')}` : ''} · ${enforcement}`;
}

export async function loadMonthlyAudit({ api, token, month, fetchImpl = fetch }) {
  if (!MONTH_PATTERN.test(String(month || ''))) {
    throw new Error('Choose a valid month in YYYY-MM format.');
  }
  const response = await fetchImpl(`${api}/api/v1/audit/monthly?month=${encodeURIComponent(month)}`, {
    headers: { Authorization: `Bearer ${token}` },
  });
  const body = await response.json().catch(() => ({}));
  if (!response.ok) {
    throw new Error(typeof body.detail === 'string' ? body.detail : `Monthly audit unavailable (${response.status}).`);
  }
  return body;
}
