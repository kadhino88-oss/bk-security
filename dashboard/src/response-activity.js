const RISK_LEVELS = new Set(['critical', 'high', 'medium', 'low', 'info']);

export function incidentEvidenceIds(incident) {
  if (!Array.isArray(incident?.alert_ids)) return [];
  return [...new Set(incident.alert_ids
    .filter((value) => typeof value === 'string')
    .map((value) => value.trim())
    .filter(Boolean))]
    .slice(0, 64);
}

async function requestJson(fetchImpl, url, options, label) {
  const response = await fetchImpl(url, options);
  const payload = await response.json().catch(() => ({}));
  if (!response.ok) {
    const detail = typeof payload.detail === 'string' ? payload.detail : '';
    throw new Error(detail || `${label} unavailable (${response.status}).`);
  }
  return payload;
}

function authHeaders(token) {
  if (!token) throw new Error('Sign in to review response activity.');
  return { Authorization: `Bearer ${token}` };
}

export async function loadResponseActivity({ api, token, fetchImpl = fetch }) {
  const headers = authHeaders(token);
  const [actions, audit] = await Promise.all([
    requestJson(fetchImpl, `${api}/api/v1/response/actions`, { headers }, 'Response actions'),
    requestJson(fetchImpl, `${api}/api/v1/response/audit`, { headers }, 'Response audit'),
  ]);
  return {
    actions: Array.isArray(actions.actions) ? actions.actions : [],
    audit: Array.isArray(audit.audit) ? audit.audit : [],
  };
}

export async function prepareIncidentDryRun({ api, token, incident, fetchImpl = fetch }) {
  const headers = authHeaders(token);
  const incidentId = String(incident?.incident_id || '').trim();
  const target = String(incident?.host_id || '').trim();
  const evidenceIds = incidentEvidenceIds(incident);
  if (!incidentId || !target || evidenceIds.length === 0) {
    throw new Error('Choose an open incident with a recorded host target and linked alert evidence.');
  }

  const candidateRisk = String(incident.severity || 'info').toLowerCase();
  const riskLevel = RISK_LEVELS.has(candidateRisk) ? candidateRisk : 'info';
  const riskScore = Number(incident.risk_score);
  const body = {
    target,
    reason: `Dry-run review: ${String(incident.title || incidentId).slice(0, 1900)}`,
    dry_run: true,
    risk_level: riskLevel,
    incident_id: incidentId,
    evidence_ids: evidenceIds,
  };
  if (Number.isInteger(riskScore) && riskScore >= 0 && riskScore <= 100) {
    body.risk_score = riskScore;
  }

  return requestJson(fetchImpl, `${api}/api/v1/response/plan`, {
    method: 'POST',
    headers: { ...headers, 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  }, 'Dry-run plan');
}

export function responseOutcomeLabel(action) {
  const status = String(action?.status || 'planned').toLowerCase();
  if (action?.dry_run === true || status === 'dry_run') return 'DRY-RUN · NO ACTION EXECUTED';
  if (status === 'executed') {
    return action?.verification?.verified === true
      ? 'EXECUTED · VERIFIED'
      : 'EXECUTION RECORDED · VERIFICATION UNCONFIRMED';
  }
  if (status === 'rolled_back') {
    return action?.verification?.verified === true
      ? 'ROLLBACK · VERIFIED'
      : 'ROLLBACK · VERIFICATION UNCONFIRMED';
  }
  if (status === 'degraded' || status === 'failed' || status === 'rollback_failed') {
    return `REVIEW REQUIRED · ${status.toUpperCase()}`;
  }
  if (status === 'planned') return 'PLAN PREPARED · NOT EXECUTED';
  return status.replaceAll('_', ' ').toUpperCase();
}

