export async function loadActiveAuthSessions(fetchImpl, apiBase, token) {
  const response = await fetchImpl(`${apiBase}/api/v1/auth/sessions`, {
    headers: { Authorization: `Bearer ${token}` },
  });
  if (!response.ok) throw new Error(`Session list unavailable (${response.status}).`);
  const payload = await response.json();
  return Array.isArray(payload.sessions) ? payload.sessions : [];
}

export async function revokeUserSessions(fetchImpl, apiBase, token, username) {
  const response = await fetchImpl(
    `${apiBase}/api/v1/auth/sessions/${encodeURIComponent(username)}/revoke`,
    { method: 'POST', headers: { Authorization: `Bearer ${token}` } },
  );
  if (!response.ok) throw new Error(`Session revocation failed (${response.status}).`);
  return response.json();
}
