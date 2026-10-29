export async function revokeAuthSession(fetchImpl, api, token) {
  if (!token) return false;
  try {
    const response = await fetchImpl(`${api}/api/v1/auth/logout`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${token}` },
    });
    if (!response.ok) return false;
    const result = await response.json();
    return result.revoked === true;
  } catch {
    return false;
  }
}
