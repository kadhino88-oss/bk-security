export function preferredCaptureDevice(devices = []) {
  return devices.find((device) => device.is_wireless && device.status === 'up')
    || devices.find((device) => device.is_loopback)
    || devices.find((device) => device.status === 'up')
    || devices[0]
    || null;
}

export function isCaptureDeviceReady(capabilities, device) {
  return Boolean(
    capabilities?.live_capture_available
    && device
    && (device.status === 'up' || device.is_loopback)
  );
}

export function canStartCapture({ canManage, busy, runningSelected, otherLiveCapture, ready }) {
  return Boolean(canManage && !busy && !runningSelected && !otherLiveCapture && ready);
}

export function canStopCapture({ canManage, busy, running }) {
  return Boolean(canManage && !busy && running);
}

export async function requestCaptureStop({ api, token, fetchImpl = globalThis.fetch }) {
  const response = await fetchImpl(`${api}/api/v1/capture/stop`, {
    method: 'POST',
    headers: { Authorization: `Bearer ${token}` },
  });
  if (!response.ok) throw new Error(`Capture stop failed (${response.status}).`);
}

export async function requestCaptureStart({
  api,
  token,
  interfaceName,
  scope = 'endpoint',
  replaceExisting = false,
  fetchImpl = globalThis.fetch,
}) {
  if (replaceExisting) {
    const stopped = await fetchImpl(`${api}/api/v1/capture/stop`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${token}` },
    });
    if (!stopped.ok) {
      throw new Error(`Current capture could not be stopped (${stopped.status}).`);
    }
  }

  const response = await fetchImpl(`${api}/api/v1/capture/start`, {
    method: 'POST',
    headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ mode: 'live', interface: interfaceName, scope }),
  });
  const result = await response.json().catch(() => ({}));
  if (!response.ok) {
    throw new Error(result.detail || `Capture start failed (${response.status}).`);
  }
  return result;
}

export function captureRoleLabel(role) {
  const normalizedRole = ['admin', 'analyst', 'viewer'].includes(role) ? role : 'unknown';
  return `SIGNED IN · ${normalizedRole.toUpperCase()}`;
}

export function captureStatusLabel(status) {
  return status?.running
    ? `${String(status.mode || 'unknown').toUpperCase()} · RUNNING`
    : 'CAPTURE STOPPED';
}

export function captureStatusExplanation(role, status) {
  const normalizedRole = ['admin', 'analyst', 'viewer'].includes(role) ? role : 'unknown';
  return status?.running
    ? `Session role: ${normalizedRole}. Packet capture is active in ${status.capture_scope === 'mirror' ? 'mirrored-network' : 'endpoint'} scope.`
    : `Session role: ${normalizedRole}. Capture is stopped; no interface is currently collecting packets.`;
}
