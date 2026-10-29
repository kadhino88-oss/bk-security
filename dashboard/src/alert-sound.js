const MAX_SEEN_ALERTS = 2000;

function alertIdentity(alert) {
  const explicit = String(alert?.alert_id || alert?.id || '').trim();
  if (explicit) return explicit;
  return [alert?.timestamp, alert?.host_id, alert?.title]
    .map((part) => String(part || '').trim())
    .join('|');
}

export function trackCriticalAlertActivity(alerts, seenSeverities = new Map()) {
  let newCritical = false;
  for (const alert of Array.isArray(alerts) ? alerts : []) {
    const id = alertIdentity(alert);
    if (!id || id === '||') continue;
    const severity = String(alert?.severity || 'INFO').trim().toUpperCase();
    const previous = seenSeverities.get(id);
    if (severity === 'CRITICAL' && previous !== 'CRITICAL') newCritical = true;
    if (seenSeverities.has(id)) seenSeverities.delete(id);
    seenSeverities.set(id, severity);
  }
  while (seenSeverities.size > MAX_SEEN_ALERTS) {
    seenSeverities.delete(seenSeverities.keys().next().value);
  }
  return newCritical;
}

export function playCriticalAlarm(audioContext, { gain = 0.55 } = {}) {
  if (!audioContext || audioContext.state === 'closed') return false;
  const volume = Math.max(0, Math.min(0.75, Number(gain)));
  if (!Number.isFinite(volume) || volume === 0) return false;

  const notes = [880, 660, 880, 660];
  const firstStart = audioContext.currentTime + 0.02;
  notes.forEach((frequency, index) => {
    const start = firstStart + index * 0.34;
    const oscillator = audioContext.createOscillator();
    const envelope = audioContext.createGain();
    oscillator.type = 'sawtooth';
    oscillator.frequency.setValueAtTime(frequency, start);
    envelope.gain.setValueAtTime(0.0001, start);
    envelope.gain.linearRampToValueAtTime(volume, start + 0.025);
    envelope.gain.setValueAtTime(volume, start + 0.2);
    envelope.gain.exponentialRampToValueAtTime(0.0001, start + 0.28);
    oscillator.connect(envelope);
    envelope.connect(audioContext.destination);
    oscillator.start(start);
    oscillator.stop(start + 0.29);
  });
  return true;
}
