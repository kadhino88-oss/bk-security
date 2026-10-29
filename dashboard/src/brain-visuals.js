function hashString(value) {
  let hash = 2166136261;
  for (let index = 0; index < value.length; index += 1) {
    hash ^= value.charCodeAt(index);
    hash = Math.imul(hash, 16777619);
  }
  return hash >>> 0;
}

export const BINARY_GLYPH_COUNT = 840;

export function brainSpherePoint(nodeId) {
  const angle = (hashString(`${nodeId}:angle`) / 0xffffffff) * Math.PI * 2;
  const radius = 150 + (hashString(`${nodeId}:radius`) % 56);
  return {
    x: 230 + Math.cos(angle) * radius,
    y: 230 + Math.sin(angle) * radius,
  };
}

export function brainSphereFlowPath(edge) {
  const from = brainSpherePoint(edge.source);
  const to = brainSpherePoint(edge.target);
  const dx = to.x - from.x;
  const dy = to.y - from.y;
  const length = Math.hypot(dx, dy);
  const direction = hashString(edge.id) % 2 ? 1 : -1;
  const bow = Math.min(58, length * 0.24) * direction;
  const controlX = (from.x + to.x) / 2 - (length ? dy / length : 0) * bow;
  const controlY = (from.y + to.y) / 2 + (length ? dx / length : 0) * bow;
  return `M ${from.x.toFixed(1)} ${from.y.toFixed(1)} Q ${controlX.toFixed(1)} ${controlY.toFixed(1)} ${to.x.toFixed(1)} ${to.y.toFixed(1)}`;
}

export function brainFlowDuration(edge) {
  const base = { normal: 4.2, interesting: 2.8, suspicious: 1.8, critical: 1.05 }[edge.level] || 3.2;
  const observedEvents = Math.max(0, Number(edge.events || 0));
  return Math.max(0.72, base / (1 + Math.log1p(observedEvents) * 0.12));
}
