export const TRAFFIC_LEVEL_RANK = {
  normal: 0,
  interesting: 1,
  suspicious: 2,
  critical: 3,
};

export function trafficLevelFor({ severity, risk = 0, events = 0, bytes = 0 } = {}) {
  const normalizedSeverity = String(severity || '').toUpperCase();
  if (normalizedSeverity === 'CRITICAL' || Number(risk) >= 80) return 'critical';
  if (normalizedSeverity === 'HIGH' || Number(risk) >= 50) return 'suspicious';
  if (normalizedSeverity === 'MEDIUM' || Number(events) >= 8 || Number(bytes) >= 1_048_576) return 'interesting';
  return 'normal';
}

export function nodeHostId(node) {
  return String(node?.host_id || (node?.type === 'host' ? node.id : '') || '');
}

export function buildTrafficTriage({ edges = [], nodes = [], alerts = [], incidents = [] } = {}) {
  const trafficSummary = {
    normal: { flows: 0, events: 0 },
    interesting: { flows: 0, events: 0 },
    suspicious: { flows: 0, events: 0 },
    critical: { flows: 0, events: 0 },
  };

  edges.forEach((edge) => {
    const level = trafficSummary[edge.level] ? edge.level : 'normal';
    trafficSummary[level].flows += 1;
    trafficSummary[level].events += Number(edge.events || 0);
  });

  const suspectHosts = new Set(
    alerts
      .filter((alert) => TRAFFIC_LEVEL_RANK[trafficLevelFor({ severity: alert.severity, risk: alert.risk_score })] >= TRAFFIC_LEVEL_RANK.suspicious)
      .map((alert) => String(alert.host_id || '').trim())
      .filter(Boolean),
  );
  const nodesById = new Map(nodes.map((node) => [node.id, node]));

  edges
    .filter((edge) => TRAFFIC_LEVEL_RANK[edge.level] >= TRAFFIC_LEVEL_RANK.suspicious)
    .forEach((edge) => {
      [edge.source, edge.target].forEach((nodeId) => {
        const host = nodeHostId(nodesById.get(nodeId));
        if (host) suspectHosts.add(host);
      });
    });

  const linkedIncidents = incidents.filter((incident) =>
    !['RESOLVED', 'CLOSED'].includes(String(incident.status || 'NEW').toUpperCase())
    && suspectHosts.has(String(incident.host_id || '').trim())
  );

  return { trafficSummary, linkedIncidents };
}
