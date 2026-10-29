import React from 'react';
import { createRoot } from 'react-dom/client';
import './style.css';
import { buildTrafficTriage, nodeHostId, TRAFFIC_LEVEL_RANK, trafficLevelFor } from './traffic-triage.js';
import { BINARY_GLYPH_COUNT, brainFlowDuration, brainSphereFlowPath } from './brain-visuals.js';
import { playCriticalAlarm, trackCriticalAlertActivity } from './alert-sound.js';
import {
  canStartCapture,
  canStopCapture,
  captureRoleLabel,
  captureStatusExplanation,
  captureStatusLabel,
  isCaptureDeviceReady,
  preferredCaptureDevice,
  requestCaptureStart,
  requestCaptureStop,
} from './capture-controls.js';
import {
  incidentEvidenceIds,
  loadResponseActivity,
  prepareIncidentDryRun,
  responseOutcomeLabel,
} from './response-activity.js';
import { formatDeploymentScope, loadMonthlyAudit, previousCompletedUtcMonth } from './monthly-audit.js';
import { revokeAuthSession } from './auth-session.js';
import { loadActiveAuthSessions, revokeUserSessions } from './admin-sessions.js';

const API = window.location.origin;

function hashString(value) {
  let hash = 2166136261;
  for (let index = 0; index < value.length; index += 1) {
    hash ^= value.charCodeAt(index);
    hash = Math.imul(hash, 16777619);
  }
  return hash >>> 0;
}

function threatGroupKey(item, type) {
  const family = String(item.threat_family_id || '').trim();
  if (family) return `family:${family}`;

  const fingerprint = String(item.threat_fingerprint || '').trim();
  if (fingerprint) return `fingerprint:${fingerprint}`;

  return `${type}:${item.incident_id || item.alert_id || `${type}-individual`}`;
}

function severityRank(value) {
  return {
    CRITICAL: 4,
    HIGH: 3,
    MEDIUM: 2,
    LOW: 1,
    INFO: 0,
  }[String(value || '').toUpperCase()] ?? 0;
}

function buildHostSignalById(alerts, incidents) {
  const signals = new Map();
  const addSignal = (item, isIncident = false) => {
    const host = String(item?.host_id || '').trim();
    if (!host) return;
    if (isIncident && ['RESOLVED', 'CLOSED'].includes(String(item.status || '').toUpperCase())) return;
    const detected = trafficLevelFor({ severity: item.severity, risk: item.risk_score });
    const level = TRAFFIC_LEVEL_RANK[detected] >= TRAFFIC_LEVEL_RANK.interesting ? detected : 'interesting';
    const previous = signals.get(host);
    signals.set(host, {
      level: TRAFFIC_LEVEL_RANK[level] > TRAFFIC_LEVEL_RANK[previous?.level || 'normal'] ? level : previous.level,
      risk: Math.max(Number(previous?.risk || 0), Number(item.risk_score || 0)),
    });
  };
  (alerts || []).forEach((item) => addSignal(item));
  (incidents || []).forEach((item) => addSignal(item, true));
  return signals;
}

function prepareGraphEdges(rawEdges) {
  return (rawEdges || []).map((edge, index) => {
    const risk = Number(edge.risk_score ?? edge.risk ?? 0);
    const level = trafficLevelFor({ severity: edge.severity, risk, events: edge.events, bytes: edge.bytes });
    const id = String(edge.id || edge.edge_id || (String(edge.source) + '->' + String(edge.target) + ':' + index));
    const priority = TRAFFIC_LEVEL_RANK[level] * 1_000_000
      + risk * 1_000
      + Number(edge.events || 0) * 10
      + Math.min(Number(edge.bytes || 0) / 1_048_576, 999);
    return { ...edge, id, level, priority };
  }).filter((edge) => edge.source && edge.target);
}

function buildNodeTrafficLevels(edges) {
  const levels = new Map();
  (edges || []).forEach((edge) => [edge.source, edge.target].forEach((nodeId) => {
    const current = levels.get(nodeId) || 'normal';
    if (TRAFFIC_LEVEL_RANK[edge.level] > TRAFFIC_LEVEL_RANK[current]) levels.set(nodeId, edge.level);
  }));
  return levels;
}

function requiredGraphEdges(edges, nodesById, importantHostIds) {
  const selected = new Map();
  const ranked = [...edges].sort((a, b) => b.priority - a.priority);
  ranked.filter((edge) => TRAFFIC_LEVEL_RANK[edge.level] >= TRAFFIC_LEVEL_RANK.suspicious)
    .forEach((edge) => selected.set(edge.id, edge));

  const contextByHost = new Map();
  ranked.forEach((edge) => {
    [edge.source, edge.target].forEach((nodeId) => {
      const host = nodeHostId(nodesById.get(nodeId));
      if (importantHostIds.has(host) && !contextByHost.has(host)) contextByHost.set(host, edge);
    });
  });
  contextByHost.forEach((edge) => selected.set(edge.id, edge));
  return [...selected.values()];
}

function selectGraphNodes(rawNodes, { hostSignalById, edgeLevelByNode, requiredEdges, limit }) {
  const nodeLevel = (node) => {
    const hostLevel = hostSignalById.get(nodeHostId(node))?.level || 'normal';
    const edgeLevel = edgeLevelByNode.get(node.id) || 'normal';
    return TRAFFIC_LEVEL_RANK[hostLevel] >= TRAFFIC_LEVEL_RANK[edgeLevel] ? hostLevel : edgeLevel;
  };
  const typePriority = (node) => node.type === 'host' ? 4 : node.type === 'process' ? 3 : node.type === 'lan_device' ? 2 : 1;
  const ranked = [...rawNodes].sort((a, b) =>
    TRAFFIC_LEVEL_RANK[nodeLevel(b)] - TRAFFIC_LEVEL_RANK[nodeLevel(a)]
    || typePriority(b) - typePriority(a)
    || Number(hostSignalById.get(nodeHostId(b))?.risk || 0) - Number(hostSignalById.get(nodeHostId(a))?.risk || 0)
  );

  const protectedIds = new Set();
  hostSignalById.forEach((signal, host) => {
    const matches = ranked.filter((node) => nodeHostId(node) === host);
    const node = matches.find((candidate) => candidate.type === 'host') || matches[0];
    if (node) protectedIds.add(node.id);
  });
  requiredEdges.forEach((edge) => {
    protectedIds.add(edge.source);
    protectedIds.add(edge.target);
  });

  const protectedNodes = ranked.filter((node) => protectedIds.has(node.id));
  const otherNodes = ranked.filter((node) => !protectedIds.has(node.id));
  return [...protectedNodes, ...otherNodes.slice(0, Math.max(0, limit - protectedNodes.length))];
}

function selectGraphEdges(edges, { nodesById, visibleIds, importantHostIds, interestingLimit, normalLimit }) {
  const ranked = edges.filter((edge) => visibleIds.has(edge.source) && visibleIds.has(edge.target))
    .sort((a, b) => b.priority - a.priority);
  const selected = new Map();
  const add = (edge) => selected.set(edge.id, edge);

  ranked.filter((edge) => TRAFFIC_LEVEL_RANK[edge.level] >= TRAFFIC_LEVEL_RANK.suspicious).forEach(add);
  const contextByHost = new Map();
  ranked.forEach((edge) => {
    [edge.source, edge.target].forEach((nodeId) => {
      const host = nodeHostId(nodesById.get(nodeId));
      if (importantHostIds.has(host) && !contextByHost.has(host)) contextByHost.set(host, edge);
    });
  });
  contextByHost.forEach(add);
  ranked.filter((edge) => edge.level === 'interesting').slice(0, interestingLimit).forEach(add);
  ranked.filter((edge) => edge.level === 'normal').slice(0, normalLimit).forEach(add);

  return [...selected.values()].sort((a, b) =>
    TRAFFIC_LEVEL_RANK[a.level] - TRAFFIC_LEVEL_RANK[b.level] || a.priority - b.priority
  );
}

function buildThreatGroups(items, type) {
  const groups = new Map();

  (items || []).forEach((item) => {
    const key = threatGroupKey(item, type);

    if (!groups.has(key)) {
      groups.set(key, {
        key,
        type,
        items: [],
        maxRisk: 0,
        severity: 'INFO',
        latest: item,
      });
    }

    const group = groups.get(key);

    group.items.push(item);
    group.maxRisk = Math.max(
      group.maxRisk,
      Number(item.risk_score || 0)
    );

    if (severityRank(item.severity) > severityRank(group.severity)) {
      group.severity = String(item.severity || 'INFO').toUpperCase();
    }

    const itemTime = new Date(
      item.timestamp || item.created_at || item.updated_at || 0
    ).getTime();

    const latestTime = new Date(
      group.latest.timestamp ||
      group.latest.created_at ||
      group.latest.updated_at ||
      0
    ).getTime();

    if (itemTime >= latestTime) {
      group.latest = item;
    }
  });

  return [...groups.values()].sort((a, b) => {
    if (b.maxRisk !== a.maxRisk) {
      return b.maxRisk - a.maxRisk;
    }

    const aTime = new Date(
      a.latest.timestamp ||
      a.latest.created_at ||
      a.latest.updated_at ||
      0
    ).getTime();

    const bTime = new Date(
      b.latest.timestamp ||
      b.latest.created_at ||
      b.latest.updated_at ||
      0
    ).getTime();

    return bTime - aTime;
  });
}

function formatThreatTime(item) {
  const value =
    item?.timestamp ||
    item?.created_at ||
    item?.updated_at;

  const time = new Date(value || 0);

  if (!value || Number.isNaN(time.getTime())) {
    return 'time unavailable';
  }

  return time.toLocaleTimeString([], {
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  });
}
function BrainMode({ graph, alerts, incidents }) {
  const [selected, setSelected] = React.useState(null);
  const rawNodes = graph?.nodes || [];
  const hostSignalById = buildHostSignalById(alerts, incidents);
  const importantHostIds = new Set(hostSignalById.keys());
  const allEdges = prepareGraphEdges(graph?.edges);
  const rawNodesById = new Map(rawNodes.map((node) => [node.id, node]));
  const edgeLevelByNode = buildNodeTrafficLevels(allEdges);
  const { trafficSummary, linkedIncidents } = buildTrafficTriage({
    edges: allEdges,
    nodes: rawNodes,
    alerts,
    incidents,
  });
  const alertItems = Array.isArray(alerts) ? alerts : [];
  const incidentItems = Array.isArray(incidents) ? incidents : [];
  const visualSourceIds = [
    ...rawNodes.map((node) => node.id),
    ...allEdges.map((edge) => edge.id),
    ...alertItems.map((alert) => alert.alert_id || alert.id),
    ...incidentItems.flatMap((incident) => [incident.incident_id || incident.id, incident.threat_family_id]),
  ].filter(Boolean).map(String);
  const binaryGlyphs = Array.from({ length: BINARY_GLYPH_COUNT }, (_, index) => {
    const latitude = Math.acos(1 - (2 * (index + 0.5)) / BINARY_GLYPH_COUNT);
    const longitude = index * Math.PI * (3 - Math.sqrt(5));
    const radius = 214;
    const x = Math.sin(latitude) * Math.cos(longitude) * radius;
    const y = -Math.cos(latitude) * radius;
    const z = Math.sin(latitude) * Math.sin(longitude) * radius;
    const entityId = visualSourceIds[index % Math.max(visualSourceIds.length, 1)] || 'BK-SECURITY-CORE';
    const bit = (hashString(`${entityId}:${Math.floor(index / 32)}`) >>> (index % 32)) & 1;
    return {
      key: `binary-${index}`,
      bit,
      style: {
        transform: `translate3d(${x.toFixed(1)}px, ${y.toFixed(1)}px, ${z.toFixed(1)}px) translate(-50%, -50%)`,
        opacity: z > 0 ? 0.5 + (z / radius) * 0.42 : 0.12 + ((z + radius) / radius) * 0.08,
      },
    };
  });
  const sphereSignals = [
    ...[...allEdges].sort((a, b) => b.priority - a.priority).slice(0, 28).map((edge) => ({ id: edge.id, level: edge.level })),
    ...alertItems.slice(0, 12).map((alert) => ({
      id: String(alert.alert_id || alert.id || alert.host_id || ''),
      level: trafficLevelFor({ severity: alert.severity, risk: alert.risk_score }),
    })),
    ...linkedIncidents.slice(0, 12).map((incident) => ({
      id: String(incident.incident_id || incident.host_id || ''),
      level: trafficLevelFor({ severity: incident.severity, risk: incident.risk_score }),
    })),
  ].filter((signal) => signal.id).slice(0, 42).map((signal) => {
    const latitude = (hashString(`${signal.id}:lat`) / 0xffffffff) * Math.PI;
    const longitude = (hashString(`${signal.id}:lon`) / 0xffffffff) * Math.PI * 2;
    const radius = 221;
    return {
      ...signal,
      position: {
        transform: `translate3d(${(Math.sin(latitude) * Math.cos(longitude) * radius).toFixed(1)}px, ${(-Math.cos(latitude) * radius).toFixed(1)}px, ${(Math.sin(latitude) * Math.sin(longitude) * radius).toFixed(1)}px) translate(-50%, -50%)`,
      },
    };
  });
  const sphereFlowsByLevel = ['critical', 'suspicious', 'interesting', 'normal'].map((level) =>
    allEdges
      .filter((edge) => edge.level === level && rawNodesById.has(edge.source) && rawNodesById.has(edge.target))
      .sort((a, b) => b.priority - a.priority)
  );
  const sphereFlowEdges = [
    ...sphereFlowsByLevel[0].slice(0, 8),
    ...sphereFlowsByLevel[1].slice(0, 12),
    ...sphereFlowsByLevel[2].slice(0, 16),
    ...sphereFlowsByLevel[3].slice(0, 20),
  ].map((edge) => ({ ...edge, path: brainSphereFlowPath(edge), duration: brainFlowDuration(edge) }));
  const uniqueThreatFamilies = new Set(linkedIncidents.map((incident) => incident.threat_family_id).filter(Boolean));
  const criticalSignals = trafficSummary.critical.flows
    + alertItems.filter((alert) => trafficLevelFor({ severity: alert.severity, risk: alert.risk_score }) === 'critical').length
    + linkedIncidents.filter((incident) => trafficLevelFor({ severity: incident.severity, risk: incident.risk_score }) === 'critical').length;
  const suspiciousSignals = trafficSummary.suspicious.flows
    + alertItems.filter((alert) => trafficLevelFor({ severity: alert.severity, risk: alert.risk_score }) === 'suspicious').length
    + linkedIncidents.filter((incident) => trafficLevelFor({ severity: incident.severity, risk: incident.risk_score }) === 'suspicious').length;
  const interestingSignals = trafficSummary.interesting.flows;
  const brainBeat = criticalSignals ? 0.88 : suspiciousSignals ? 1.12 : interestingSignals ? 1.42 : trafficSummary.normal.flows ? 1.82 : 2.35;
  const brainSpin = criticalSignals ? 24 : suspiciousSignals ? 32 : interestingSignals ? 42 : trafficSummary.normal.flows ? 56 : 76;
  const brainActivityLabel = criticalSignals ? 'CRITICAL SIGNAL OBSERVED'
    : suspiciousSignals ? 'SUSPICIOUS TRAFFIC OBSERVED'
      : interestingSignals ? 'INTERESTING TRAFFIC OBSERVED'
        : trafficSummary.normal.flows || Number(graph?.event_count || 0) > 0 ? 'MONITORING LIVE TRAFFIC'
          : 'WAITING FOR LIVE TELEMETRY';
  const requiredEdges = requiredGraphEdges(allEdges, rawNodesById, importantHostIds);
  const nodes = selectGraphNodes(rawNodes, {
    hostSignalById,
    edgeLevelByNode,
    requiredEdges,
    limit: 30,
  });
  const visibleIds = new Set(nodes.map((node) => node.id));
  const edges = selectGraphEdges(allEdges, {
    nodesById: rawNodesById,
    visibleIds,
    importantHostIds,
    interestingLimit: 14,
    normalLimit: 6,
  });
  const trafficLevelByNode = buildNodeTrafficLevels(edges);
  const riskByHost = new Map([...hostSignalById].map(([host, signal]) => [host, signal.risk]));

  const points = React.useMemo(() => {
    const center = { x: 430, y: 205 };
    const result = new Map();
    const hostNodes = nodes.filter((node) => node.type === 'host');
    const processNodes = nodes.filter((node) => node.type === 'process');
    const otherNodes = nodes.filter((node) => node.type !== 'host' && node.type !== 'process');
    const placeRing = (items, radiusX, radiusY, offset) => {
      items.forEach((node, index) => {
        const angle = offset + (index / Math.max(items.length, 1)) * Math.PI * 2;
        const jitter = (hashString(node.id) % 19) - 9;
        result.set(node.id, { x: center.x + Math.cos(angle) * (radiusX + jitter), y: center.y + Math.sin(angle) * (radiusY + jitter), angle });
      });
    };
    placeRing(hostNodes, 230, 145, -Math.PI / 2);
    placeRing(processNodes, 155, 112, -Math.PI / 2 + 0.35);
    placeRing(otherNodes, 290, 175, -Math.PI / 2 + 0.12);
    return result;
  }, [nodes]);

  const corePoint = { x: 430, y: 205 };
  const selectedNode = selected ? nodes.find((node) => node.id === selected) : null;
  const selectedHost = selectedNode ? nodeHostId(selectedNode) : null;
  const relatedIncident = selectedHost ? (incidents || []).find((item) => item.host_id === selectedHost) : null;

  function nodeSignalLevel(node) {
    const hostLevel = hostSignalById.get(nodeHostId(node))?.level || 'normal';
    const trafficLevel = trafficLevelByNode.get(node.id) || 'normal';
    return TRAFFIC_LEVEL_RANK[hostLevel] >= TRAFFIC_LEVEL_RANK[trafficLevel] ? hostLevel : trafficLevel;
  }

  function nodeClass(node) {
    const type = node.type === 'lan_device' ? 'lan' : node.type;
    return `brain-node brain-${type} brain-${nodeSignalLevel(node)}`;
  }

  return (
    <section className="panel brain-panel">
      <div className="panelhead">
        <div><h2>Security Brain</h2><p className="brain-subtitle">LIVE TELEMETRY Â· SECURITY CORE Â· 15 MIN WINDOW</p></div>
        <span className="graph-count">{graph?.event_count || 0} SIGNALS Â· {nodes.length}/{rawNodes.length} NODES</span>
      </div>
      <div className={`brain-hero${criticalSignals ? ' brain-hero-critical' : suspiciousSignals ? ' brain-hero-suspicious' : ''}`} style={{ '--brain-beat': `${brainBeat}s`, '--brain-spin': `${brainSpin}s` }}>
        <div className="brain-hero-heading">
          <span>BK SECURITY CORE</span>
          <strong>{brainActivityLabel}</strong>
        </div>
        <div className="brain-orb-viewport" role="img" aria-label={`Security Brain data sphere. ${trafficSummary.normal.flows} normal flows, ${trafficSummary.interesting.flows} interesting flows, ${trafficSummary.suspicious.flows} suspicious flows, ${trafficSummary.critical.flows} critical flows. ${linkedIncidents.length} linked incidents and ${uniqueThreatFamilies.size} Threat Families.`}>
          <div className="brain-orb-aura" />
          <div className="brain-orb-static-rim" />
          <div className="brain-sphere-rotator" aria-hidden="true">
            <div className="brain-binary-sphere">
              {binaryGlyphs.map((glyph) => <span key={glyph.key} className={`brain-binary-glyph brain-binary-glyph-${glyph.bit}`} style={glyph.style}>{glyph.bit}</span>)}
              <svg className="brain-sphere-flow-layer" viewBox="0 0 460 460" aria-hidden="true">
                <defs><filter id="brainSphereFlowGlow"><feGaussianBlur stdDeviation="2" result="blur"/><feMerge><feMergeNode in="blur"/><feMergeNode in="SourceGraphic"/></feMerge></filter></defs>
                {sphereFlowEdges.map((edge) => <g key={`sphere-flow-${edge.id}`} className={`brain-sphere-flow-group brain-sphere-flow-group--${edge.level}`}>
                  <path d={edge.path} className={`brain-sphere-flow brain-sphere-flow--${edge.level}`} />
                  <circle r={edge.level === 'critical' ? 3 : edge.level === 'suspicious' ? 2.5 : edge.level === 'interesting' ? 2.1 : 1.5} className={`brain-sphere-flow-dot brain-sphere-flow-dot--${edge.level}`}>
                    <animateMotion dur={`${edge.duration}s`} repeatCount="indefinite" path={edge.path} />
                  </circle>
                </g>)}
              </svg>
              {sphereSignals.map((signal, index) => <span key={`surface-${signal.id}-${index}`} className={`brain-surface-signal brain-surface-${signal.level}`} style={signal.position} />)}
            </div>
          </div>
          <div className="brain-core-mark" aria-hidden="true">
            <span className="brain-core-mark-disc"><b>BK</b></span>
          </div>
          <div className="brain-core-caption">SECURITY BRAIN</div>
          <div className="brain-orb-hud brain-orb-hud-left"><b>{trafficSummary.normal.flows}</b><span>NORMAL</span></div>
          <div className="brain-orb-hud brain-orb-hud-right"><b>{trafficSummary.interesting.flows}</b><span>INTERESTING</span></div>
          <div className="brain-orb-hud brain-orb-hud-alert"><b>{trafficSummary.suspicious.flows}</b><span>SUSPICIOUS</span></div>
          <div className="brain-orb-hud brain-orb-hud-critical"><b>{trafficSummary.critical.flows}</b><span>CRITICAL</span></div>
        </div>
        <div className="brain-hero-context">
          <span><b>{alertItems.length}</b> ALERTS</span>
          <i />
          <span><b>{linkedIncidents.length}</b> LINKED INCIDENTS</span>
          <i />
          <span><b>{uniqueThreatFamilies.size}</b> THREAT FAMILIES</span>
        </div>
        <div className="brain-hero-note">Binary surface keyed to current hosts, flows, alerts, incident and Threat Family IDs</div>
      </div>
      <div className="brain-pathway" aria-label="Traffic triage flow">
        <div className="brain-pathway-core"><span>BK SECURITY CORE</span><small>LIVE TELEMETRY</small></div>
        <div className="brain-pathway-branches">
          <div className="brain-pathway-branch brain-pathway-normal">
            <div className="brain-pathway-card">
              <small>TRAFFIC BRANCH</small>
              <strong>NORMAL TRAFFIC</strong>
              <span>{trafficSummary.normal.flows} flows &middot; {trafficSummary.normal.events} events</span>
            </div>
            <div className="brain-pathway-interesting">
              <b>INTERESTING</b>
              <span>{trafficSummary.interesting.flows} flows &middot; {trafficSummary.interesting.events} events</span>
            </div>
          </div>
          <div className="brain-pathway-branch brain-pathway-suspect">
            <div className="brain-pathway-card">
              <small>TRAFFIC BRANCH</small>
              <strong>SUSPECT TRAFFIC</strong>
              <span>{trafficSummary.suspicious.flows} flows &middot; {trafficSummary.suspicious.events} events</span>
              {trafficSummary.critical.flows > 0 && <div className="brain-pathway-critical">
                <b>CRITICAL</b>
                <span>{trafficSummary.critical.flows} flows &middot; {trafficSummary.critical.events} events</span>
              </div>}
            </div>
            <div className="brain-pathway-downstream">
              <div className="brain-pathway-section-head">
                <small>ASSOCIATED OPEN INCIDENTS</small>
                <b>{linkedIncidents.length}</b>
              </div>
              {linkedIncidents.length ? <div className="brain-pathway-relations">
                {linkedIncidents.slice(0, 3).map((incident) => (
                  <div className="brain-pathway-relation" key={incident.incident_id || incident.host_id}>
                    <div className="brain-pathway-relation-incident">
                      <small>{incident.incident_id ? `INCIDENT ID ${incident.incident_id}` : 'INCIDENT'}</small>
                      <strong>{incident.title || incident.incident_id || incident.host_id}</strong>
                      <span>{incident.host_id} / {String(incident.status || 'NEW').toUpperCase()}</span>
                    </div>
                    <span className="brain-pathway-arrow" aria-label="linked to">&rarr;</span>
                    <div className="brain-pathway-relation-family">
                      <small>THREAT FAMILY</small>
                      <strong>{incident.threat_family_id || 'Not assigned'}</strong>
                    </div>
                  </div>
                ))}
                {linkedIncidents.length > 3 && <div className="brain-pathway-more">+{linkedIncidents.length - 3} more linked incidents</div>}
              </div> : <div className="brain-pathway-empty">No open incident linked to suspicious traffic</div>}
            </div>
          </div>
        </div>
      </div>
      <div className="brain-layout">
        <div className="brain-stage">
          <svg className="brain-canvas" viewBox="0 0 860 410" role="img" aria-label="Live BK Security Brain telemetry graph">
            <defs>
              <radialGradient id="brainGlow"><stop offset="0%" stopColor="#d4a017" stopOpacity=".28"/><stop offset="55%" stopColor="#d4a017" stopOpacity=".08"/><stop offset="100%" stopColor="#d4a017" stopOpacity="0"/></radialGradient>
              <filter id="softGlow"><feGaussianBlur stdDeviation="3" result="blur"/><feMerge><feMergeNode in="blur"/><feMergeNode in="SourceGraphic"/></feMerge></filter>
            </defs>
            <ellipse cx="430" cy="205" rx="155" ry="104" className="brain-silhouette" />
            <ellipse cx="430" cy="205" rx="132" ry="86" fill="url(#brainGlow)" className="brain-aura" />
            {edges.map((edge) => {
              const from = points.get(edge.source) || corePoint;
              const to = points.get(edge.target) || corePoint;
              const opacity = { normal: 0.3, interesting: 0.82, suspicious: 0.96, critical: 1 }[edge.level];
              const pulseDuration = brainFlowDuration(edge);
              return <g key={edge.id} className="brain-edge-group">
                <line x1={from.x} y1={from.y} x2={to.x} y2={to.y} className={`brain-edge brain-edge--${edge.level}`} style={{ opacity }} />
                <circle r={edge.level === 'critical' ? 4.5 : edge.level === 'suspicious' ? 3.4 : edge.level === 'interesting' ? 2.8 : 1.8} className={`brain-pulse brain-pulse--${edge.level}`}><animateMotion dur={`${pulseDuration}s`} repeatCount="indefinite" path={`M ${from.x} ${from.y} L ${to.x} ${to.y}`} /></circle>
              </g>;
            })}
            {nodes.map((node) => {
              const point = points.get(node.id) || corePoint;
              const level = nodeSignalLevel(node);
              const baseRadius = node.type === 'host' ? 8 : node.type === 'process' ? 5.5 : 4.5;
              const radius = baseRadius + (level === 'critical' ? 2 : level === 'suspicious' ? 1 : 0);
              const selectedClass = selected === node.id ? ' selected' : '';
              return <g key={node.id} className={`${nodeClass(node)}${selectedClass}`} onClick={() => setSelected(node.id)} onKeyDown={(event) => { if (event.key === 'Enter' || event.key === ' ') { event.preventDefault(); setSelected(node.id); } }} role="button" tabIndex={0} aria-label={`Inspect ${node.label || node.id}`}>
                <circle cx={point.x} cy={point.y} r={radius} />
                <circle cx={point.x} cy={point.y} r={radius + 8} className="node-ripple" />
                {(node.type === 'host' || level !== 'normal') && <text x={point.x + 11} y={point.y + 4}>{String(node.label || node.id).slice(0, 30)}</text>}
              </g>;
            })}
            <g className="brain-core" filter="url(#softGlow)">
              <circle cx={corePoint.x} cy={corePoint.y} r="45" className="core-orbit" />
              <circle cx={corePoint.x} cy={corePoint.y} r="29" className="core-circle" />
              <text x={corePoint.x} y={corePoint.y + 5} textAnchor="middle" className="core-mark">BK</text>
              <text x={corePoint.x} y={262} textAnchor="middle" className="core-label">BK SECURITY CORE</text>
            </g>
          </svg>
          <div className="brain-traffic-legend" aria-label="Traffic level legend">
            <span className="brain-legend-normal">Normal</span>
            <span className="brain-legend-interesting">Interesting</span>
            <span className="brain-legend-suspicious">Suspicious</span>
            <span className="brain-legend-critical">Critical</span>
          </div>
          <div className="brain-footer"><span>OBSERVED TELEMETRY</span><span>Pulse = observed traffic / event flow</span><span>Click a node to inspect</span></div>
        </div>
        <aside className="brain-inspector">
          {selectedNode ? <>
            <div className="inspector-kicker">NODE SELECTED</div>
            <h3>{selectedNode.label || selectedNode.id}</h3>
            <dl>
              <dt>Type</dt><dd>{selectedNode.type}</dd>
              {selectedNode.host_id && <><dt>Host</dt><dd>{selectedNode.host_id}</dd></>}
              {selectedNode.ip && <><dt>IP</dt><dd>{selectedNode.ip}</dd></>}
              {selectedNode.pid && <><dt>PID</dt><dd>{selectedNode.pid}</dd></>}
              {selectedNode.vendor && <><dt>Vendor</dt><dd>{selectedNode.vendor}</dd></>}
              {selectedNode.type === 'host' && <><dt>Risk</dt><dd>{riskByHost.get(selectedNode.host_id) || 0}</dd></>}
            </dl>
            {relatedIncident && <div className="brain-incident"><b>{relatedIncident.severity?.toUpperCase()} INCIDENT</b><span>{relatedIncident.title}</span><small>Risk {relatedIncident.risk_score}</small></div>}
            <button className="brain-clear" onClick={() => setSelected(null)}>Clear selection</button>
          </> : <>
            <div className="inspector-kicker">SECURITY BRAIN</div>
            <h3>Live security picture</h3>
            <p>Select a host, process, LAN device or destination. The graph is fed from the same telemetry pipeline used by the SOC.</p>
            <div className="brain-metrics"><b>{nodes.filter((n) => n.type === 'host').length}<small>HOSTS</small></b><b>{nodes.filter((n) => n.type === 'process').length}<small>PROCESSES</small></b><b>{nodes.filter((n) => n.type === 'destination').length}<small>DESTINATIONS</small></b></div>
          </>}
        </aside>
      </div>
    </section>
  );
}

function TopologyPanel({ topology, alerts, incidents }) {
  const [selectedNodeId, setSelectedNodeId] = React.useState(null);
  const hostSignalById = buildHostSignalById(alerts, incidents);
  const importantHostIds = new Set(hostSignalById.keys());
  const rawNodes = topology?.nodes || [];
  const rawNodesById = new Map(rawNodes.map((node) => [node.id, node]));
  const allEdges = prepareGraphEdges(topology?.edges);
  const edgeLevelByNode = buildNodeTrafficLevels(allEdges);
  const requiredEdges = requiredGraphEdges(allEdges, rawNodesById, importantHostIds);
  const nodes = selectGraphNodes(rawNodes, {
    hostSignalById,
    edgeLevelByNode,
    requiredEdges,
    limit: 26,
  });
  const groups = {
    host: nodes.filter((node) => node.type === 'host'),
    process: nodes.filter((node) => node.type === 'process'),
    lan_device: nodes.filter((node) => node.type === 'lan_device'),
    destination: nodes.filter((node) => node.type === 'destination'),
  };
  const positions = new Map();
  const columns = { host: 88, process: 340, lan_device: 470, destination: 650 };
  Object.entries(groups).forEach(([type, items]) => {
    items.forEach((node, index) => {
      const band = type === 'lan_device' ? groups.lan_device.length : items.length;
      positions.set(node.id, { x: columns[type], y: 42 + ((index + 1) * 236) / (band + 1) });
    });
  });
  const visibleIds = new Set(nodes.map((node) => node.id));
  const edges = selectGraphEdges(allEdges, {
    nodesById: rawNodesById,
    visibleIds,
    importantHostIds,
    interestingLimit: 10,
    normalLimit: 4,
  });
  const trafficLevelByNode = buildNodeTrafficLevels(edges);
  return (
    <section className="panel topology-panel">
      <div className="panelhead"><h2>Network topology</h2><span className="graph-count">{topology?.event_count || 0} EVENTS Â· {nodes.length}/{rawNodes.length} NODES Â· LAST {topology?.window_minutes || 60} MIN</span></div>
      {nodes.length ? <div className="topology-scroll"><svg className="topology" viewBox="0 0 880 300" role="img" aria-label="Observed host, process and destination relationships">
        {edges.map((edge) => {
          const from = positions.get(edge.source);
          const to = positions.get(edge.target);
          const opacity = { normal: 0.3, interesting: 0.82, suspicious: 0.96, critical: 1 }[edge.level];
          const path = `M ${from.x} ${from.y} L ${to.x} ${to.y}`;
          return <g key={edge.id} className={`topology-flow topology-flow--${edge.level}`}>
            <line x1={from.x} y1={from.y} x2={to.x} y2={to.y} className={`topology-edge topology-edge--${edge.level}`} style={{ opacity }} />
            <circle r={edge.level === 'critical' ? 4 : edge.level === 'suspicious' ? 3.1 : edge.level === 'interesting' ? 2.5 : 1.7} className={`topology-pulse topology-pulse--${edge.level}`}>
              <animateMotion dur={`${brainFlowDuration(edge)}s`} repeatCount="indefinite" path={path} />
            </circle>
          </g>;
        })}
        {nodes.map((node) => {
          const point = positions.get(node.id);
          const label = node.type === 'destination' && node.domains?.length ? String(node.label || node.id) + ' · ' + node.domains[0] : node.label;
          const color = node.type === 'host' ? 'host' : node.type === 'destination' ? 'destination' : 'process';
          const host = nodeHostId(node);
          const hostLevel = hostSignalById.get(host)?.level || 'normal';
          const trafficLevel = trafficLevelByNode.get(node.id) || 'normal';
          const level = TRAFFIC_LEVEL_RANK[hostLevel] >= TRAFFIC_LEVEL_RANK[trafficLevel] ? hostLevel : trafficLevel;
          const radius = level === 'critical' ? 9 : level === 'suspicious' ? 8 : 7;
          return <g key={node.id} className={`topology-node ${color} topology-node--${level}${selectedNodeId === node.id ? ' selected' : ''}`} onClick={() => setSelectedNodeId(node.id)} onKeyDown={(event) => { if (event.key === 'Enter' || event.key === ' ') { event.preventDefault(); setSelectedNodeId(node.id); } }} role="button" tabIndex={0} aria-label={`Inspect ${node.label || node.id}`} aria-pressed={selectedNodeId === node.id}>
            <circle cx={point.x} cy={point.y} r={radius} />
            {(node.type === 'host' || level !== 'normal') && <text x={point.x + 13} y={point.y + 4}>{String(label || node.id).slice(0, 32)}</text>}
          </g>;
        })}
      </svg></div> : <div className="empty topology-empty">Waiting for network and endpoint telemetry.</div>}
      {selectedNodeId && (() => {
        const node = nodes.find((item) => item.id === selectedNodeId);
        if (!node) return null;
        const relatedFlows = allEdges.filter((edge) => edge.source === node.id || edge.target === node.id);
        const hostId = nodeHostId(node);
        const relatedIncidents = (incidents || []).filter((item) => item.host_id === hostId && !['RESOLVED', 'CLOSED'].includes(String(item.status || '').toUpperCase()));
        return <div className="topology-inspector" aria-live="polite">
          <div><small>SELECTED {String(node.type || 'NODE').toUpperCase()}</small><strong>{node.label || node.id}</strong><span>{hostId ? `Host ${hostId}` : node.id}{node.ip ? ` · ${node.ip}` : ''}</span></div>
          <div className="topology-inspector-metrics"><b>{relatedFlows.length}<small>OBSERVED FLOWS</small></b><b>{relatedIncidents.length}<small>OPEN INCIDENTS</small></b></div>
          {relatedIncidents.length > 0 && <div className="topology-inspector-incidents">{relatedIncidents.map((item) => <span key={item.incident_id || item.id}>{item.incident_id || item.title} · {item.threat_family_id || 'No Threat Family ID'}</span>)}</div>}
          <button type="button" onClick={() => setSelectedNodeId(null)}>Clear selection</button>
        </div>;
      })()}
      <div className="topology-legend"><span>Host</span><span>Process / LAN device</span><span>Destination</span><span className="topology-legend-flow">Moving markers show observed traffic direction</span></div>
    </section>
  );
}

function CapturePanel({ token, role }) {
  const [capabilities, setCapabilities] = React.useState(null);
  const [busy, setBusy] = React.useState(false);
  const [message, setMessage] = React.useState('');
  const [selectedInterface, setSelectedInterface] = React.useState('');
  const [captureScope, setCaptureScope] = React.useState('endpoint');
  const canManage = role === 'admin' || role === 'analyst';
  const refresh = React.useCallback(async () => {
    if (!token) return;
    try {
      const response = await fetch(`${API}/api/v1/capture/capabilities`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      const result = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(result.detail || `Capture status unavailable (${response.status}).`);
      setCapabilities(result);
      return result;
    } catch (error) {
      setMessage(error.message || 'Capture status is temporarily unavailable.');
      return null;
    }
  }, [token]);

  React.useEffect(() => {
    refresh();
    const interval = window.setInterval(refresh, 10000);
    return () => window.clearInterval(interval);
  }, [refresh]);

  const status = capabilities?.status || {};
  const runtime = capabilities?.runtime || {};
  const captureDevices = runtime.capture_devices || [];
  React.useEffect(() => {
    if (status.running && status.mode === 'live') {
      setCaptureScope(status.capture_scope === 'mirror' ? 'mirror' : 'endpoint');
    }
  }, [status.running, status.mode, status.capture_scope]);
  const hasSelectedDevice = captureDevices.some((device) => device.name === selectedInterface);
  React.useEffect(() => {
    if (hasSelectedDevice) return;
    const preferred = preferredCaptureDevice(captureDevices);
    setSelectedInterface(preferred?.name || '');
  }, [captureDevices, hasSelectedDevice]);

  const selectedDevice = captureDevices.find((device) => device.name === selectedInterface);
  const selectedCaptureReady = isCaptureDeviceReady(capabilities, selectedDevice);
  const runningSelected = status.running && status.mode === 'live' && status.interface === selectedInterface;
  const otherLiveCapture = status.running && status.mode === 'live' && status.interface !== selectedInterface;
  const readinessReason = (runtime.reasons || []).join(' · ');
  const startCaptureEnabled = canStartCapture({
    canManage,
    busy,
    runningSelected,
    otherLiveCapture,
    ready: selectedCaptureReady,
  });
  const stopCaptureEnabled = canStopCapture({ canManage, busy, running: status.running });

  async function checkCaptureReadiness() {
    setBusy(true);
    setMessage('Checking capture readiness…');
    try {
      const result = await refresh();
      if (!result) return;
      const devices = result.runtime?.capture_devices || [];
      const device = devices.find((item) => item.name === selectedInterface)
        || preferredCaptureDevice(devices);
      if (device && !selectedInterface) setSelectedInterface(device.name);
      if (isCaptureDeviceReady(result, device)) {
        setMessage(`Readiness confirmed for ${device.display_name || device.name}. Live capture was not started.`);
        return;
      }
      const reason = (result.runtime?.reasons || []).join(' · ')
        || (!device ? 'No selectable Npcap interface is available.' : device.status === 'down' ? 'The selected interface is down.' : 'Live capture prerequisites are not ready.');
      setMessage(reason);
    } finally {
      setBusy(false);
    }
  }

  async function stopCapture() {
    setBusy(true);
    setMessage('');
    try {
      await requestCaptureStop({ api: API, token });
      setMessage('Capture stopped.');
      await refresh();
    } catch (error) {
      setMessage(error.message || 'Capture could not be stopped.');
    } finally {
      setBusy(false);
    }
  }

  async function startCapture() {
    if (!canManage) {
      setMessage('Live capture requires an admin or analyst login.');
      return;
    }
    if (otherLiveCapture) {
      setMessage('A live capture is already using another interface. Stop it before selecting a different adapter.');
      return;
    }
    if (!selectedCaptureReady) {
      setMessage(readinessReason || (!selectedDevice ? 'No selectable Npcap interface is available.' : 'Live capture prerequisites are not ready.'));
      return;
    }
    setBusy(true);
    setMessage('');
    try {
      await requestCaptureStart({
        api: API,
        token,
        interfaceName: selectedInterface,
        scope: captureScope,
        replaceExisting: status.running,
      });
      setMessage(`Live capture is running on ${selectedDevice?.display_name || selectedInterface}.`);
      await refresh();
    } catch (error) {
      setMessage(error.message || 'Live capture could not be started.');
      await refresh();
    } finally {
      setBusy(false);
    }
  }

  const stateLabel = captureStatusLabel(status);

  return (
    <section className="panel capture-panel">
      <div className="panelhead">
        <div>
          <h2>Packet capture</h2>
          <span className="capture-kicker">LIVE READINESS · Npcap / Scapy</span>
        </div>
        <div className="capture-status-stack">
          <span className="capture-role">{captureRoleLabel(role)}</span>
          <span className={`capture-state ${status.running ? 'capture-state-on' : ''}`}>
            {stateLabel}
          </span>
        </div>
      </div>
      <p className="capture-session-explanation">{captureStatusExplanation(role, status)}</p>
      <div className="capture-source-card" aria-label="Recommended network-wide capture source">
        <div className="capture-source-heading">
          <div>
            <span className="capture-source-kicker">NETWORK-WIDE VISIBILITY · RECOMMENDED SOURCE</span>
            <strong>SPAN / RSPAN mirror feed</strong>
          </div>
          <span className="capture-source-badge">PASSIVE · SWITCH/AP SETUP REQUIRED</span>
        </div>
        <div className="capture-source-flow" aria-label="Wi-Fi access point to switch mirror to BK Security sensor">
          <span>Wi-Fi AP / controller / gateway</span><b aria-hidden="true">→</b>
          <span>Switch port or VLAN mirror</span><b aria-hidden="true">→</b>
          <span>BK Security sensor NIC</span>
        </div>
        <p>
          One Wi-Fi adapter sees only traffic delivered to this computer. A 100 km geographic deployment requires multiple authorized sensors on AP, controller, gateway or mirrored switch links, plus centralized telemetry; this single-endpoint V1 does not provide that coverage yet. A mirrored feed is passive: it detects and alerts but does not block traffic.
        </p>
      </div>
      <div className="capture-layout">
        <div className="capture-readiness">
          <div className={`capture-ready-indicator ${selectedCaptureReady ? 'is-ready' : 'is-blocked'}`}>
            <span />
            <strong>{selectedCaptureReady ? 'Selected interface ready' : 'Live capture unavailable'}</strong>
          </div>
          <p>
            {selectedCaptureReady
              ? `Npcap / Scapy ready${runtime.elevated ? ' · elevated process' : ''}. Capture starts only after an operator action.`
              : readinessReason || 'Waiting for capture diagnostics.'}
          </p>
          <small>{selectedDevice?.is_wireless
            ? 'Wi-Fi endpoint mode observes traffic delivered to this computer. To see other clients, deploy a sensor on an AP/controller/gateway or feed a mirrored port.'
            : selectedDevice?.is_loopback
              ? 'Loopback observes this computer only; it does not monitor other Wi-Fi clients.'
              : 'An adapter observes traffic delivered to this sensor. Whole-network visibility needs an AP/controller/gateway feed or a mirrored port.'}</small>
        </div>
        <div className="capture-metrics">
          <div><small>ACTIVE INTERFACE</small><b>{status.interface ? (captureDevices.find((device) => device.name === status.interface)?.display_name || status.interface) : (status.mode === 'simulation' ? 'Simulation' : '—')}</b></div>
          <div><small>EVENTS ACCEPTED</small><b>{status.accepted ?? 0}</b></div>
          <div><small>REJECTED / DROPPED</small><b>{Number(status.rejected || 0) + Number(status.dropped || 0)}</b></div>
        </div>
        <div className="capture-actions">
          <label className="capture-interface-label" htmlFor="capture-scope">Traffic scope</label>
          <select id="capture-scope" value={captureScope} onChange={(event) => setCaptureScope(event.target.value)} disabled={busy || (status.running && status.mode === 'live')}>
            <option value="endpoint">Endpoint · this computer</option>
            <option value="mirror">Mirrored network · SPAN/RSPAN feed</option>
          </select>
          {captureScope === 'mirror' && <p className="capture-message" role="note">Mirror mode groups observed flows by source IP and the selected interface. Configure the AP uplinks and client VLANs on the switch mirror; BK Security cannot verify mirror completeness or block traffic at the switch.</p>}
          <label className="capture-interface-label" htmlFor="capture-interface">Local Npcap sensor interface · one interface at a time</label>
          <select id="capture-interface" value={selectedInterface} onChange={(event) => setSelectedInterface(event.target.value)} disabled={busy || (status.running && status.mode === 'live')}>
            {captureDevices.map((device) => <option key={device.name} value={device.name}>
              {device.display_name} · {device.status.toUpperCase()}{device.is_wireless ? ' · Wi-Fi' : device.is_loopback ? ' · loopback' : ''}
            </option>)}
          </select>
          <button type="button" onClick={checkCaptureReadiness} disabled={busy} title="Recheck Npcap, Scapy and selected-interface readiness. This does not start capture.">
            {busy ? 'Checking readiness…' : 'Check capture readiness'}
          </button>
          <button type="button" onClick={startCapture} disabled={!startCaptureEnabled} title={!canManage ? 'Live capture requires an admin or analyst login.' : runningSelected ? 'The selected capture is already active.' : otherLiveCapture ? 'Stop the active capture before selecting a different interface.' : !selectedCaptureReady ? 'Check readiness and resolve the displayed prerequisite before starting capture.' : 'Start a live capture on the selected interface.'}>
            {runningSelected ? 'Selected capture active' : 'Start live capture'}
          </button>
          {status.running && <button type="button" className="capture-stop" onClick={stopCapture} disabled={!stopCaptureEnabled} title={!canManage ? 'Stopping live capture requires an admin or analyst login.' : busy ? 'Capture operation in progress.' : 'Stop the active capture.'}>Stop capture</button>}
        </div>
      </div>
      {!canManage && <p className="capture-message" role="status">Readiness is visible to every role. Starting or stopping capture requires an admin or analyst login. Current role: {role}.</p>}
      {canManage && !selectedCaptureReady && !otherLiveCapture && <p className="capture-message" role="status">
        {readinessReason || (!selectedDevice ? 'No selectable Npcap interface is available.' : selectedDevice.status === 'down' ? 'The selected interface is down.' : 'Live capture prerequisites are not ready.')}
      </p>}
      {otherLiveCapture && <p className="capture-message" role="status">A live capture is already using another interface. Stop it before selecting a different adapter.</p>}
      {status.running && status.mode === 'live' && <p className="capture-message" role="status">Stop the active capture before changing interfaces.</p>}
      {message && <p className="capture-message" role="status">{message}</p>}
    </section>
  );
}

function responseTimestamp(value) {
  const timestamp = String(value || '').trim();
  if (!timestamp) return 'Time unavailable';
  const date = new Date(timestamp);
  return Number.isNaN(date.getTime()) ? timestamp : date.toLocaleString();
}

function responseText(value) {
  if (value === null || value === undefined) return '';
  if (typeof value === 'string' || typeof value === 'number' || typeof value === 'boolean') return String(value);
  try {
    return JSON.stringify(value);
  } catch {
    return '[structured response detail]';
  }
}

function ResponseDesk({ token, role, incidents }) {
  const [activity, setActivity] = React.useState({ actions: [], audit: [] });
  const [tab, setTab] = React.useState('actions');
  const [selectedIncidentId, setSelectedIncidentId] = React.useState('');
  const [refreshing, setRefreshing] = React.useState(false);
  const [planning, setPlanning] = React.useState(false);
  const [message, setMessage] = React.useState('');
  const [loadError, setLoadError] = React.useState('');
  const canPrepare = role === 'admin' || role === 'analyst';
  const planableIncidents = (incidents || []).filter((incident) => (
    incident.incident_id && incident.host_id && incidentEvidenceIds(incident).length > 0
  ));
  const selectedIncident = planableIncidents.find((incident) => incident.incident_id === selectedIncidentId)
    || planableIncidents[0];

  const refresh = React.useCallback(async () => {
    if (!token) return;
    setRefreshing(true);
    try {
      setActivity(await loadResponseActivity({ api: API, token }));
      setLoadError('');
    } catch (error) {
      setLoadError(error.message || 'Response activity is temporarily unavailable.');
    } finally {
      setRefreshing(false);
    }
  }, [token]);

  React.useEffect(() => {
    refresh();
    const interval = window.setInterval(refresh, 30000);
    return () => window.clearInterval(interval);
  }, [refresh]);

  React.useEffect(() => {
    if (planableIncidents.some((incident) => incident.incident_id === selectedIncidentId)) return;
    setSelectedIncidentId(planableIncidents[0]?.incident_id || '');
  }, [planableIncidents, selectedIncidentId]);

  async function prepareDryRun() {
    if (!canPrepare || !selectedIncident || planning) return;
    setPlanning(true);
    setMessage('');
    try {
      const plan = await prepareIncidentDryRun({ api: API, token, incident: selectedIncident });
      setMessage(`Dry-run plan ${plan.plan_id || ''} recorded (${String(plan.action || 'policy decision').toUpperCase()}). No response action was executed.`);
      await refresh();
    } catch (error) {
      setMessage(error.message || 'Dry-run plan could not be prepared.');
    } finally {
      setPlanning(false);
    }
  }

  const entries = tab === 'actions' ? activity.actions : activity.audit;

  return (
    <section className="panel response-desk">
      <div className="panelhead">
        <div>
          <h2>Response desk</h2>
          <span className="threat-panel-sub">POLICY-SELECTED · DRY-RUN · AUDIT</span>
        </div>
        <button type="button" onClick={refresh} disabled={refreshing} title="Refresh response actions and audit history.">
          {refreshing ? 'Refreshing…' : 'Refresh response history'}
        </button>
      </div>
      <p className="response-desk-explanation">
        Prepare a policy-selected plan from an open incident and review its audit trail. This dashboard control always creates a dry-run; it cannot approve, execute, block, isolate, or terminate a target.
      </p>
      <div className="response-desk-plan">
        <label htmlFor="response-incident">Open incident with a recorded host</label>
        <select
          id="response-incident"
          value={selectedIncident?.incident_id || ''}
          onChange={(event) => setSelectedIncidentId(event.target.value)}
          disabled={!canPrepare || planning || planableIncidents.length === 0}
        >
          {planableIncidents.length === 0 && <option value="">No planable incident is available</option>}
          {planableIncidents.map((incident) => (
            <option key={incident.incident_id} value={incident.incident_id}>
              {String(incident.severity || 'INFO').toUpperCase()} · {incident.title || incident.incident_id} · {incident.host_id} · {incidentEvidenceIds(incident).length} linked alerts
            </option>
          ))}
        </select>
        <button
          type="button"
          onClick={prepareDryRun}
          disabled={!canPrepare || !selectedIncident || planning}
          title={!canPrepare ? 'Preparing a plan requires an admin or analyst role.' : !selectedIncident ? 'An open incident with a host target is required.' : 'Create a policy-selected dry-run plan; no OS action will run.'}
        >
          {planning ? 'Preparing dry-run…' : 'Prepare dry-run plan'}
        </button>
      </div>
      {!canPrepare && <p className="response-desk-message" role="note">Current role: {role}. Response history is read-only for this role.</p>}
      {!selectedIncident && canPrepare && <p className="response-desk-message" role="note">An incident needs an ID, a recorded host, and linked alert evidence before a plan can be prepared.</p>}
      {message && <p className="response-desk-message" role="status">{message}</p>}
      {loadError && <p className="response-desk-error" role="alert">{loadError}</p>}
      <div className="response-desk-tabs" role="tablist" aria-label="Response records">
        <button type="button" role="tab" aria-selected={tab === 'actions'} onClick={() => setTab('actions')}>Plans and outcomes</button>
        <button type="button" role="tab" aria-selected={tab === 'audit'} onClick={() => setTab('audit')}>Audit trail</button>
      </div>
      {entries.length === 0 ? (
        <div className="response-desk-empty">{tab === 'actions' ? 'No response plans recorded.' : 'No response audit entries recorded.'}</div>
      ) : (
        <div className="response-desk-list">
          {entries.slice(0, 20).map((entry, index) => {
            const key = `${entry.plan_id || entry.execution_id || entry.action_id || `${entry.action || 'audit'}-${entry.timestamp || index}`}:${index}`;
            const actionLabel = String(entry.action || entry.action_type || 'response event').replaceAll('_', ' ').toUpperCase();
            const details = entry.data || {};
            const detailText = responseText(entry.reason || details.reason || details.result)
              || (entry.incident_id ? `Incident ${responseText(entry.incident_id)}` : 'Recorded in the response audit.');
            return (
              <article className="response-desk-entry" key={key}>
                <div className="response-desk-entry-head">
                  <strong>{tab === 'actions' ? responseOutcomeLabel(entry) : actionLabel}</strong>
                  <time>{responseTimestamp(entry.planned_at || entry.timestamp || entry.created_at || entry.executed_at)}</time>
                </div>
                <div className="response-desk-entry-body">
                  <b>{tab === 'actions' ? actionLabel : (entry.actor || 'Unknown actor')}</b>
                  <span>{entry.target || details.target || entry.plan_id || '—'}</span>
                  <small>{detailText}</small>
                  {tab === 'actions' && <small>Risk {String(entry.risk_level || 'unknown').toUpperCase()} · score {Number.isFinite(Number(entry.risk_score)) ? entry.risk_score : '—'} · {entry.plan_id || entry.execution_id || 'No plan ID'}</small>}
                </div>
              </article>
            );
          })}
        </div>
      )}
    </section>
  );
}

function MonthlyAuditReport({ token }) {
  const [month, setMonth] = React.useState(previousCompletedUtcMonth());
  const [report, setReport] = React.useState(null);
  const [loading, setLoading] = React.useState(false);
  const [error, setError] = React.useState('');

  const refresh = React.useCallback(async () => {
    if (!token) return;
    setLoading(true);
    setError('');
    try {
      setReport(await loadMonthlyAudit({ api: API, token, month }));
    } catch (loadError) {
      setError(loadError.message || 'Monthly audit could not be loaded.');
      setReport(null);
    } finally {
      setLoading(false);
    }
  }, [token, month]);

  React.useEffect(() => { refresh(); }, [refresh]);

  const events = report?.events || {};
  const alerts = report?.alerts || {};
  const incidents = report?.incidents || {};
  const response = report?.response || {};
  const operationalAudit = report?.operational_audit || {};
  const repairs = response.safe_platform_repairs?.records_in_period;

  return (
    <section className="panel monthly-audit">
      <div className="panelhead">
        <div>
          <h2>Monthly security audit</h2>
          <span className="threat-panel-sub">UTC · EVIDENCE-BASED SUMMARY</span>
        </div>
        <div className="monthly-audit-controls">
          <label htmlFor="monthly-audit-period">Report month (UTC)</label>
          <input id="monthly-audit-period" type="month" value={month} onChange={(event) => setMonth(event.target.value)} />
          <button type="button" onClick={refresh} disabled={loading || !month}>
            {loading ? 'Loading…' : 'Refresh report'}
          </button>
        </div>
      </div>
      {error && <p className="monthly-audit-error" role="alert">{error}</p>}
      {report && <>
        <div className="monthly-audit-coverage" role="status">
          Coverage: {report.coverage?.completeness || 'unknown'} · retained local records only
          {report.coverage?.possible_truncation ? ' · a source may have reached its retention limit' : ''}
        </div>
          <div className="monthly-audit-coverage" role="note">
            Deployment scope: {formatDeploymentScope(report.scope)}
          </div>
        <div className="monthly-audit-stats">
          <article><strong>{events.records_in_period ?? '—'}</strong><span>Events received</span><small>{events.simulation_marked ?? 0} marked as simulation</small></article>
          <article><strong>{alerts.records_in_period ?? '—'}</strong><span>Alerts raised</span><small>{Object.keys(alerts.by_severity || {}).length} severity levels</small></article>
          <article><strong>{incidents.created_in_period ?? '—'}</strong><span>Incidents created</span><small>{incidents.marked_resolved_or_closed_in_period ?? 0} marked resolved or closed in period</small></article>
          <article><strong>{response.verified_block_or_isolate_actions ?? '—'}</strong><span>Verified containment actions</span><small>{response.execution_attempts ?? 0} execution attempts</small></article>
          <article><strong>{repairs ?? '—'}</strong><span>Verified BK platform repairs</span><small>{response.verified_rollbacks ?? 0} verified rollbacks</small></article>
          <article><strong>{operationalAudit.entries_in_period ?? '—'}</strong><span>Operational audit entries</span><small>{Object.keys(operationalAudit.by_action || {}).length} action types</small></article>
        </div>
        <div className="monthly-audit-limitations">
          <p><b>Attacks avoided:</b> not measured. A verified block does not prove an attack was avoided.</p>
          <p><b>Threat remediations:</b> not tracked as independently verified in V1. An incident marked resolved is an operator status.</p>
          <p><b>Reliability audit chain:</b> {report.outcomes?.reliability_audit_chain || 'not checked'}.</p>
        </div>
        <details className="monthly-audit-breakdown">
          <summary>Show event, alert and response breakdown</summary>
          <div className="monthly-audit-breakdown-grid">
            <div><b>Events by type</b>{Object.entries(events.by_type || {}).map(([name, count]) => <span key={name}>{name} · {count}</span>)}</div>
            <div><b>Alerts by severity</b>{Object.entries(alerts.by_severity || {}).map(([name, count]) => <span key={name}>{name} · {count}</span>)}</div>
            <div><b>Response records by status</b>{Object.entries(response.by_status || {}).map(([name, count]) => <span key={name}>{name} · {count}</span>)}</div>
          </div>
        </details>
      </>}
    </section>
  );
}

function AdminSessionPanel({ token, role }) {
  const [sessions, setSessions] = React.useState([]);
  const [loading, setLoading] = React.useState(false);
  const [busyUser, setBusyUser] = React.useState('');
  const [message, setMessage] = React.useState('');
  const [error, setError] = React.useState('');

  async function refresh() {
    setLoading(true);
    setError('');
    try {
      setSessions(await loadActiveAuthSessions(fetch, API, token));
    } catch (cause) {
      setError(cause.message || 'Unable to load active sessions.');
    } finally {
      setLoading(false);
    }
  }

  React.useEffect(() => {
    if (role === 'admin' && token) refresh();
  }, [role, token]);

  async function revoke(username) {
    if (!window.confirm(`End every active session for ${username}? They will need to sign in again.`)) return;
    setBusyUser(username);
    setMessage('');
    setError('');
    try {
      const result = await revokeUserSessions(fetch, API, token, username);
      setMessage(`${result.revoked_sessions} active session(s) revoked for ${username}.`);
      await refresh();
    } catch (cause) {
      setError(cause.message || 'Unable to revoke sessions.');
    } finally {
      setBusyUser('');
    }
  }

  if (role !== 'admin') return null;
  return (
    <section className="panel admin-sessions">
      <div className="panelhead">
        <div><h2>Operator sessions</h2><span className="threat-panel-sub">ADMIN · CURRENT DEPLOYMENT ONLY</span></div>
        <button type="button" onClick={refresh} disabled={loading}>{loading ? 'Refreshing…' : 'Refresh sessions'}</button>
      </div>
      <p>End all active sessions for a compromised operator. This does not disable the account; the operator can sign in again.</p>
      {message && <p className="admin-session-message" role="status">{message}</p>}
      {error && <p className="admin-session-error" role="alert">{error}</p>}
      {sessions.length === 0 && !loading ? <div className="response-desk-empty">No active operator sessions.</div> : (
        <div className="admin-session-list">
          {sessions.map((session) => (
            <div className="admin-session-row" key={session.username}>
              <div><strong>{session.username}</strong><span>{session.active_sessions} active · expires by {new Date(session.latest_expiration * 1000).toLocaleString()}</span></div>
              <button type="button" onClick={() => revoke(session.username)} disabled={Boolean(busyUser)}>
                {busyUser === session.username ? 'Revoking…' : `Revoke ${session.active_sessions}`}
              </button>
            </div>
          ))}
        </div>
      )}
    </section>
  );
}

function App() {
  const [token, setToken] = React.useState(localStorage.getItem('bk_token'));
  const [role, setRole] = React.useState(localStorage.getItem('bk_role') || 'viewer');
  const [login, setLogin] = React.useState({ username: 'admin', password: '' });
  const [data, setData] = React.useState({ alerts: {}, open_incidents: 0, hosts: 0, events: 0, risk_max: 0 });
  const [incidents, setIncidents] = React.useState([]);
  const [alerts, setAlerts] = React.useState([]);
  const [topology, setTopology] = React.useState(null);
  const [brain, setBrain] = React.useState(null);
  const [error, setError] = React.useState('');
  const [online, setOnline] = React.useState(false);
  const [expandedIncidentGroups, setExpandedIncidentGroups] = React.useState({});
  const [expandedAlertGroups, setExpandedAlertGroups] = React.useState({});
  const [criticalAlarmEnabled, setCriticalAlarmEnabled] = React.useState(false);
  const [alarmMessage, setAlarmMessage] = React.useState('');
  const alarmAudioRef = React.useRef(null);
  const alarmEnabledRef = React.useRef(false);
  const alertFeedSeededRef = React.useRef(false);
  const seenAlertSeveritiesRef = React.useRef(new Map());

  const receiveAlerts = React.useCallback((incoming) => {
    const ordered = [...(incoming || [])].reverse();
    const newCritical = trackCriticalAlertActivity(ordered, seenAlertSeveritiesRef.current);
    if (alertFeedSeededRef.current && newCritical && alarmEnabledRef.current) {
      const audio = alarmAudioRef.current;
      if (audio?.state === 'running') playCriticalAlarm(audio);
      else setAlarmMessage('Audio paused by the browser. Use Test sound to resume the alarm.');
    }
    alertFeedSeededRef.current = true;
    setAlerts(ordered);
  }, []);

  async function resumeAlarmAudio() {
    const AudioContextConstructor = window.AudioContext || window.webkitAudioContext;
    if (!AudioContextConstructor) throw new Error('This system does not provide Web Audio.');
    if (!alarmAudioRef.current || alarmAudioRef.current.state === 'closed') {
      alarmAudioRef.current = new AudioContextConstructor();
    }
    await alarmAudioRef.current.resume();
    if (alarmAudioRef.current.state !== 'running') throw new Error('The browser did not resume audio playback.');
    return alarmAudioRef.current;
  }

  async function toggleCriticalAlarm() {
    if (criticalAlarmEnabled) {
      alarmEnabledRef.current = false;
      setCriticalAlarmEnabled(false);
      setAlarmMessage('Critical alarm muted.');
      const audio = alarmAudioRef.current;
      alarmAudioRef.current = null;
      if (audio && audio.state !== 'closed') await audio.close();
      return;
    }
    try {
      await resumeAlarmAudio();
      alarmEnabledRef.current = true;
      setCriticalAlarmEnabled(true);
      setAlarmMessage('Loud alarm enabled for new critical alerts.');
    } catch (error) {
      setAlarmMessage(error.message || 'Audio could not be enabled.');
    }
  }

  async function testCriticalAlarm() {
    try {
      playCriticalAlarm(await resumeAlarmAudio());
      setAlarmMessage('Alarm test played.');
    } catch (error) {
      setAlarmMessage(error.message || 'Alarm test could not play.');
    }
  }

  const load = React.useCallback(async () => {
    if (!token) return;
    try {
      const headers = { Authorization: `Bearer ${token}` };
      const [overviewResponse, incidentsResponse, alertsResponse, topologyResponse] = await Promise.all([
        fetch(`${API}/api/v1/overview`, { headers }),
        fetch(`${API}/api/v1/incidents`, { headers }),
        fetch(`${API}/api/v1/alerts`, { headers }),
        fetch(`${API}/api/v1/network/topology?minutes=60`, { headers }),
      ]);
      const responses = [overviewResponse, incidentsResponse, alertsResponse, topologyResponse];
      if (responses.some((response) => response.status === 401)) {
        localStorage.removeItem('bk_token');
        localStorage.removeItem('bk_role');
        setToken(null);
        setRole('viewer');
        return;
      }
      const failed = responses.find((response) => !response.ok);
      if (failed) throw new Error(`Dashboard data unavailable (${failed.status}).`);
      const [overview, incidentData, alertData, topologyData] = await Promise.all(responses.map((response) => response.json()));
      setData(overview);
      setIncidents(incidentData.incidents || []);
      receiveAlerts(alertData.alerts || []);
      setTopology(topologyData);
      setError('');
    } catch (loadError) {
      setError(loadError.message || 'BK Security local engine is temporarily unavailable.');
      setOnline(false);
    }
  }, [token, receiveAlerts]);

  React.useEffect(() => {
    if (!token) return undefined;
    load();
    const refresh = window.setInterval(load, 10000);
    const wsProtocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const ws = new WebSocket(`${wsProtocol}//${window.location.host}/ws/soc?token=${encodeURIComponent(token)}`);
    ws.onopen = () => setOnline(true);
    ws.onclose = () => setOnline(false);
    ws.onmessage = (message) => {
      const snapshot = JSON.parse(message.data);
      if (snapshot.type === 'soc.snapshot') {
        setData(snapshot.overview);
        setIncidents(snapshot.incidents || []);
        receiveAlerts(snapshot.alerts || []);
        if (snapshot.brain) { setBrain(snapshot.brain); setTopology(snapshot.brain); }
      }
    };
    return () => { window.clearInterval(refresh); ws.close(); };
  }, [token, load, receiveAlerts]);

  async function doLogin(event) {
    event.preventDefault();
    setError('');
    try {
      const response = await fetch(`${API}/api/v1/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(login),
      });
      if (!response.ok) { setError(response.status === 401 ? 'Invalid username or password' : `Sign in failed (${response.status}).`); return; }
      const result = await response.json();
      localStorage.setItem('bk_token', result.access_token);
      localStorage.setItem('bk_role', result.role || 'viewer');
      setRole(result.role || 'viewer');
      setToken(result.access_token);
    } catch {
      setError('BK Security local engine is unreachable. Start the desktop service and try again.');
    }
  }

  async function doLogout() {
    const revoked = await revokeAuthSession(fetch, API, token);
    localStorage.removeItem('bk_token');
    localStorage.removeItem('bk_role');
    setRole('viewer');
    setToken(null);
    setError(revoked ? '' : 'Signed out on this device, but the server could not confirm session revocation.');
  }

  async function updateIncidentStatus(incidentId, status) {
    try {
      const response = await fetch(`${API}/api/v1/incidents/${encodeURIComponent(incidentId)}/status`, {
        method: 'PATCH',
        headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({ status }),
      });
      if (!response.ok) {
        setError(`Incident update failed (${response.status})`);
        return;
      }
      setError('');
      await load();
    } catch {
      setError('Incident update could not reach the local engine.');
    }
  }

  if (!token) {
    return (
      <div className="login">
        <div className="loginbox">
          <div className="brand">BK <span>SECURITY</span></div>
          <p>AI SECURITY OPERATIONS CENTER</p>
          <form onSubmit={doLogin}>
            <input value={login.username} onChange={(event) => setLogin({ ...login, username: event.target.value })} placeholder="Username" />
            <input type="password" value={login.password} onChange={(event) => setLogin({ ...login, password: event.target.value })} placeholder="Password" />
            <button>Sign in</button>
            {error && <small>{error}</small>}
          </form>
        </div>
      </div>
    );
  }

  const openIncidents = incidents.filter(
    (item) =>
      !['RESOLVED', 'CLOSED'].includes(
        String(item.status || 'NEW').toUpperCase()
      )
  );

  const incidentGroups = buildThreatGroups(
    openIncidents,
    'incident'
  );

  const alertGroups = buildThreatGroups(
    alerts,
    'alert'
  ).slice(0, 12);

  const toggleIncidentGroup = (key) => {
    setExpandedIncidentGroups((current) => ({
      ...current,
      [key]: !current[key],
    }));
  };

  const toggleAlertGroup = (key) => {
    setExpandedAlertGroups((current) => ({
      ...current,
      [key]: !current[key],
    }));
  };
const cards = [['CRITICAL', data.alerts?.critical || 0], ['HIGH', data.alerts?.high || 0], ['MEDIUM', data.alerts?.medium || 0], ['RISK MAX', data.risk_max || 0]];
  return (
    <div className="app">
      <header>
        <div><div className="brand">BK <span>SECURITY</span></div><div className="sub">AI SECURITY OPERATIONS CENTER Â· V1.0</div></div>
        <div className={online ? 'status' : 'status off'}>{online ? 'â— CORE ONLINE' : 'â— CORE OFFLINE'}</div>
      </header>
      {error && <div className="dashboard-error" role="alert">{error}</div>}
      <main>
        <section className="hero">
          <div><h1>Security Operations Center</h1><p>Detection, investigation and controlled response.</p></div>
          <button className="logout" onClick={doLogout}>Sign out</button>
        </section>
        <section className="grid">
          {cards.map(([label, value]) => <div className="card" key={label}><small>{label}</small><strong>{value}</strong><span>Current telemetry</span></div>)}
          <div className="card"><small>HOSTS</small><strong>{data.hosts}</strong><span>Observed endpoints</span></div>
        </section>
        <BrainMode graph={brain || topology} alerts={alerts} incidents={incidents} />
        <CapturePanel token={token} role={role} />
        <TopologyPanel topology={topology} alerts={alerts} incidents={incidents} />
        <section className="panel">
          <div className="panelhead">
            <div>
              <h2>Incidents</h2>
              <span className="threat-panel-sub">
                {incidentGroups.length} THREAT FAMILIES
              </span>
            </div>
            <span>
              {openIncidents.length} OPEN
            </span>
          </div>

          {incidentGroups.length ? (
            <div className="rows threat-groups">
              {incidentGroups.map((group) => {
                const incident = group.latest;
                const status = String(
                  incident.status || 'NEW'
                ).toUpperCase();

                const transitions = {
                  NEW: ['INVESTIGATING', 'CLOSED'],
                  INVESTIGATING: [
                    'CONTAINMENT',
                    'RESOLVED',
                    'CLOSED',
                  ],
                  CONTAINMENT: [
                    'INVESTIGATING',
                    'RESOLVED',
                    'CLOSED',
                  ],
                  RESOLVED: [
                    'INVESTIGATING',
                    'CLOSED',
                  ],
                }[status] || [];

                const expanded =
                  !!expandedIncidentGroups[group.key];

                const grouped =
                  group.items.length > 1;

                return (
                  <div
                    className={`threat-group ${
                      expanded ? 'threat-group-expanded' : ''
                    }`}
                    key={group.key}
                  >
                    <div
                      className="row incident-row threat-group-head"
                      onClick={() =>
                        toggleIncidentGroup(group.key)
                      }
                    >
                      <b>
                        {group.severity}
                      </b>

                      <span>
                        {incident.title}
                        {grouped && (
                          <small className="threat-occurrences">
                            {group.items.length} occurrences
                          </small>
                        )}
                      </span>

                      <span className="threat-family-label">
                        {group.key.startsWith('family:')
                          ? 'THREAT FAMILY'
                          : group.key.startsWith('fingerprint:')
                            ? 'THREAT FINGERPRINT'
                            : 'INDIVIDUAL'}
                      </span>

                      <em>
                        {group.maxRisk}
                      </em>

                      <small
                        className={`incident-status status-${status.toLowerCase()}`}
                      >
                        {status}
                      </small>

                      <button
                        type="button"
                        className="threat-expand"
                        onClick={(event) => {
                          event.stopPropagation();
                          toggleIncidentGroup(group.key);
                        }}
                      >
                        {expanded ? 'HIDE' : 'VIEW'}
                      </button>
                    </div>

                    <div className="threat-group-meta">
                      <span>
                        {group.items.length} occurrence
                        {group.items.length > 1 ? 's' : ''}
                      </span>

                      <span>
                        Risk max {group.maxRisk}
                      </span>

                      <span>
                        Latest {formatThreatTime(group.latest)}
                      </span>

                      {incident.host_id && (
                        <span>
                          Host {incident.host_id}
                        </span>
                      )}
                    </div>

                    {expanded && (
                      <div className="threat-group-items">
                        {group.items.map((item) => {
                          const itemStatus =
                            String(
                              item.status || 'NEW'
                            ).toUpperCase();

                          const itemTransitions = {
                            NEW: [
                              'INVESTIGATING',
                              'CLOSED',
                            ],
                            INVESTIGATING: [
                              'CONTAINMENT',
                              'RESOLVED',
                              'CLOSED',
                            ],
                            CONTAINMENT: [
                              'INVESTIGATING',
                              'RESOLVED',
                              'CLOSED',
                            ],
                            RESOLVED: [
                              'INVESTIGATING',
                              'CLOSED',
                            ],
                          }[itemStatus] || [];

                          return (
                            <div
                              className="row incident-row threat-child"
                              key={item.incident_id}
                            >
                              <b>
                                {String(
                                  item.severity || 'INFO'
                                ).toUpperCase()}
                              </b>

                              <span>
                                {item.title}
                              </span>

                              <span>
                                {item.host_id || '—'}
                              </span>

                              <em>
                                {item.risk_score || 0}
                              </em>

                              <small
                                className={`incident-status status-${itemStatus.toLowerCase()}`}
                              >
                                {itemStatus}
                              </small>

                              {(role === 'admin' ||
                                role === 'analyst') &&
                                itemTransitions.length > 0 && (
                                  <select
                                    aria-label={`Change status for ${item.title}`}
                                    value={itemStatus}
                                    onChange={(event) =>
                                      updateIncidentStatus(
                                        item.incident_id,
                                        event.target.value
                                      )
                                    }
                                    onClick={(event) =>
                                      event.stopPropagation()
                                    }
                                  >
                                    <option value={itemStatus}>
                                      {itemStatus}
                                    </option>

                                    {itemTransitions.map(
                                      (next) => (
                                        <option
                                          key={next}
                                          value={next}
                                        >
                                          {next}
                                        </option>
                                      )
                                    )}
                                  </select>
                                )}
                            </div>
                          );
                        })}
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          ) : (
            <div className="empty">
              No active incidents detected.
            </div>
          )}
        </section>

        <ResponseDesk token={token} role={role} incidents={openIncidents} />
        <MonthlyAuditReport token={token} />
        <AdminSessionPanel token={token} role={role} />

        <section className="panel">
          <div className="panelhead">
            <div>
              <h2>Recent alerts</h2>
              <span className="threat-panel-sub">
                {alertGroups.length} THREAT GROUPS
              </span>
            </div>
            <div className="alert-sound-controls" aria-label="Critical alert sound controls">
              <span className={`alarm-state ${criticalAlarmEnabled ? 'alarm-state-on' : ''}`}>
                {criticalAlarmEnabled ? 'CRITICAL ALARM ON' : 'ALARMS MUTED'}
              </span>
              <button type="button" aria-pressed={criticalAlarmEnabled} onClick={toggleCriticalAlarm}>
                {criticalAlarmEnabled ? 'Mute alarm' : 'Enable loud alarm'}
              </button>
              <button type="button" onClick={testCriticalAlarm}>Test sound</button>
              <small>New critical alerts only</small>
            </div>
          </div>
          {alarmMessage && <p className="alarm-message" role="status">{alarmMessage}</p>}

          <div className="rows threat-groups">
            {alertGroups.map((group) => {
              const alert = group.latest;
              const expanded =
                !!expandedAlertGroups[group.key];

              return (
                <div
                  className={`threat-group ${
                    expanded ? 'threat-group-expanded' : ''
                  }`}
                  key={group.key}
                >
                  <div
                    className="row threat-alert-head"
                    onClick={() =>
                      toggleAlertGroup(group.key)
                    }
                  >
                    <b>
                      {group.severity}
                    </b>

                    <span>
                      {alert.title}
                      {group.items.length > 1 && (
                        <small className="threat-occurrences">
                          {group.items.length} occurrences
                        </small>
                      )}
                    </span>

                    <span className="threat-family-label">
                      {group.key.startsWith('family:')
                        ? 'THREAT FAMILY'
                        : group.key.startsWith('fingerprint:')
                          ? 'THREAT FINGERPRINT'
                          : 'INDIVIDUAL'}
                    </span>

                    <em>
                      {group.maxRisk}
                    </em>

                    <button
                      type="button"
                      className="threat-expand"
                      onClick={(event) => {
                        event.stopPropagation();
                        toggleAlertGroup(group.key);
                      }}
                    >
                      {expanded ? 'HIDE' : 'VIEW'}
                    </button>
                  </div>

                  <div className="threat-group-meta">
                    <span>
                      {group.items.length} occurrence
                      {group.items.length > 1 ? 's' : ''}
                    </span>

                    <span>
                      Risk max {group.maxRisk}
                    </span>

                    <span>
                      Latest {formatThreatTime(group.latest)}
                    </span>

                    {alert.host_id && (
                      <span>
                        Host {alert.host_id}
                      </span>
                    )}
                  </div>

                  {expanded && (
                    <div className="threat-group-items">
                      {group.items.map((item) => (
                        <div
                          className="row threat-child threat-alert-child"
                          key={item.alert_id}
                        >
                          <b>
                            {String(
                              item.severity || 'INFO'
                            ).toUpperCase()}
                          </b>

                          <span>
                            {item.title}
                          </span>

                          <span>
                            {item.host_id || '—'}
                          </span>

                          <em>
                            {item.risk_score || 0}
                          </em>

                          <small>
                            {formatThreatTime(item)}
                          </small>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        </section>
        <footer className="origin-attribution">
          <span>Based on PCYBOX Orbis by (Mister-iks) - </span>
          <a href="https://github.com/Mister-iks/pcybox-orbis" target="_blank" rel="noreferrer">
            https://github.com/Mister-iks/pcybox-orbis
          </a>
        </footer>
      </main>
    </div>
  );
}

createRoot(document.getElementById('root')).render(<App />);




