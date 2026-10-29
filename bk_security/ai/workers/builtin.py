from __future__ import annotations
from ..contracts import InvestigationRequest, InvestigationResult, SecurityWorker

class ThreatAnalyst(SecurityWorker):
    name='threat_analyst'
    def investigate(self, request):
        a=request.alert
        ti=request.threat_context.get('threat_intel') or {}
        if ti.get('match'):
            return InvestigationResult('suspicious', min(0.98, .65+float(ti.get('confidence',0))*.3), 'Threat intelligence matched an indicator.', ['Indicator reputation requires investigation.'], ['Enrich indicator and review related connections.'], [{'type':'threat_intel','data':ti}])
        return InvestigationResult('needs_review', .55, 'No decisive threat-intelligence match was supplied.', ['Behavioral context is required.'], ['Review process lineage and destination context.'])

class NetworkAnalyst(SecurityWorker):
    name='network_analyst'
    def investigate(self, request):
        a=request.alert; ports=[e.network.get('dst_port') for e in request.related_events if e.network]
        if a.risk_score >= 70 or any(p in {4444,4445,31337,9050} for p in ports):
            return InvestigationResult('suspicious', min(.95, .55+a.risk_score/250), 'Network evidence contains elevated-risk indicators.', ['Destination/port behavior is unusual for the observed host.'], ['Inspect destination reputation and process ownership.'])
        return InvestigationResult('needs_review', .5, 'Network evidence alone is insufficient for disposition.')

class ProcessAnalyst(SecurityWorker):
    name='process_analyst'
    suspicious={'powershell.exe','cmd.exe','mshta.exe','rundll32.exe','regsvr32.exe','certutil.exe','bitsadmin.exe'}
    def investigate(self, request):
        names={str(e.process.get('name') or '').lower() for e in request.related_events}
        hit=names & self.suspicious
        if hit: return InvestigationResult('suspicious', .78, 'A process associated with the alert matches a monitored execution pattern.', [f'Observed process: {next(iter(hit))}'], ['Review command line, parent process and child processes.'])
        return InvestigationResult('needs_review', .45, 'No monitored process name was observed in supplied evidence.')

class BehaviorAnalyst(SecurityWorker):
    name='behavior_analyst'
    def investigate(self, request):
        scores=[float(e.data.get('behavior_score',0)) for e in request.related_events]
        if max(scores,default=0)>=70: return InvestigationResult('suspicious', .82, 'Behavioral scoring indicates an abnormal pattern.', ['Behavior score exceeded the high-risk threshold.'], ['Review baseline deviation and timeline.'])
        return InvestigationResult('needs_review', .48, 'Behavioral evidence is not decisive.')

class IncidentAnalyst(SecurityWorker):
    name='incident_analyst'
    def investigate(self, request):
        return InvestigationResult('needs_review', .6, 'Incident context should be evaluated across all correlated evidence.', ['Cross-signal correlation is required before containment.'], ['Review incident timeline and correlated alerts.'])

class ThreatIntelAnalyst(ThreatAnalyst):
    name='threat_intel_analyst'

class ForensicsAnalyst(ProcessAnalyst):
    name='forensics_analyst'

class SecurityReporter(SecurityWorker):
    name='security_reporter'
    def investigate(self, request):
        return InvestigationResult('needs_review', .4, f'Report prepared for alert {request.alert.alert_id}.', ['Evidence should be reviewed by an analyst before final disposition.'])
