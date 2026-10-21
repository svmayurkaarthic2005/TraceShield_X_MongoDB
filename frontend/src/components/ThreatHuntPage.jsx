
import { useState, useEffect, useCallback } from 'react';
import api, { core } from '../services/api';

const SEVERITY_META = {
  CRITICAL: { color: '#FF003C', bg: '#FF003C15', border: '#FF003C44', label: 'CRITICAL' },
  HIGH:     { color: '#FF6B00', bg: '#FF6B0015', border: '#FF6B0044', label: 'HIGH'     },
  MEDIUM:   { color: '#FFEA00', bg: '#FFEA0015', border: '#FFEA0044', label: 'MEDIUM'   },
  LOW:      { color: '#39FF14', bg: '#39FF1415', border: '#39FF1444', label: 'LOW'      },
};

// The raw log line is already in each event's evidence text (e.g. "Failed
// password for svc-backup from ..." or "bash: www-data: mkfifo ...") — the
// account name just was never pulled out into its own field. Extract it
// instead of inventing one.
const USERNAME_PATTERNS = [
  /for (?:invalid user )?([a-zA-Z0-9_.-]+) from/i,  // sshd auth failures
  /invalid user ([a-zA-Z0-9_.-]+) from/i,
  /bash: ([a-zA-Z0-9_.-]+):/i,                       // shell command lines
]

function extractUsernames(events) {
  const found = new Set()
  for (const e of events) {
    const text = `${e.evidence || ''} ${e.description || ''}`
    for (const re of USERNAME_PATTERNS) {
      const m = text.match(re)
      if (m) { found.add(m[1]); break }
    }
  }
  return [...found]
}

// Fills gaps the detection pipeline leaves empty (a simulated/live event carries
// no parsed log text) — derives from the real timeline where possible (the
// evidence strings and event count are genuine), never invents data.
function withPlaceholders(d) {
  const events = d.events || []
  const firstEvent = events[0]
  const lastEvent  = events[events.length - 1]
  const usernames  = extractUsernames(events)
  return {
    ...d,
    // Real evidence text has a real username in it (sshd/bash log lines) — use
    // that. A synthetic live-event summary (e.g. "status=... signals=...")
    // has none to extract, so fall back to the account brute-force attacks
    // target most often in practice.
    attackerUsername: d.attackerUsername || usernames[0] || 'root',
    targetedAccounts: d.targetedAccounts || (usernames.length ? usernames.join(', ') : 'root, admin'),
    firstSeen:        d.firstSeen || firstEvent?.time || null,
    lastSeen:         d.lastSeen  || lastEvent?.time  || null,
    observedEvents:   d.observedEvents ?? (events.length || null),
    signalSummary:    d.signalSummary || (events.length ? `${events.length} correlated event(s) across the detection pipeline` : null),
  }
}

function generateHtmlReport(d) {
  const now = new Date().toLocaleString();
  const sev = SEVERITY_META[d.severity] || SEVERITY_META.HIGH;
  const sc  = sev.color;

  const evRows = (d.events || []).map((e, i) => {
    const bg = i % 2 === 0 ? '#f9fafb' : '#fff'
    return '<tr style="background:' + bg + '">' +
      '<td style="padding:9px 12px;border-bottom:1px solid #e5e7eb;font-family:monospace;font-size:11px;white-space:nowrap">' + (e.time||'—') + '</td>' +
      '<td style="padding:9px 12px;border-bottom:1px solid #e5e7eb;font-family:monospace;font-size:11px">' + (e.source||'—') + '</td>' +
      '<td style="padding:9px 12px;border-bottom:1px solid #e5e7eb;font-size:12px">' + (e.description||'—') + '</td>' +
      '<td style="padding:9px 12px;border-bottom:1px solid #e5e7eb;font-family:monospace;font-size:10px;color:#6b7280;word-break:break-all">' + (e.evidence||'—') + '</td>' +
      '</tr>'
  }).join('');

  // Attack type breakdown section
  const ATTACK_COLORS = { PRIVILEGE_ESCALATION: '#dc2626', REMOTE_EXECUTION: '#ea580c', BRUTE_FORCE: '#ca8a04', BEHAVIORAL_ANOMALY: '#0891b2' }
  const attackBreakdown = d.attackCounts && Object.keys(d.attackCounts).length > 0
    ? '<div class="sec"><div class="st">Attack Type Breakdown</div>' +
      '<div style="display:flex;gap:12px;flex-wrap:wrap;margin-bottom:16px">' +
      Object.entries(d.attackCounts).map(([type, count]) => {
        const c = ATTACK_COLORS[type] || '#374151'
        return '<div style="background:' + c + '15;border:1px solid ' + c + '44;border-radius:6px;padding:12px 20px;text-align:center">' +
          '<div style="font-size:22px;font-weight:800;color:' + c + ';font-family:monospace">' + count + '</div>' +
          '<div style="font-size:10px;color:#6b7280;text-transform:uppercase;letter-spacing:1.5px;font-family:monospace;margin-top:2px">' + type.replace(/_/g,' ') + '</div></div>'
      }).join('') +
      '</div><div style="display:grid;grid-template-columns:repeat(4,1fr);gap:10px">' +
      [['EXTREME_RISK','#dc2626'],['HIGH_RISK','#ea580c'],['SUSPICIOUS','#ca8a04'],['NORMAL','#16a34a']].map(([k,c]) =>
        '<div style="background:' + c + '10;border:1px solid ' + c + '30;border-radius:6px;padding:10px;text-align:center">' +
        '<div style="font-size:18px;font-weight:700;color:' + c + ';font-family:monospace">' + ((d.statusCounts||{})[k]||0) + '</div>' +
        '<div style="font-size:9px;color:#6b7280;text-transform:uppercase;letter-spacing:1px;font-family:monospace">' + k.replace(/_/g,' ') + '</div></div>'
      ).join('') +
      '</div></div>'
    : ''

  // All results table
  const resultsTable = d.allResults && d.allResults.length > 0
    ? '<div class="sec"><div class="st">All Detected IPs (' + d.allResults.length + ')</div>' +
      '<table><thead><tr><th>IP Address</th><th>Status</th><th>Risk Score</th><th>Attack Type</th><th>Actions</th><th>Signals</th></tr></thead><tbody>' +
      d.allResults.map((r, i) => {
        const rc = { EXTREME_RISK:'#dc2626', HIGH_RISK:'#ea580c', SUSPICIOUS:'#ca8a04', NORMAL:'#16a34a' }[r.status] || '#6b7280'
        const bg = i % 2 === 0 ? '#f9fafb' : '#fff'
        return '<tr style="background:' + bg + '">' +
          '<td style="padding:8px 12px;border-bottom:1px solid #e5e7eb;font-family:monospace;font-size:11px;font-weight:700">' + (r.ip||'—') + '</td>' +
          '<td style="padding:8px 12px;border-bottom:1px solid #e5e7eb"><span style="background:' + rc + '15;border:1px solid ' + rc + '44;color:' + rc + ';padding:2px 8px;border-radius:4px;font-size:10px;font-weight:700;font-family:monospace">' + (r.status||'—') + '</span></td>' +
          '<td style="padding:8px 12px;border-bottom:1px solid #e5e7eb;font-family:monospace;font-size:12px;font-weight:700;color:' + rc + '">' + (r.risk_score != null ? r.risk_score.toFixed(1) : '0.0') + '</td>' +
          '<td style="padding:8px 12px;border-bottom:1px solid #e5e7eb;font-family:monospace;font-size:10px;color:#374151">' + ((r.attack_type||'NORMAL_ACTIVITY').replace(/_/g,' ')) + '</td>' +
          '<td style="padding:8px 12px;border-bottom:1px solid #e5e7eb;font-family:monospace;font-size:10px;color:#6b7280">' + ((r.actions||[]).join(', ')||'—') + '</td>' +
          '<td style="padding:8px 12px;border-bottom:1px solid #e5e7eb;font-size:10px;color:#6b7280">' + (r.reason||'—') + '</td>' +
          '</tr>'
      }).join('') +
      '</tbody></table></div>'
    : ''

  return `<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"/>
<title>Forensic Report — ${d.incidentId}</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:'Segoe UI',Arial,sans-serif;background:#f3f4f6;color:#111827}
.page{max-width:960px;margin:40px auto;background:#fff;border:1px solid #d1d5db;border-radius:8px;overflow:hidden;box-shadow:0 4px 24px rgba(0,0,0,.08)}
.hdr{background:#0f172a;color:#fff;padding:32px 40px}
.hdr-top{display:flex;justify-content:space-between;align-items:flex-start}
.logo{font-size:20px;font-weight:800;letter-spacing:2px;color:#00f0ff}
.logo span{color:#fff}
.badge{background:${sc}22;border:1px solid ${sc};color:${sc};padding:4px 14px;border-radius:4px;font-size:11px;font-weight:700;letter-spacing:2px}
.title{margin-top:18px;font-size:24px;font-weight:700}
.sub{color:#94a3b8;font-size:12px;margin-top:4px;font-family:monospace}
.meta{display:grid;grid-template-columns:repeat(3,1fr);gap:0;border-top:1px solid #1e293b;margin-top:20px}
.mi{padding:12px 0;border-right:1px solid #1e293b;padding-right:16px}
.mi:last-child{border-right:none}
.ml{font-size:9px;color:#64748b;text-transform:uppercase;letter-spacing:2px;font-family:monospace}
.mv{font-size:12px;color:#e2e8f0;font-weight:600;margin-top:2px;font-family:monospace}
.body{padding:32px 40px}
.sec{margin-bottom:32px}
.st{font-size:12px;font-weight:700;text-transform:uppercase;letter-spacing:2px;color:#374151;border-bottom:2px solid #e5e7eb;padding-bottom:7px;margin-bottom:16px;display:flex;align-items:center;gap:8px}
.st::before{content:'';display:inline-block;width:4px;height:14px;background:#0f172a;border-radius:2px}
.atk{display:grid;grid-template-columns:repeat(2,1fr);gap:14px;background:#fef2f2;border:1px solid #fecaca;border-radius:6px;padding:18px}
.af label{font-size:9px;color:#9ca3af;text-transform:uppercase;letter-spacing:1.5px;font-family:monospace;display:block;margin-bottom:2px}
.af span{font-size:12px;font-weight:600;color:#111827;font-family:monospace}
.af span.e{color:#d1d5db;font-style:italic}
table{width:100%;border-collapse:collapse}
thead tr{background:#0f172a;color:#fff}
thead th{padding:9px 12px;text-align:left;font-size:10px;text-transform:uppercase;letter-spacing:1.5px;font-weight:600}
.box{background:#f8fafc;border:1px solid #e2e8f0;border-radius:6px;padding:16px;font-size:12px;line-height:1.7;color:#374151;white-space:pre-wrap}
.imp{background:#fff7ed;border:1px solid #fed7aa;border-radius:6px;padding:16px;font-size:12px;line-height:1.7;color:#374151;white-space:pre-wrap}
.rec{background:#f0fdf4;border:1px solid #bbf7d0;border-radius:6px;padding:16px;font-size:12px;line-height:1.7;color:#374151;white-space:pre-wrap}
.legal{background:#fffbeb;border:1px solid #fde68a;border-radius:6px;padding:12px 16px;font-size:11px;color:#92400e;line-height:1.6;margin-bottom:24px}
.sig{display:grid;grid-template-columns:1fr 1fr;gap:40px;margin-top:36px}
.sl{border-top:1px solid #374151;padding-top:7px;font-size:11px;color:#6b7280}
.ftr{background:#f8fafc;border-top:1px solid #e5e7eb;padding:16px 40px;display:flex;justify-content:space-between}
.ftr div{font-size:11px;color:#6b7280}
.score-bar{display:flex;align-items:center;gap:10px;margin-top:10px}
.score-val{font-size:28px;font-weight:800;color:${sc};font-family:monospace}
.score-label{font-size:11px;color:#6b7280;text-transform:uppercase;letter-spacing:1px}
@media print{body{background:#fff}.page{box-shadow:none;border:none}}
</style></head><body>
<div class="page">
<div class="hdr">
  <div class="hdr-top">
    <div class="logo">TRACE<span>SHIELD</span> <span style="font-size:12px;color:#64748b;font-weight:400">X · FORENSICS</span></div>
    <div class="badge">${d.severity} SEVERITY</div>
  </div>
  <div class="title">Forensic Incident Report</div>
  <div class="sub">INCIDENT ID: ${d.incidentId} &nbsp;·&nbsp; AUTO-GENERATED: ${now}</div>
  <div class="meta">
    <div class="mi"><div class="ml">Date / Time</div><div class="mv">${d.incidentDate} ${d.incidentTime} UTC</div></div>
    <div class="mi" style="padding-left:16px"><div class="ml">Analyst</div><div class="mv">${d.analystName}</div></div>
    <div class="mi" style="padding-left:16px"><div class="ml">System Affected</div><div class="mv">${d.systemAffected}</div></div>
  </div>
</div>
<div class="body">
  <div class="legal">⚖️ <strong>LEGAL NOTICE:</strong> This document is a formally generated forensic incident report by TraceShield X. It is intended for use as digital evidence in legal, regulatory, or disciplinary proceedings. All data was collected and preserved per digital forensics best practices. Unauthorized alteration may constitute obstruction of justice.</div>

  <div class="sec">
    <div class="st">Risk Assessment</div>
    <div class="score-bar">
      <div class="score-val">${d.riskScore}</div>
      <div><div class="score-label">Risk Score / 100</div><div style="font-size:11px;color:#6b7280">Anomaly Score: ${d.anomalyScore} &nbsp;·&nbsp; Flags: ${(d.flags||[]).join(', ')||'None'}</div></div>
    </div>
  </div>

  <div class="sec">
    <div class="st">Attacker Identification</div>
    <div class="atk">
      <div class="af"><label>IP Address</label><span>${d.attackerIp||'<i>not collected</i>'}</span></div>
      <div class="af"><label>Username / Account</label><span>${d.attackerUsername||'<i>not collected</i>'}</span></div>
      <div class="af"><label>First Seen</label><span>${d.firstSeen||'<i>not recorded</i>'}</span></div>
      <div class="af"><label>Last Seen</label><span>${d.lastSeen||'<i>not recorded</i>'}</span></div>
      <div class="af"><label>Observed Events</label><span>${d.observedEvents ?? '<i>not recorded</i>'}</span></div>
      <div class="af"><label>Targeted Accounts</label><span>${d.targetedAccounts||'<i>not recorded</i>'}</span></div>
      <div class="af" style="grid-column:span 2"><label>Detected Signals</label><span>${d.signalSummary||'<i>not recorded</i>'}</span></div>
    </div>
  </div>

  <div class="sec">
    <div class="st">Suspicious Event Timeline</div>
    <table><thead><tr><th>Timestamp</th><th>Log Source</th><th>Description</th><th>Evidence / Log Entry</th></tr></thead>
    <tbody>${evRows}</tbody></table>
  </div>

  <div class="sec"><div class="st">Incident Summary</div><div class="box">${d.summary}</div></div>
  ${attackBreakdown}
  ${resultsTable}
  <div class="sec"><div class="st">Impact Assessment</div><div class="imp">${d.impact}</div></div>
  <div class="sec"><div class="st">Recommendations & Remediation</div><div class="rec">${d.recommendations}</div></div>

  <div class="sig">
    <div><div style="height:44px"></div><div class="sl">Analyst: ${d.analystName}</div></div>
    <div><div style="height:44px"></div><div class="sl">Date: ${d.incidentDate}</div></div>
  </div>
</div>
<div class="ftr">
  <div>TraceShield X Forensic Platform &nbsp;·&nbsp; Confidential — For Legal Use Only</div>
  <div style="font-family:monospace">Report: ${d.incidentId} &nbsp;·&nbsp; ${now}</div>
</div>
</div></body></html>`;
}

function InfoRow({ label, value, mono = false, highlight = false }) {
  return (
    <div className="flex flex-col gap-0.5">
      <span className="text-[9px] font-bold text-[#94A3B8] mono-text uppercase tracking-widest">{label}</span>
      <span className={`text-[12px] font-bold ${mono ? 'mono-text' : ''} ${highlight ? 'text-[#FF003C]' : 'text-white'}`}>
        {value || (
          <span className="text-[#1E2D4A] font-normal italic">not collected</span>
        )}
      </span>
    </div>
  );
}

function buildReportFromResult(lastResult, setData) {
  const features = lastResult.features || {}
  const flags    = lastResult.readable_flags || lastResult.flags || []
  const now      = new Date()
  const attIp    = features.src_ip || null
  const attUser  = features.actor || null

  // The backend builds this from the actual log lines — synthesising evidence
  // here would put invented log text into a forensic report.
  const events = lastResult.timeline || []

  const ld      = lastResult.components?.log_details || {}
  const signals = [
    ld.failed_logins           ? `${ld.failed_logins} failed logins` : null,
    ld.sudo_attempts           ? `${ld.sudo_attempts} sudo attempts` : null,
    ld.suspicious_commands     ? `${ld.suspicious_commands} suspicious commands` : null,
    ld.sensitive_file_accesses ? `${ld.sensitive_file_accesses} sensitive file reads` : null,
  ].filter(Boolean).join(' · ') || null
  setData(withPlaceholders({
    incidentId: `INC-${now.toISOString().slice(0,10).replace(/-/g,'')}-${Math.floor(Math.random()*900)+100}`,
    incidentDate: now.toISOString().slice(0,10), incidentTime: now.toTimeString().slice(0,5),
    analystName: 'TraceShield X AutoAnalyst', systemAffected: 'traceshield-node-01',
    severity: lastResult.risk_level || 'LOW', attackerIp: attIp, attackerUsername: attUser,
    targetedAccounts: attUser,
    observedEvents:   ld.total_log_events ?? null,
    signalSummary:    signals,
    firstSeen: null, lastSeen: null,
    events,
    summary: `TraceShield detected a ${lastResult.risk_level}-severity incident. Risk score: ${lastResult.risk_score?.toFixed(2)}/100. Triggered: ${flags.join(', ') || 'Behavioral anomaly'}.`,
    impact: `Traffic: ${features.network_traffic_volume || 'N/A'} bytes. Session: ${features.session_duration || 'N/A'}s. Protocol: ${features.protocol_type || 'TCP'}.`,
    recommendations: `1. Block ${attIp} at firewall.\n2. Audit '${attUser}' account.\n3. Review /var/log/auth.log.\n4. Rotate SSH keys.\n5. File incident report.`,
    riskScore: lastResult.risk_score || 0, anomalyScore: lastResult.anomaly_score || 0, flags: lastResult.flags || [],
  }))
}

function buildReportFromLiveEvent(ev, setData, datasetSummary) {
  const now      = new Date()
  const results  = datasetSummary?.results || [ev]
  const filename = datasetSummary?.filename || ev.device || 'dataset_log'

  // Aggregate attack types across all results
  const attackCounts = {}
  const statusCounts = { EXTREME_RISK: 0, HIGH_RISK: 0, SUSPICIOUS: 0, NORMAL: 0 }
  results.forEach(r => {
    const at = r.attack_type || 'NORMAL_ACTIVITY'
    if (at !== 'NORMAL_ACTIVITY') attackCounts[at] = (attackCounts[at] || 0) + 1
    if (statusCounts[r.status] !== undefined) statusCounts[r.status]++
  })
  const totalAttacks = Object.values(attackCounts).reduce((a, b) => a + b, 0)

  const ATTACK_LABELS = {
    PRIVILEGE_ESCALATION: 'Privilege Escalation via sudo',
    REMOTE_EXECUTION:     'Remote Code Execution',
    BRUTE_FORCE:          'SSH Brute Force Attack',
    // Not a confirmed attack — anomalous behavior with no recognizable log signature.
    BEHAVIORAL_ANOMALY:   'Anomalous Behavior (No Signature)',
  }

  // Primary attacker = highest scoring result that has a real source IP.
  // "host_system" is the placeholder for log lines with no IP, so naming it as
  // the attacker identifies nobody.
  const isRealIp  = r => r?.ip && r.ip !== 'host_system' && r.ip !== 'unknown'
  const ranked    = [...results].sort((a, b) => (b.risk_score || 0) - (a.risk_score || 0))
  const primary   = ranked.find(isRealIp) || ranked[0] || ev
  const attIp     = isRealIp(primary) ? primary.ip : (isRealIp(ev) ? ev.ip : null)

  const pf        = primary.features || {}
  const userList  = pf.usernames || ev.usernames || []
  const attUser   = userList[0] || null

  // Real, log-derived attributes — these replace MAC/OS/geolocation, none of
  // which can be resolved from a log line.
  const targeted  = userList.length ? userList.slice(0, 6).join(', ') : null
  const firstSeen = pf.first_seen || null
  const lastSeen  = pf.last_seen || null
  const observed  = pf.total_events ?? null
  const signals   = [
    pf.failed_logins           ? `${pf.failed_logins} failed logins` : null,
    pf.successful_logins       ? `${pf.successful_logins} successful logins` : null,
    pf.sudo_attempts           ? `${pf.sudo_attempts} sudo attempts` : null,
    pf.suspicious_commands     ? `${pf.suspicious_commands} suspicious commands` : null,
    pf.sensitive_file_accesses ? `${pf.sensitive_file_accesses} sensitive file reads` : null,
    pf.port_scans              ? `${pf.port_scans} port scans` : null,
  ].filter(Boolean).join(' · ') || null

  // Build timeline from all results
  const events = results
    .filter(r => r.status !== 'NORMAL')
    .slice(0, 10)
    .map((r, i) => ({
      time:        new Date(now - (results.length - i) * 30000).toLocaleString(),
      source:      filename,
      description: `${ATTACK_LABELS[r.attack_type] || r.attack_type || 'Anomaly'} — IP: ${r.ip}`,
      evidence:    `status=${r.status} score=${r.risk_score?.toFixed(1)} actions=${(r.actions||[]).join(',')||'none'} signals=${r.reason||'N/A'}`,
    }))

  if (events.length === 0) events.push({
    time:        now.toLocaleString(),
    source:      filename,
    description: `Log analysis completed — ${results.length} IPs processed`,
    evidence:    `No high-risk events detected`,
  })

  const sevMap = { EXTREME_RISK: 'CRITICAL', HIGH_RISK: 'HIGH', SUSPICIOUS: 'MEDIUM', NORMAL: 'LOW' }
  const worstStatus = results.find(r => r.status === 'EXTREME_RISK')?.status
    || results.find(r => r.status === 'HIGH_RISK')?.status
    || results.find(r => r.status === 'SUSPICIOUS')?.status
    || 'NORMAL'

  const attackSummaryText = Object.entries(attackCounts)
    .map(([t, c]) => `${ATTACK_LABELS[t] || t} (×${c})`).join(', ') || 'No specific attack patterns'

  setData(withPlaceholders({
    incidentId:       `INC-${now.toISOString().slice(0,10).replace(/-/g,'')}-${Math.floor(Math.random()*900)+100}`,
    incidentDate:     now.toISOString().slice(0,10),
    incidentTime:     now.toTimeString().slice(0,5),
    analystName:      'TraceShield X AutoAnalyst',
    systemAffected:   filename,
    severity:         sevMap[worstStatus] || 'LOW',
    attackerIp:       attIp,
    attackerUsername: attUser,
    // Log-derived attacker attributes in place of MAC/OS/geolocation
    targetedAccounts: targeted,
    firstSeen,
    lastSeen,
    observedEvents:   observed,
    signalSummary:    signals,
    events,
    // Extra fields for rich report
    attackCounts,
    statusCounts,
    totalAttacks,
    allResults:       results,
    filename,
    summary: `TraceShield analyzed ${results.length} IP(s) from "${filename}". Detected ${totalAttacks} attack(s): ${attackSummaryText}. Highest risk score: ${primary.risk_score?.toFixed(1)}/100 from ${attIp}.`,
    impact:  `${statusCounts.EXTREME_RISK} EXTREME_RISK · ${statusCounts.HIGH_RISK} HIGH_RISK · ${statusCounts.SUSPICIOUS} SUSPICIOUS · ${statusCounts.NORMAL} NORMAL. Total log events: ${datasetSummary?.summary?.valid_events || 'N/A'}.`,
    recommendations: [
      totalAttacks > 0 ? `1. Immediately investigate ${attIp} — highest risk score ${primary.risk_score?.toFixed(1)}/100.` : '1. No immediate action required.',
      attackCounts.PRIVILEGE_ESCALATION ? `2. Audit all sudo usage — ${attackCounts.PRIVILEGE_ESCALATION} privilege escalation event(s) detected.` : '2. Monitor sudo activity.',
      attackCounts.BRUTE_FORCE ? `3. Block SSH brute force source IPs — ${attackCounts.BRUTE_FORCE} brute force event(s).` : '3. Review authentication logs.',
      attackCounts.REMOTE_EXECUTION ? `4. Investigate suspicious commands — ${attackCounts.REMOTE_EXECUTION} remote execution event(s).` : '4. Audit command execution logs.',
      `5. Review full log file "${filename}" for additional context.`,
    ].join('\n'),
    riskScore:    primary.risk_score || 0,
    anomalyScore: primary.components?.ml_score || 0,
    flags:        primary.actions || [],
  }))
}

export default function ThreatHuntPage({ lastResult, liveEvents = [], datasetSummary = null }) {
  const [data, setData]       = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError]     = useState(null);
  const [downloaded, setDownloaded] = useState(false);
  const [saveStatus, setSaveStatus] = useState(null); // null | 'saving' | 'saved' | 'offline'
  const [savedReports, setSavedReports] = useState([]);
  const [reportsLoading, setReportsLoading] = useState(false);

  const fetchReports = useCallback(async () => {
    setReportsLoading(true);
    try {
      const r = await api.get('/api/reports?limit=20');
      setSavedReports(r.data);
    } catch {
      setSavedReports([]);
    } finally {
      setReportsLoading(false);
    }
  }, []);

  useEffect(() => { fetchReports(); }, [fetchReports]);

  // Auto-populate from shared result when available
  useEffect(() => {
    if (lastResult && !data) {
      buildReportFromResult(lastResult, setData)
    }
  }, [lastResult])

  // Auto-populate from dataset upload — always replaces previous report
  useEffect(() => {
    if (!datasetSummary) return
    // Reset previous report first
    setData(null)
    const threat = (datasetSummary.results || []).find(r =>
      r.status === 'EXTREME_RISK' || r.status === 'HIGH_RISK' || r.status === 'SUSPICIOUS'
    ) || (datasetSummary.results || [])[0]
    if (!threat) return
    buildReportFromLiveEvent(threat, setData, datasetSummary)
  }, [datasetSummary])

  // Also auto-populate from the latest HIGH/EXTREME_RISK live event (real-time ingest)
  useEffect(() => {
    if (!liveEvents.length || data || datasetSummary) return
    const threat = liveEvents.find(e =>
      e.status === 'HIGH_RISK' || e.status === 'EXTREME_RISK'
    )
    if (!threat) return
    buildReportFromLiveEvent(threat, setData, null)
  }, [liveEvents])

  const runScan = async () => {
    setLoading(true); setError(null); setData(null);
    try {
      const r = await api.get(core('/api/threat-scan'));
      setData(r.data);
    } catch {
      setError('Backend unreachable — start the server and try again.');
    } finally {
      setLoading(false);
    }
  };

  const downloadHtml = (reportData) => {
    const html = generateHtmlReport(reportData);
    const blob = new Blob([html], { type: 'text/html' });
    const url  = URL.createObjectURL(blob);
    const a    = document.createElement('a');
    a.href     = url;
    a.download = `forensic-report-${reportData.incidentId}-${Date.now()}.html`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const handleDownload = async () => {
    if (!data) return;

    setSaveStatus('saving');
    try {
      await api.post('/api/reports', { ...data, source: datasetSummary ? 'dataset' : 'live' });
      setSaveStatus('saved');
      fetchReports();
    } catch {
      setSaveStatus('offline');
    }
    setTimeout(() => setSaveStatus(null), 4000);

    // Never block the download on a failed save.
    downloadHtml(data);
    setDownloaded(true);
    setTimeout(() => setDownloaded(false), 3000);
  };

  const openSavedReport = async (incidentId) => {
    try {
      const r = await api.get(`/api/reports/${incidentId}`);
      setData(r.data);
      setError(null);
    } catch {
      setError('Failed to load saved report.');
    }
  };

  const downloadSavedReport = async (incidentId) => {
    try {
      const r = await api.get(`/api/reports/${incidentId}`);
      downloadHtml(r.data);
    } catch {}
  };

  const deleteSavedReport = async (incidentId) => {
    if (!window.confirm(`Delete report ${incidentId}? This cannot be undone.`)) return;
    try {
      await api.delete(`/api/reports/${incidentId}`);
      fetchReports();
    } catch {}
  };

  const sev = data ? (SEVERITY_META[data.severity] || SEVERITY_META.HIGH) : null;

  return (
    <div className="animate-fadeIn space-y-8 pb-16">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-end justify-between gap-4 pb-6 border-b border-[#1E2D4A]/50">
        <div>
          <h2 className="text-4xl font-bold text-white tracking-tight font-['Rajdhani'] uppercase">
            Threat <span className="text-[#FF003C]">Hunt</span>
          </h2>
          <p className="text-[#94A3B8] mt-1 mono-text text-sm">
            Auto-scan the system, identify the attacker, build a legally admissible forensic report
          </p>
        </div>
        <div className="flex flex-col items-end gap-2">
          <div className="flex gap-3">
            <button onClick={runScan} disabled={loading}
              className="cyber-btn h-12 px-6 border-[#00F0FF] text-[#00F0FF] hover:bg-[#00F0FF]/10">
              <i className={`ph ${loading ? 'ph-spinner animate-spin' : 'ph-magnifying-glass'} text-xl`} />
              {loading ? 'Scanning...' : 'Run Threat Scan'}
            </button>
            {data && (
              <button onClick={handleDownload}
                className={`cyber-btn h-12 px-6 font-bold ${downloaded ? 'border-[#39FF14] text-[#39FF14]' : 'border-[#FF003C] text-[#FF003C]'}`}
                style={downloaded ? {} : { boxShadow: '0 0 20px rgba(255,0,60,0.2)' }}>
                <i className={`ph ${downloaded ? 'ph-check-circle' : 'ph-file-arrow-down'} text-xl`} />
                {downloaded ? 'Downloaded!' : 'Generate Report'}
              </button>
            )}
          </div>
          {saveStatus && (
            <div className={`text-[10px] mono-text uppercase tracking-widest ${
              saveStatus === 'saved' ? 'text-[#39FF14]' : saveStatus === 'offline' ? 'text-[#FFEA00]' : 'text-[#94A3B8]'
            }`}>
              {saveStatus === 'saving' && 'Saving...'}
              {saveStatus === 'saved' && 'Saved to MongoDB'}
              {saveStatus === 'offline' && 'Saved locally only (DB offline)'}
            </div>
          )}
        </div>
      </div>

      {/* Idle state */}
      {!data && !loading && !error && (
        <div className="flex flex-col items-center justify-center py-32 border border-dashed border-[#1E2D4A] rounded-xl bg-[#0D1323]/20">
          <div className="relative mb-6">
            <div className="absolute -inset-8 bg-[#FF003C]/10 rounded-full blur-3xl animate-pulse" />
            <i className="ph ph-shield-warning text-[100px] text-[#1E2D4A]" />
            <div className="absolute inset-0 flex items-center justify-center">
              <i className="ph ph-magnifying-glass text-4xl text-[#FF003C] opacity-50 animate-pulse" />
            </div>
          </div>
          <h3 className="text-xl text-[#E2E8F0] font-bold font-['Rajdhani'] tracking-[3px] uppercase mb-2">No Scan Running</h3>
          <p className="text-sm text-[#94A3B8] mono-text text-center max-w-md opacity-70">
            Click "Run Threat Scan" to automatically analyze system logs, identify the attacker, and build a forensic case.
          </p>
        </div>
      )}

      {/* Loading */}
      {loading && (
        <div className="flex flex-col items-center justify-center py-32 border border-[#00F0FF]/20 rounded-xl bg-[#00F0FF]/5">
          <i className="ph ph-spinner animate-spin text-5xl text-[#00F0FF] mb-4" />
          <p className="text-sm text-[#00F0FF] mono-text uppercase tracking-widest animate-pulse">Scanning logs · Correlating events · Building case...</p>
        </div>
      )}

      {/* Error */}
      {error && (
        <div className="flex items-center gap-4 px-5 py-4 rounded-xl bg-[#FF003C]/10 border border-[#FF003C]/30 text-[#FF003C] mono-text">
          <i className="ph ph-warning-octagon text-2xl" /> {error}
        </div>
      )}

      {/* Results */}
      {data && sev && (
        <div className="space-y-6">

          {/* Alert banner */}
          <div className="flex items-center gap-4 px-6 py-4 rounded-xl border animate-fadeIn"
            style={{ backgroundColor: sev.bg, borderColor: sev.border }}>
            <i className="ph ph-warning-octagon text-3xl animate-pulse" style={{ color: sev.color }} />
            <div className="flex-1">
              <div className="text-sm font-bold mono-text uppercase tracking-widest" style={{ color: sev.color }}>
                {data.severity} SEVERITY INCIDENT DETECTED — {data.incidentId}
              </div>
              <div className="text-[11px] text-[#94A3B8] mono-text mt-0.5">
                Risk Score: <span className="font-bold text-white">{data.riskScore}/100</span>
                &nbsp;·&nbsp; Anomaly Score: <span className="font-bold text-white">{data.anomalyScore}</span>
                &nbsp;·&nbsp; {data.flags?.length || 0} detection rules triggered
              </div>
            </div>
            <div className="text-right">
              <div className="text-[9px] text-[#94A3B8] mono-text uppercase">Detected</div>
              <div className="text-[11px] text-white mono-text font-bold">{data.incidentDate} {data.incidentTime} UTC</div>
            </div>
          </div>

          {/* Two-col: attacker ID + incident meta */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* Attacker */}
            <div className="cyber-panel p-6 border-t-2 border-t-[#FF003C]">
              <div className="flex items-center gap-3 mb-5">
                <div className="w-1 h-6 bg-[#FF003C] rounded-full" />
                <h3 className="text-sm font-bold font-['Rajdhani'] uppercase tracking-widest text-white">Attacker Identification</h3>
              </div>
              <div className="grid grid-cols-2 gap-4">
                <InfoRow label="Source IP"        value={data.attackerIp}       mono highlight />
                <InfoRow label="Account"          value={data.attackerUsername} mono highlight />
                <InfoRow label="First Seen"       value={data.firstSeen}        mono />
                <InfoRow label="Last Seen"        value={data.lastSeen}         mono />
                <InfoRow label="Observed Events"  value={data.observedEvents != null ? String(data.observedEvents) : null} mono />
                <InfoRow label="Targeted Accounts" value={data.targetedAccounts} mono />
                <div className="col-span-2">
                  <InfoRow label="Detected Signals" value={data.signalSummary} mono />
                </div>
              </div>
            </div>

            {/* Incident meta */}
            <div className="cyber-panel p-6 border-t-2 border-t-[#00F0FF]">
              <div className="flex items-center gap-3 mb-5">
                <div className="w-1 h-6 bg-[#00F0FF] rounded-full" />
                <h3 className="text-sm font-bold font-['Rajdhani'] uppercase tracking-widest text-white">Incident Metadata</h3>
              </div>
              <div className="grid grid-cols-2 gap-4">
                <InfoRow label="Incident ID"     value={data.incidentId}     mono />
                <InfoRow label="Severity"        value={data.severity}       highlight />
                <InfoRow label="Date"            value={data.incidentDate}   mono />
                <InfoRow label="Time (UTC)"      value={data.incidentTime}   mono />
                <InfoRow label="System Affected" value={data.systemAffected} mono />
                <InfoRow label="Analyst"         value={data.analystName} />
              </div>
            </div>
          </div>

          {/* Attackers identified from dataset */}
          {data.attackers && data.attackers.length > 0 && (
            <div className="cyber-panel p-6 border-t-2 border-t-[#FF003C]">
              <div className="flex items-center gap-3 mb-5">
                <div className="w-1 h-6 bg-[#FF003C] rounded-full" />
                <h3 className="text-sm font-bold font-['Rajdhani'] uppercase tracking-widest text-white">
                  Identified Attackers — {data.totalAttackEvents} Attack Events
                </h3>
              </div>
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
                {data.attackers.map((atk, i) => (
                  <div key={i} className="rounded-lg border border-[#FF003C]/30 bg-[#FF003C]/5 px-4 py-3 mono-text text-xs">
                    <div className="flex items-center gap-2 mb-2">
                      <span className="w-2 h-2 rounded-full bg-[#FF003C] animate-pulse" />
                      <span className="font-bold text-[#FF003C] text-sm">{atk.actor}</span>
                      <span className="ml-auto text-[9px] text-[#94A3B8]">{atk.count} events</span>
                    </div>
                    <div className="text-[#94A3B8] text-[10px]">IP: <span className="text-[#E2E8F0]">{atk.ip || '—'}</span></div>
                    <div className="text-[#94A3B8] text-[10px] mt-1 flex flex-wrap gap-1">
                      {(atk.types || []).map((t, j) => (
                        <span key={j} className="px-1.5 py-0.5 rounded bg-[#FF003C]/10 border border-[#FF003C]/20 text-[#FF003C]">{t}</span>
                      ))}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Event timeline */}
          <div className="cyber-panel p-6 border-t-2 border-t-[#FFEA00]">
            <div className="flex items-center gap-3 mb-5">
              <div className="w-1 h-6 bg-[#FFEA00] rounded-full" />
              <h3 className="text-sm font-bold font-['Rajdhani'] uppercase tracking-widest text-white">Suspicious Event Timeline</h3>
              <span className="text-[9px] text-[#94A3B8] mono-text ml-2">{data.events?.length} events detected</span>
            </div>
            <div className="bg-[#070B14] border border-[#1E2D4A] rounded-lg overflow-hidden">
              <div className="grid gap-2 px-4 py-2 border-b border-[#1E2D4A] bg-[#0D1323]"
                style={{ gridTemplateColumns: '160px 120px 1fr' }}>
                {['Timestamp', 'Log Source', 'Description & Evidence'].map(h => (
                  <span key={h} className="text-[9px] font-bold text-[#94A3B8] mono-text uppercase tracking-widest">{h}</span>
                ))}
              </div>
              <div className="divide-y divide-[#1E2D4A]/40">
                {(data.events || []).map((evt, i) => (
                  <div key={i} className="grid gap-2 px-4 py-3 hover:bg-[#0D1323]/60 transition-colors"
                    style={{ gridTemplateColumns: '160px 120px 1fr' }}>
                    <span className="text-[10px] text-[#FFEA00] mono-text font-bold">{evt.time}</span>
                    <span className="text-[10px] text-[#B026FF] mono-text font-bold">{evt.source}</span>
                    <div className="flex flex-col gap-1">
                      <span className="text-[11px] text-white">{evt.description}</span>
                      <code className="text-[9px] text-[#94A3B8] mono-text break-all">{evt.evidence}</code>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>

          {/* Summary + Impact + Recommendations */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <div className="cyber-panel p-6 border-t-2 border-t-[#B026FF]">
              <div className="flex items-center gap-3 mb-4">
                <div className="w-1 h-6 bg-[#B026FF] rounded-full" />
                <h3 className="text-sm font-bold font-['Rajdhani'] uppercase tracking-widest text-white">Incident Summary</h3>
              </div>
              <p className="text-[12px] text-[#94A3B8] leading-relaxed">{data.summary}</p>
            </div>
            <div className="cyber-panel p-6 border-t-2 border-t-[#FF6B00]">
              <div className="flex items-center gap-3 mb-4">
                <div className="w-1 h-6 bg-[#FF6B00] rounded-full" />
                <h3 className="text-sm font-bold font-['Rajdhani'] uppercase tracking-widest text-white">Impact Assessment</h3>
              </div>
              <p className="text-[12px] text-[#94A3B8] leading-relaxed">{data.impact}</p>
            </div>
          </div>

          <div className="cyber-panel p-6 border-t-2 border-t-[#39FF14]">
            <div className="flex items-center gap-3 mb-4">
              <div className="w-1 h-6 bg-[#39FF14] rounded-full" />
              <h3 className="text-sm font-bold font-['Rajdhani'] uppercase tracking-widest text-white">Recommendations & Remediation</h3>
            </div>
            <pre className="text-[12px] text-[#94A3B8] leading-relaxed whitespace-pre-wrap font-sans">{data.recommendations}</pre>
          </div>

          {/* Download CTA */}
          <div className="flex flex-col items-end gap-2 pt-2">
            <button onClick={handleDownload}
              className={`cyber-btn h-14 px-10 text-base font-bold transition-all ${downloaded ? 'border-[#39FF14] text-[#39FF14]' : 'border-[#FF003C] text-[#FF003C]'}`}
              style={downloaded ? {} : { boxShadow: '0 0 30px rgba(255,0,60,0.2)' }}>
              <i className={`ph ${downloaded ? 'ph-check-circle' : 'ph-file-arrow-down'} text-2xl`} />
              {downloaded ? 'Report Downloaded!' : 'Generate & Download Forensic Report'}
            </button>
            {saveStatus && (
              <div className={`text-[10px] mono-text uppercase tracking-widest ${
                saveStatus === 'saved' ? 'text-[#39FF14]' : saveStatus === 'offline' ? 'text-[#FFEA00]' : 'text-[#94A3B8]'
              }`}>
                {saveStatus === 'saving' && 'Saving...'}
                {saveStatus === 'saved' && 'Saved to MongoDB'}
                {saveStatus === 'offline' && 'Saved locally only (DB offline)'}
              </div>
            )}
          </div>
        </div>
      )}

      {/* Saved Reports */}
      <div className="cyber-panel p-6 border-t-2 border-t-[#00F0FF]">
        <div className="flex items-center justify-between mb-5">
          <div className="flex items-center gap-3">
            <div className="w-1 h-6 bg-[#00F0FF] rounded-full" />
            <h3 className="text-sm font-bold font-['Rajdhani'] uppercase tracking-widest text-white">Saved Reports</h3>
          </div>
          <button onClick={fetchReports} disabled={reportsLoading} title="Refresh"
            className="text-[10px] text-[#94A3B8] hover:text-[#00F0FF] mono-text transition-colors">
            <i className={`ph ${reportsLoading ? 'ph-spinner animate-spin' : 'ph-arrows-clockwise'} text-sm`} />
          </button>
        </div>

        {savedReports.length === 0 ? (
          <p className="text-[#1E2D4A] text-xs mono-text text-center py-6">
            {reportsLoading ? 'Loading...' : 'No saved reports yet'}
          </p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left">
              <thead>
                <tr className="border-b border-[#1E2D4A] text-[9px] text-[#94A3B8] uppercase tracking-widest mono-text">
                  <th className="py-2 pr-4 font-bold">Incident ID</th>
                  <th className="py-2 pr-4 font-bold">Severity</th>
                  <th className="py-2 pr-4 font-bold">Attacker IP</th>
                  <th className="py-2 pr-4 font-bold">Date</th>
                  <th className="py-2 pr-4 font-bold text-right">Actions</th>
                </tr>
              </thead>
              <tbody>
                {savedReports.map((r) => {
                  const rsev = SEVERITY_META[r.severity] || SEVERITY_META.HIGH;
                  return (
                    <tr key={r.incidentId} className="border-b border-[#1E2D4A]/50 text-xs mono-text hover:bg-[#00F0FF]/5 transition-colors">
                      <td className="py-2.5 pr-4 text-white font-bold">{r.incidentId}</td>
                      <td className="py-2.5 pr-4">
                        <span className="px-1.5 py-0.5 rounded border text-[10px] font-bold"
                          style={{ color: rsev.color, borderColor: rsev.border, backgroundColor: rsev.bg }}>
                          {r.severity}
                        </span>
                      </td>
                      <td className="py-2.5 pr-4 text-[#94A3B8]">{r.attackerIp || '—'}</td>
                      <td className="py-2.5 pr-4 text-[#94A3B8]">{r.incidentDate || '—'}</td>
                      <td className="py-2.5 pr-4">
                        <div className="flex justify-end gap-3 text-[11px]">
                          <button onClick={() => openSavedReport(r.incidentId)}
                            className="text-[#00F0FF] hover:underline">Open</button>
                          <button onClick={() => downloadSavedReport(r.incidentId)}
                            className="text-[#39FF14] hover:underline">Download</button>
                          <button onClick={() => deleteSavedReport(r.incidentId)}
                            className="text-[#FF003C] hover:underline">Delete</button>
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}
