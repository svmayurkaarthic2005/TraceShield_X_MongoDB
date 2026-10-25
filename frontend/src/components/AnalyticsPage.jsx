import React, { useCallback, useEffect, useRef, useState } from 'react';
import api, { ingest } from '../services/api';
import SimulatedBadge, { SimulatedFrame } from './SimulatedBadge';

// Shared by every modal in this file: closes on Escape, and locks background
// scroll while open. Each effect captures body.style.overflow as it actually
// is when the modal opens (not a hardcoded ''), and restores exactly that on
// cleanup — so if two modals were ever open at once, closing the inner one
// restores "hidden" (what the outer modal set) instead of unlocking the page.
function useModalEscapeAndScrollLock(isOpen, onClose) {
  useEffect(() => {
    if (!isOpen) return
    const onKeyDown = (e) => { if (e.key === 'Escape') onClose() }
    window.addEventListener('keydown', onKeyDown)
    const prevOverflow = document.body.style.overflow
    document.body.style.overflow = 'hidden'
    return () => {
      window.removeEventListener('keydown', onKeyDown)
      document.body.style.overflow = prevOverflow
    }
  }, [isOpen, onClose])
}

function PulseGraph({ data, threshold = 75 }) {
  const [hoveredIndex, setHoveredIndex] = useState(null);

  // Fixed pixel dimensions for the plot area
  const W = 500, H = 80;
  const toX = i => (i / (data.length - 1)) * W;
  const toY = v => H - (v / 100) * H;
  const threshY = toY(threshold);

  const linePath = data.map((v, i) => (i === 0 ? 'M' : 'L') + ' ' + toX(i).toFixed(1) + ' ' + toY(v).toFixed(1)).join(' ')
  const fillPath = 'M ' + toX(0).toFixed(1) + ' ' + H + ' ' + data.map((v, i) => 'L ' + toX(i).toFixed(1) + ' ' + toY(v).toFixed(1)).join(' ') + ' L ' + W + ' ' + H + ' Z'

  return (
    <div className="bg-[#070B14] border border-[#1E2D4A] rounded-lg p-4 flex flex-col relative shadow-inner transition-all" style={{ height: '200px' }}>
      {/* Header */}
      <div className="flex justify-between items-center mb-2">
        <div className="flex flex-col">
          <span className="text-[10px] text-[#94A3B8] mono-text uppercase tracking-widest">Behavioral_Pulse_Graph</span>
          <span className="text-[10px] text-[#00F0FF] mono-text opacity-50">ISOLATION_FOREST_STREAM_V2</span>
        </div>
        <div className="flex gap-2 items-center bg-[#39FF14]/5 px-3 py-1 rounded-full border border-[#39FF14]/20">
          <div className="w-1.5 h-1.5 rounded-full bg-[#39FF14] animate-pulse" />
          <span className="text-[10px] text-[#39FF14] font-bold mono-text uppercase tracking-widest">Real_Time</span>
        </div>
      </div>

      {/* Chart: Y-axis label + plot + Y ticks */}
      <div className="flex flex-1 gap-1 min-h-0">

        {/* Y-axis title (rotated) */}
        <div className="flex items-center justify-center flex-shrink-0" style={{ width: '14px' }}>
          <span className="text-[8px] text-[#00F0FF] mono-text opacity-50 uppercase tracking-widest"
            style={{ writingMode: 'vertical-rl', transform: 'rotate(180deg)', whiteSpace: 'nowrap' }}>
            Variance
          </span>
        </div>

        {/* Y tick labels */}
        <div className="flex flex-col justify-between flex-shrink-0 text-right py-0" style={{ width: '22px' }}>
          {['1.0','0.75','0.5','0.25','0.0'].map(l => (
            <span key={l} className="text-[8px] text-[#00F0FF] mono-text opacity-50 leading-none">{l}</span>
          ))}
        </div>

        {/* SVG plot */}
        <div className="flex-1 flex flex-col min-w-0 gap-1">
          <div className="relative flex-1 min-h-0">
            <svg
              viewBox={`0 0 ${W} ${H}`}
              preserveAspectRatio="none"
              className="w-full h-full"
              style={{ display: 'block' }}
              onMouseLeave={() => setHoveredIndex(null)}
            >
              <defs>
                <linearGradient id="pgFill" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor="#00F0FF" stopOpacity="0.25" />
                  <stop offset="100%" stopColor="#00F0FF" stopOpacity="0" />
                </linearGradient>
              </defs>

              {/* Grid lines at 0, 25, 50, 75, 100 */}
              {[0,25,50,75,100].map(v => (
                <line key={v} x1="0" y1={toY(v)} x2={W} y2={toY(v)}
                  stroke="#1E2D4A" strokeWidth="0.8" strokeDasharray="4,4" opacity="0.6" />
              ))}

              {/* Threshold line */}
              <line x1="0" y1={threshY} x2={W} y2={threshY}
                stroke="#FF003C" strokeWidth="0.8" strokeDasharray="5,4" opacity="0.8" />
              <text x="4" y={threshY - 3} fill="#FF003C" fontSize="7"
                fontFamily="monospace" opacity="0.75" fontWeight="bold">THRESHOLD</text>

              {/* Fill */}
              <path d={fillPath} fill="url(#pgFill)" />

              {/* Line */}
              <path d={linePath} fill="none" stroke="#00F0FF" strokeWidth="1"
                strokeLinecap="round" strokeLinejoin="round"
                style={{ filter: 'drop-shadow(0 0 3px #00F0FF)' }} />

              {/* Hit areas */}
              {data.map((v, i) => (
                <rect key={i}
                  x={toX(i) - W / data.length / 2} y="0"
                  width={W / data.length} height={H}
                  fill="transparent" className="cursor-crosshair"
                  onMouseEnter={() => setHoveredIndex(i)}
                />
              ))}

              {/* Hover crosshair + dot */}
              {hoveredIndex !== null && (
                <>
                  <line x1={toX(hoveredIndex)} y1="0" x2={toX(hoveredIndex)} y2={H}
                    stroke="#00F0FF" strokeWidth="0.5" strokeDasharray="2,2" opacity="0.5" />
                  <circle cx={toX(hoveredIndex)} cy={toY(data[hoveredIndex])} r="2.5"
                    fill="#00F0FF" style={{ filter: 'drop-shadow(0 0 4px #00F0FF)' }} />
                </>
              )}

              {/* Live head */}
              <circle cx={toX(data.length - 1)} cy={toY(data[data.length - 1])} r="2.5"
                fill="#00F0FF" className="animate-pulse"
                style={{ filter: 'drop-shadow(0 0 5px #00F0FF)' }} />
            </svg>

            {/* Hover tooltip */}
            {hoveredIndex !== null && (
              <div className="absolute bg-[#121A2F]/95 border border-[#00F0FF]/60 p-1.5 rounded pointer-events-none z-50 min-w-[90px] backdrop-blur-sm"
                style={{
                  left: `${(hoveredIndex / (data.length - 1)) * 100}%`,
                  top: `${(1 - data[hoveredIndex] / 100) * 100}%`,
                  transform: hoveredIndex > data.length / 2 ? 'translate(-110%,-50%)' : 'translate(8%,-50%)'
                }}>
                <div className="text-[8px] text-[#94A3B8] mono-text border-b border-[#1E2D4A] pb-1 mb-1 flex justify-between">
                  <span>PT #{hoveredIndex}</span>
                  <span className={data[hoveredIndex] > threshold ? 'text-[#FF003C]' : 'text-[#39FF14]'}>
                    {data[hoveredIndex] > threshold ? 'ANOMALY' : 'NOMINAL'}
                  </span>
                </div>
                <div className="text-[9px] text-white mono-text font-bold">{(data[hoveredIndex] / 100).toFixed(3)}</div>
              </div>
            )}
          </div>

          {/* X-axis ticks + label */}
          <div className="flex flex-col gap-0.5">
            <div className="flex justify-between text-[8px] text-[#00F0FF] mono-text opacity-40 pointer-events-none">
              <span>T-30s</span><span>T-20s</span><span>T-10s</span><span>T-0s</span>
            </div>
            <div className="text-center text-[8px] text-[#00F0FF] mono-text opacity-40 uppercase tracking-widest">Time</div>
          </div>
        </div>
      </div>

      {/* Legend */}
      <div className="flex justify-center gap-6 mt-1">
        <div className="flex items-center gap-1.5">
          <div className="w-4 h-px bg-[#00F0FF]" style={{ boxShadow: '0 0 3px #00F0FF' }} />
          <span className="text-[8px] text-[#94A3B8] mono-text uppercase">Variance Flow</span>
        </div>
        <div className="flex items-center gap-1.5">
          <div className="w-4 h-px bg-[#FF003C]" style={{ borderTop: '1px dashed #FF003C' }} />
          <span className="text-[8px] text-[#94A3B8] mono-text uppercase">Detection Limit</span>
        </div>
      </div>
    </div>
  );
}

export default function AnalyticsPage({ lastResult, liveEvents = [] }) {
  const [pulseIndices, setPulseIndices] = useState(Array(20).fill(20))
  const [anomaliesDetected, setAnomaliesDetected] = useState(0)
  const [ipTable, setIpTable]   = useState([])
  const [selectedCmd, setSelectedCmd] = useState(null)
  const [datasetRows, setDatasetRows] = useState([])
  const [ipTableSimulated, setIpTableSimulated] = useState(false)

  const closeCmdModal = useCallback(() => setSelectedCmd(null), [])
  useModalEscapeAndScrollLock(!!selectedCmd, closeCmdModal)

  // Seed from events the ingestion service has actually scored. The dataset
  // rows carry no source IP, so they cannot populate a per-IP table.
  useEffect(() => {
    api.get(ingest('/events/recent?limit=100'))
      .then(r => {
        const events = r.data.events || []
        if (!events.length) { setIpTable(generateIpTable()); setIpTableSimulated(true); return }
        setIpTableSimulated(false)
        setDatasetRows(events)

        // Aggregate per IP — keep each IP's highest-scoring observation
        const byIp = new Map()
        for (const e of events) {
          if (!e.ip || e.ip === 'unknown') continue
          const score = Math.round(e.risk_score ?? 0)
          const prev  = byIp.get(e.ip)
          if (prev && prev.score >= score) { prev.requests += e.request_count || 1; continue }
          const triggered = []
          if (e.attack_type && e.attack_type !== 'NORMAL_ACTIVITY') triggered.push(e.attack_type)
          if (e.status && e.status !== 'NORMAL') triggered.push(e.status)
          byIp.set(e.ip, {
            ip:            e.ip,
            requests:      (prev?.requests || 0) + (e.request_count || 1),
            failedLogins:  Math.round((e.log_score || 0) / 18),
            loginAttempts: e.request_count || 0,
            repScore:      Math.min(1, (e.risk_score ?? 0) / 100),
            oddHours:      0,
            sessionDur:    0,
            score,
            level:         scoreLevel(score),
            triggered,
            usedCmds:      [],
            actor:         e.scenario ? `Scenario: ${e.scenario}` : (e.device || 'unknown'),
            name:          e.attack_type || 'Event',
            rawLog:        e.reason || '',
          })
        }
        setIpTable([...byIp.values()].sort((a, b) => b.score - a.score))

        const last20 = events.slice(0, 20).reverse().map(e => Math.round(e.risk_score ?? 0))
        while (last20.length < 20) last20.unshift(5)
        setPulseIndices(last20)
        setAnomaliesDetected(events.filter(e => e.status && e.status !== 'NORMAL').length)
      })
      .catch(() => { setIpTable(generateIpTable()); setIpTableSimulated(true) })
  }, [])

  // When a new real result comes in, push its risk_score into the pulse graph
  useEffect(() => {
    if (!lastResult) return
    const score = lastResult.risk_score ?? 0
    setPulseIndices(prev => {
      const isAnomaly = score > 35
      if (isAnomaly) setAnomaliesDetected(c => c + 1)
      return [...prev.slice(1), Math.round(score)]
    })
    if (lastResult.features) {
      const f = lastResult.features
      const ip = f.src_ip || '10.0.0.1'
      const failed  = Number(f.failed_logins || 0)
      const rep     = Number(f.ip_reputation_score || 0)
      const odd     = Number(f.unusual_time_access || 0)
      const session = Number(f.session_duration || 0)
      const priv    = Number(f.privilege_escalation || 0)
      const sudo    = Number(f.sudo_attempt || 0)
      const score2  = Math.round(lastResult.risk_score || 0)
      const triggered = []
      if (failed > 0) triggered.push('BRUTE_FORCE')
      if (rep > 0.6)  triggered.push('LOW_REPUTATION_IP')
      if (odd === 1)  triggered.push('ODD_ACCESS_TIME')
      if (priv === 1) triggered.push('PRIVILEGE_ESCALATION')
      const newRow = {
        ip, requests: failed + Number(f.login_attempts||0),
        failedLogins: failed, loginAttempts: Number(f.login_attempts||0),
        repScore: rep, oddHours: odd, sessionDur: session,
        score: score2, level: scoreLevel(score2), triggered, usedCmds: [],
        actor: f.actor || 'unknown', name: f.name || 'Event', rawLog: f.raw_log || '',
      }
      setIpTable(prev => [newRow, ...prev.filter(r => r.ip !== ip)].slice(0, 70).sort((a,b) => b.score - a.score))
    }
  }, [lastResult])

  // Feed live WS events into pulse graph AND IP table
  useEffect(() => {
    if (!liveEvents.length) return
    const latest = liveEvents[0]
    if (!latest) return
    const score = latest.risk_score ?? 0
    setPulseIndices(prev => {
      const isAnomaly = score > 35
      if (isAnomaly) setAnomaliesDetected(c => c + 1)
      return [...prev.slice(1), Math.round(score)]
    })

    // Inject dataset upload events into the IP table
    if (latest.ip && latest.ip !== 'unknown') {
      const failedLogins  = latest.log_score ? Math.round(latest.log_score / 10) : 0
      const repScore      = parseFloat((Math.random() * 0.5).toFixed(2))
      const triggered     = []
      if (latest.attack_type === 'BRUTE_FORCE')          triggered.push('BRUTE_FORCE')
      if (latest.attack_type === 'PRIVILEGE_ESCALATION') triggered.push('PRIV_ESC')
      if (latest.attack_type === 'REMOTE_EXECUTION')     triggered.push('REMOTE_EXEC')
      if (latest.status === 'HIGH_RISK' || latest.status === 'EXTREME_RISK') triggered.push(latest.status)
      const newRow = {
        ip:           latest.ip,
        requests:     latest.request_count || 1,
        failedLogins,
        loginAttempts: failedLogins,
        repScore,
        oddHours:     0,
        sessionDur:   0,
        score:        Math.round(score),
        level:        scoreLevel(Math.round(score)),
        triggered,
        usedCmds:     [],
        attack_type:  latest.attack_type || 'NORMAL_ACTIVITY',
        device:       latest.device || '',
        actor:        latest.scenario ? `Scenario: ${latest.scenario}` : (latest.device || 'unknown'),
      }
      setIpTable(prev => {
        const filtered = prev.filter(r => r.ip !== latest.ip)
        return [newRow, ...filtered].slice(0, 15).sort((a, b) => b.score - a.score)
      })
    }
  }, [liveEvents])

  return (
    <div className="animate-fadeIn space-y-8 pb-10">
      {/* Page Header */}
      <div className="flex flex-col md:flex-row md:items-end justify-between gap-6 pb-6 border-b border-[#1E2D4A]/50">
        <div>
          <h2 className="text-4xl font-bold text-white tracking-tight font-['Rajdhani'] uppercase">Forensic <span className="text-[#00F0FF]">Analytics</span></h2>
          <p className="text-[#94A3B8] mt-1 mono-text text-sm">Cross-Layer Anomaly Correlation & Pattern Intelligence</p>
        </div>
        <div className="flex items-center gap-4 bg-[#121A2F] border border-[#1E2D4A] px-4 py-2 rounded">
           <div className="flex flex-col items-end">
              <span className="text-[9px] text-[#94A3B8] uppercase mono-text">Session_ID</span>
              <span className="text-xs font-bold text-[#00F0FF] mono-text">TSX-9942-X1</span>
           </div>
           <div className="w-[1px] h-8 bg-[#1E2D4A]" />
           <i className="ph ph-fingerprint text-2xl text-[#00F0FF]" />
        </div>
      </div>

      <div className="flex flex-col gap-10">
        
        {/* Layer 1: Behavioral ML */}
        <div className="cyber-panel relative overflow-hidden group p-8">
          <div className="absolute top-0 right-0 p-8 opacity-5">
             <i className="ph ph-brain text-[200px]" />
          </div>
          <div className="flex items-center gap-4 mb-10 relative z-10">
             <div className="w-3 h-8 bg-[#00F0FF] rounded-full shadow-[0_0_15px_#00F0FF]" />
             <div>
                <h3 className="text-2xl font-bold font-['Rajdhani'] uppercase tracking-widest">Layer 1: Behavioral ML Engine</h3>
                <p className="text-xs text-[#94A3B8] mono-text uppercase tracking-widest mt-1 opacity-70">Statistical Anomaly Profiling & Pattern Intelligence</p>
             </div>
             <span className="ml-auto px-4 py-1.5 rounded bg-[#00F0FF]/10 text-[#00F0FF] text-xs font-bold mono-text uppercase tracking-[3px] border border-[#00F0FF]/20">Proactive_Active</span>
          </div>

          <div className="flex flex-col gap-8 relative z-10">
            {/* Top row: description + stats */}
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
              <div className="space-y-4">
                <h4 className="text-sm font-bold text-white uppercase tracking-wider font-['Rajdhani'] border-b border-[#1E2D4A] pb-2">Analysis Vector Briefing</h4>
                <p className="text-[#94A3B8] leading-relaxed">
                  Detects <span className="text-[#00F0FF] font-bold italic">"Time-Stomping"</span> and log sequence anomalies. Uses Isolation Forest to profile micro-behavioral shifts that bypass static signatures by analyzing the variance in session lifecycle and entropy.
                </p>
              </div>
              <div className="grid grid-cols-2 gap-4 content-start">
                {/* Only Anomalies Found is computed — the rest are static.
                    Isolation Forest is unsupervised, so there is no accuracy to report. */}
                <StatRow label="Variance Detection *" value="99.4%" color="#39FF14" />
                <StatRow label="Anomalies Found" value={anomaliesDetected.toString()} color={anomaliesDetected > 0 ? "#FF003C" : "#00F0FF"} pulse={anomaliesDetected > 0} />
                <StatRow label="Sequence Entropy *" value="0.42" color="#00F0FF" />
                <StatRow label="Model Accuracy *" value="98.2%" color="#FFEA00" />
                <div className="col-span-2 flex items-center gap-1.5">
                  <SimulatedBadge label="* placeholder" title="Static values — not computed from the model" />
                </div>
              </div>
            </div>
            {/* Full-width graph below */}
            <PulseGraph data={pulseIndices} threshold={75} />
          </div>
        </div>

        {/* Layer 2: IP Suspicion Scoring */}
        <div className="cyber-panel border-t-2 border-t-[#B026FF] p-8">
           <div className="flex flex-col md:flex-row md:items-center gap-4 mb-8">
              <div className="flex items-center gap-3">
                 <i className="ph ph-network text-3xl text-[#B026FF]" />
                 <div>
                   <h3 className="text-2xl font-bold font-['Rajdhani'] uppercase tracking-widest text-[#B026FF] flex items-center gap-2 flex-wrap">
                     Layer 2: IP Threat Scoring
                     {ipTableSimulated && <SimulatedBadge title="No scored events yet — showing placeholder rows" />}
                   </h3>
                   <p className="text-xs text-[#94A3B8] mono-text uppercase tracking-widest mt-0.5 opacity-70">
                     {ipTableSimulated
                       ? 'Placeholder rows — upload a log or run a scan for real data'
                       : 'Real-time suspicion scoring per source IP'}
                   </p>
                 </div>
              </div>
              <div className="h-[1px] flex-1 bg-gradient-to-r from-[#B026FF] to-transparent opacity-30" />
              <div className="flex gap-6">
                <div className="flex flex-col items-end">
                  <span className="text-[9px] text-[#94A3B8] mono-text uppercase">Tracked_IPs</span>
                  <span className="text-sm font-bold text-white mono-text">{ipTable.length}</span>
                </div>
                <div className="flex flex-col items-end">
                  <span className="text-[9px] text-[#94A3B8] mono-text uppercase">High_Risk</span>
                  <span className="text-sm font-bold text-[#FF003C] mono-text">{ipTable.filter(r => r.level === 'CRITICAL' || r.level === 'HIGH').length}</span>
                </div>              </div>
           </div>

           {/* Forensic command keyword legend */}
           <div className="mb-6 bg-[#070B14] border border-[#1E2D4A] rounded-lg p-4">
             <div className="flex items-center gap-2 mb-3">
               <i className="ph ph-terminal-window text-[#B026FF] text-sm" />
               <span className="text-[9px] font-bold text-[#94A3B8] mono-text uppercase tracking-widest">Monitored Evasion Commands</span>
               <span className="ml-auto text-[9px] text-[#B026FF] mono-text">{FORENSIC_CMDS.length} signatures active</span>
             </div>
             <div className="flex flex-wrap gap-2">
               {FORENSIC_CMDS.map(fc => (
                 <div key={fc.cmd} className="group/cmd relative flex items-center gap-1.5 px-2.5 py-1 rounded border bg-[#0D1323] cursor-pointer hover:scale-105 transition-transform"
                   style={{ borderColor: fc.color + '33' }}
                   onClick={() => setSelectedCmd(fc)}>
                   <div className="w-1 h-1 rounded-full flex-shrink-0" style={{ backgroundColor: fc.color }} />
                   <code className="text-[10px] font-bold mono-text" style={{ color: fc.color }}>{fc.cmd}</code>
                   <span className="text-[8px] text-[#94A3B8] mono-text px-1 rounded" style={{ backgroundColor: fc.color + '15' }}>{fc.severity}</span>
                 </div>
               ))}
             </div>
           </div>

           {/* Table */}
           <div className="bg-[#070B14] border border-[#1E2D4A] rounded-lg overflow-hidden">
             {/* Header */}
             <div className="grid grid-cols-12 gap-2 px-4 py-2 border-b border-[#1E2D4A] bg-[#0D1323]">
               <span className="col-span-2 text-[9px] font-bold text-[#94A3B8] mono-text uppercase tracking-widest">IP Address</span>
               <span className="col-span-1 text-[9px] font-bold text-[#94A3B8] mono-text uppercase tracking-widest">Reqs</span>
               <span className="col-span-1 text-[9px] font-bold text-[#94A3B8] mono-text uppercase tracking-widest">Fails</span>
               <span className="col-span-1 text-[9px] font-bold text-[#94A3B8] mono-text uppercase tracking-widest">Rep</span>
               <span className="col-span-1 text-[9px] font-bold text-[#94A3B8] mono-text uppercase tracking-widest">Score</span>
               <span className="col-span-1 text-[9px] font-bold text-[#94A3B8] mono-text uppercase tracking-widest">Level</span>
               <span className="col-span-5 text-[9px] font-bold text-[#94A3B8] mono-text uppercase tracking-widest">Evasion Commands Detected</span>
             </div>
             {/* Rows */}
             <div className="divide-y divide-[#1E2D4A]/50 max-h-[360px] overflow-y-auto">
               {ipTable.map((row, i) => (
                 <IpRow key={row.uid || row.ip} row={row} rank={i + 1} onCmdClick={setSelectedCmd} />
               ))}
             </div>
           </div>

           {/* Score legend */}
           <div className="flex flex-wrap gap-4 mt-4">
             {[['CRITICAL','#FF003C','≥ 80'],['HIGH','#FF6B00','60–79'],['MEDIUM','#FFEA00','40–59'],['LOW','#39FF14','< 40']].map(([label, color, range]) => (
               <div key={label} className="flex items-center gap-2">
                 <div className="w-2 h-2 rounded-full" style={{ backgroundColor: color, boxShadow: `0 0 6px ${color}` }} />
                 <span className="text-[9px] mono-text uppercase font-bold" style={{ color }}>{label}</span>
                 <span className="text-[9px] text-[#94A3B8] mono-text">{range}</span>
               </div>
             ))}
           </div>
        </div>

        {/* Layer 3 runs on real scored events, and only falls back to a
            generated chain when the pipeline has produced none. */}
        {liveEvents.length > 0
          ? <Layer3Panel events={liveEvents} />
          : (
            <SimulatedFrame note="No scored events yet — showing an illustrative chain generated in the browser. Upload a log or run a scan and this switches to real pipeline events.">
              <Layer3Panel />
            </SimulatedFrame>
          )}
      </div>

      {/* Global Performance Cards — static placeholders; nothing measures these */}
      <div>
        <div className="flex items-center gap-2 mb-2">
          <SimulatedBadge title="Static values — none of these are measured" />
          <span className="text-[9px] text-[#FFB020]/70 mono-text uppercase tracking-widest">
            Placeholder metrics — not measured by the pipeline
          </span>
        </div>
        <div className="grid grid-cols-1 md:grid-cols-4 gap-6 opacity-60 saturate-[0.6]">
           <SmallCard icon="ph-arrows-clockwise" label="Real-time Lag" value="0.04ms" color="#39FF14" />
           <SmallCard icon="ph-shield-check" label="Auth Integrity" value="VERIFIED" color="#00F0FF" />
           <SmallCard icon="ph-link-simple" label="API Hook" value="EXTERNAL" color="#B026FF" />
           <SmallCard icon="ph-activity" label="AI Confidence" value="98.2%" color="#FFEA00" />
        </div>
      </div>

      {/* Command Dictionary Modal */}
      {selectedCmd && <CmdModal cmd={selectedCmd} onClose={closeCmdModal} />}
    </div>
  );
}

const DETECTION_KEYWORDS = [
  { key: 'BRUTE_FORCE',       label: 'Brute Force',        desc: 'failed_logins > 5 & login_attempts > 10', severity: 'HIGH',   color: '#FF003C' },
  { key: 'LOW_REPUTATION_IP', label: 'Low Rep IP',         desc: 'ip_reputation_score < 0.3',               severity: 'HIGH',   color: '#FF003C' },
  { key: 'ODD_ACCESS_TIME',   label: 'Odd Access Time',    desc: 'unusual_time_access == 1',                severity: 'MEDIUM', color: '#FFEA00' },
  { key: 'LONG_SESSION',      label: 'Long Session',       desc: 'session_duration > 300',                  severity: 'MEDIUM', color: '#FFEA00' },
];

// Forensic evasion commands — log deletion / evidence tampering
const FORENSIC_CMDS = [
  { cmd: 'rm -rf /var/log',   severity: 'CRITICAL', color: '#FF003C',  desc: 'Wipes system log directory' },
  { cmd: 'history -c',        severity: 'CRITICAL', color: '#FF003C',  desc: 'Clears shell command history' },
  { cmd: 'shred -u',          severity: 'CRITICAL', color: '#FF003C',  desc: 'Secure-deletes files unrecoverably' },
  { cmd: 'wevtutil cl',       severity: 'HIGH',     color: '#FF6B00',  desc: 'Clears Windows Event Log' },
  { cmd: 'wmic shadowcopy',   severity: 'HIGH',     color: '#FF6B00',  desc: 'Deletes VSS shadow copies' },
  { cmd: 'reg delete',        severity: 'HIGH',     color: '#FF6B00',  desc: 'Removes registry forensic traces' },
  { cmd: 'chmod 777',         severity: 'MEDIUM',   color: '#FFEA00',  desc: 'Masks file permission changes' },
  { cmd: 'taskkill /f',       severity: 'MEDIUM',   color: '#FFEA00',  desc: 'Force-kills monitoring processes' },
  { cmd: 'net user /delete',  severity: 'MEDIUM',   color: '#FFEA00',  desc: 'Removes user account traces' },
  { cmd: 'del /s /q',         severity: 'MEDIUM',   color: '#FFEA00',  desc: 'Silent recursive file deletion' },
  { cmd: 'auditpol /clear',   severity: 'HIGH',     color: '#FF6B00',  desc: 'Disables Windows audit policy' },
  { cmd: 'logrotate -f',      severity: 'MEDIUM',   color: '#FFEA00',  desc: 'Forces log rotation to overwrite' },
];

function scoreLevel(score) {
  if (score >= 80) return 'CRITICAL';
  if (score >= 60) return 'HIGH';
  if (score >= 40) return 'MEDIUM';
  return 'LOW';
}

function scoreColor(level) {
  return { CRITICAL: '#FF003C', HIGH: '#FF6B00', MEDIUM: '#FFEA00', LOW: '#39FF14' }[level] ?? '#94A3B8';
}

function randIp() {
  return `${Math.floor(Math.random()*220)+10}.${Math.floor(Math.random()*254)+1}.${Math.floor(Math.random()*254)+1}.${Math.floor(Math.random()*254)+1}`;
}

function generateIpTable() {
  const entries = [];
  for (let i = 0; i < 12; i++) {
    const failedLogins   = Math.floor(Math.random() * 20);
    const loginAttempts  = Math.floor(Math.random() * 25);
    const repScore       = parseFloat((Math.random()).toFixed(2));
    const oddHours       = Math.random() > 0.6 ? 1 : 0;
    const sessionDur     = Math.floor(Math.random() * 500);
    const requests       = Math.floor(Math.random() * 500) + 10;

    // Mirror backend detection rules exactly
    const triggered = [];
    if (failedLogins > 5 && loginAttempts > 10) triggered.push('BRUTE_FORCE');
    if (repScore < 0.3)                          triggered.push('LOW_REPUTATION_IP');
    if (oddHours === 1)                          triggered.push('ODD_ACCESS_TIME');
    if (sessionDur > 300)                        triggered.push('LONG_SESSION');

    // Assign 0–3 random forensic commands, weighted by suspicion
    const numCmds = Math.random() > 0.4 ? Math.floor(Math.random() * 3) + 1 : 0;
    const usedCmds = [...FORENSIC_CMDS]
      .sort(() => Math.random() - 0.5)
      .slice(0, numCmds)
      .map(c => c.cmd);

    const score = Math.min(100, Math.round(
      failedLogins * 2.5 +
      (1 - repScore) * 30 +
      oddHours * 20 +
      (requests > 200 ? 15 : 0) +
      usedCmds.length * 8
    ));
    // uid keeps rows distinct even if randIp() happens to repeat
    entries.push({ uid: `fallback#${i}`, ip: randIp(), requests, failedLogins, loginAttempts, repScore, oddHours, sessionDur, score, level: scoreLevel(score), triggered, usedCmds });
  }
  return entries.sort((a, b) => b.score - a.score);
}

// Full command dictionary with extended info
const CMD_DICT = {
  'rm -rf /var/log':  { os: 'Linux/macOS', category: 'Log Deletion',       mitigation: 'Immutable log forwarding to SIEM', example: 'rm -rf /var/log/auth.log /var/log/syslog' },
  'history -c':       { os: 'Linux/macOS', category: 'History Tampering',   mitigation: 'Centralized shell audit logging',   example: 'history -c && history -w' },
  'shred -u':         { os: 'Linux/macOS', category: 'Secure Deletion',     mitigation: 'File integrity monitoring (FIM)',    example: 'shred -u -z /var/log/auth.log' },
  'wevtutil cl':      { os: 'Windows',     category: 'Event Log Clearing',  mitigation: 'Forward events to remote SIEM',     example: 'wevtutil cl System && wevtutil cl Security' },
  'wmic shadowcopy':  { os: 'Windows',     category: 'Backup Destruction',  mitigation: 'Offsite VSS backup replication',    example: 'wmic shadowcopy delete /nointeractive' },
  'reg delete':       { os: 'Windows',     category: 'Registry Tampering',  mitigation: 'Registry change auditing enabled',  example: 'reg delete HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run /f' },
  'chmod 777':        { os: 'Linux/macOS', category: 'Permission Masking',  mitigation: 'Enforce least-privilege file ACLs', example: 'chmod 777 /etc/passwd' },
  'taskkill /f':      { os: 'Windows',     category: 'Process Termination', mitigation: 'Protected process for AV/EDR agents',example: 'taskkill /f /im sysmon.exe' },
  'net user /delete': { os: 'Windows',     category: 'Account Removal',     mitigation: 'AD change auditing + alerting',     example: 'net user backdoor /delete' },
  'del /s /q':        { os: 'Windows',     category: 'Silent Deletion',     mitigation: 'File system audit policy enabled',  example: 'del /s /q C:\\Windows\\Temp\\*.log' },
  'auditpol /clear':  { os: 'Windows',     category: 'Audit Disabling',     mitigation: 'GPO-enforced audit policy lockdown', example: 'auditpol /clear /y' },
  'logrotate -f':     { os: 'Linux/macOS', category: 'Log Overwrite',       mitigation: 'Append-only log storage (WORM)',    example: 'logrotate -f /etc/logrotate.conf' },
};

function CmdModal({ cmd, onClose }) {
  const dict = CMD_DICT[cmd.cmd] || {};
  const color = cmd.color;

  return (
    <div className="fixed inset-0 z-[100] flex items-center justify-center p-4"
      onClick={onClose}>
      {/* Backdrop */}
      <div className="absolute inset-0 bg-[#070B14]/80 backdrop-blur-sm" />

      {/* Panel */}
      <div className="relative w-full max-w-lg max-h-[85vh] bg-[#0D1323] border rounded-xl shadow-2xl overflow-hidden animate-fadeIn flex flex-col"
        style={{ borderColor: color + '44', boxShadow: `0 0 40px ${color}18` }}
        onClick={e => e.stopPropagation()}>

        {/* Top accent bar */}
        <div className="h-1 w-full flex-shrink-0" style={{ background: `linear-gradient(to right, ${color}, transparent)` }} />

        {/* Header */}
        <div className="flex items-start justify-between p-6 border-b border-[#1E2D4A] flex-shrink-0 min-w-0">
          <div className="flex items-center gap-3 min-w-0">
            <div className="w-10 h-10 rounded-lg flex items-center justify-center border flex-shrink-0"
              style={{ borderColor: color + '44', backgroundColor: color + '10' }}>
              <i className="ph ph-terminal-window text-xl" style={{ color }} />
            </div>
            <div className="min-w-0">
              <code className="text-lg font-bold mono-text break-all" style={{ color }}>{cmd.cmd}</code>
              <div className="flex items-center gap-2 mt-0.5 flex-wrap">
                <span className="text-[9px] font-bold mono-text px-2 py-0.5 rounded border"
                  style={{ color, borderColor: color + '44', backgroundColor: color + '10' }}>
                  {cmd.severity}
                </span>
                {dict.os && <span className="text-[9px] text-[#94A3B8] mono-text">{dict.os}</span>}
                {dict.category && <span className="text-[9px] text-[#94A3B8] mono-text">· {dict.category}</span>}
              </div>
            </div>
          </div>
          <button onClick={onClose}
            className="text-[#94A3B8] hover:text-white transition-colors p-1 flex-shrink-0">
            <i className="ph ph-x text-lg" />
          </button>
        </div>

        {/* Body */}
        <div className="p-6 space-y-5 overflow-y-auto min-h-0">
          {/* What it does */}
          <div>
            <div className="text-[9px] font-bold text-[#94A3B8] mono-text uppercase tracking-widest mb-2 flex items-center gap-2">
              <i className="ph ph-info text-[#00F0FF]" /> What it does
            </div>
            <p className="text-sm text-[#E2E8F0] leading-relaxed break-words">{cmd.desc}</p>
          </div>

          {/* Example usage */}
          {dict.example && (
            <div>
              <div className="text-[9px] font-bold text-[#94A3B8] mono-text uppercase tracking-widest mb-2 flex items-center gap-2">
                <i className="ph ph-code text-[#B026FF]" /> Example Usage
              </div>
              <div className="bg-[#070B14] border border-[#1E2D4A] rounded-lg px-4 py-3 overflow-x-auto">
                <code className="text-[11px] text-[#B026FF] mono-text break-all">{dict.example}</code>
              </div>
            </div>
          )}

          {/* Mitigation */}
          {dict.mitigation && (
            <div>
              <div className="text-[9px] font-bold text-[#94A3B8] mono-text uppercase tracking-widest mb-2 flex items-center gap-2">
                <i className="ph ph-shield-check text-[#39FF14]" /> Mitigation
              </div>
              <div className="flex items-center gap-3 bg-[#39FF14]/5 border border-[#39FF14]/20 rounded-lg px-4 py-3">
                <i className="ph ph-check-circle text-[#39FF14] text-lg flex-shrink-0" />
                <span className="text-sm text-[#E2E8F0] break-words">{dict.mitigation}</span>
              </div>
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="px-6 py-3 border-t border-[#1E2D4A] bg-[#070B14]/40 flex items-center justify-between flex-shrink-0">
          <span className="text-[9px] text-[#94A3B8] mono-text uppercase tracking-widest">TraceShield_X · Forensic Command Dictionary</span>
          <button onClick={onClose}
            className="text-[10px] font-bold mono-text px-4 py-1.5 rounded border transition-all hover:bg-[#1E2D4A]"
            style={{ color, borderColor: color + '44' }}>
            CLOSE
          </button>
        </div>
      </div>
    </div>
  );
}

function IpRow({ row, rank, onCmdClick }) {
  const color = scoreColor(row.level);
  const [expanded, setExpanded] = useState(false);
  return (
    <>
    <div className="grid grid-cols-12 gap-2 px-4 py-2.5 items-center hover:bg-[#0D1323]/60 transition-colors group cursor-pointer"
      onClick={() => setExpanded(e => !e)}>
      {/* IP + actor */}
      <div className="col-span-2 flex items-center gap-2">
        <span className="text-[9px] text-[#1E2D4A] mono-text w-4 text-right flex-shrink-0">{rank}</span>
        <div className="min-w-0">
          <div className="text-[11px] text-white mono-text font-bold truncate" title={row.ip}>{row.ip}</div>
          <div className="text-[9px] text-[#94A3B8] mono-text truncate" title={row.actor}>{row.actor}</div>
        </div>
      </div>
      {/* Requests */}
      <span className="col-span-1 text-[11px] text-[#94A3B8] mono-text">{row.requests}</span>
      {/* Failed logins */}
      <span className={`col-span-1 text-[11px] mono-text font-bold ${row.failedLogins > 0 ? 'text-[#FF003C]' : 'text-[#94A3B8]'}`}>{row.failedLogins}</span>
      {/* Rep score */}
      <span className={`col-span-1 text-[11px] mono-text font-bold ${row.repScore > 0.6 ? 'text-[#FF003C]' : row.repScore > 0.3 ? 'text-[#FFEA00]' : 'text-[#39FF14]'}`}>{row.repScore?.toFixed(2)}</span>      {/* Score bar */}
      <div className="col-span-1 flex items-center gap-1.5">
        <span className="text-[11px] mono-text font-bold" style={{ color }}>{row.score}</span>
      </div>
      {/* Level badge */}
      <div className="col-span-1">
        <span className="text-[9px] font-bold mono-text px-1.5 py-0.5 rounded border"
          style={{ color, borderColor: color + '44', backgroundColor: color + '10' }}>
          {row.level}
        </span>
      </div>
      {/* Triggered forensic commands, attack_type, and flags */}
      <div className="col-span-5 flex flex-wrap gap-1.5 items-center">
        {row.attack_type && row.attack_type !== 'NORMAL_ACTIVITY' && (() => {
          const AT = { PRIVILEGE_ESCALATION: ['🔴','text-red-400','border-red-800/60','bg-red-950/40'], REMOTE_EXECUTION: ['🟠','text-orange-400','border-orange-800/60','bg-orange-950/40'], BRUTE_FORCE: ['🟡','text-yellow-400','border-yellow-800/60','bg-yellow-950/40'], BEHAVIORAL_ANOMALY: ['🔵','text-cyan-400','border-cyan-800/60','bg-cyan-950/40'] }
          const [icon, tc, bc, bg] = AT[row.attack_type] || []
          return icon ? <span className={`text-[9px] font-bold mono-text px-1.5 py-0.5 rounded border ${tc} ${bc} ${bg}`}>{icon} {row.attack_type.replace('_',' ')}</span> : null
        })()}
        {row.usedCmds.length === 0 && !row.attack_type && row.triggered.length === 0 ? (
          <span className="text-[9px] text-[#1E2D4A] mono-text">— none detected</span>
        ) : (
          <>
            {row.usedCmds.map(cmd => {
              const fc = FORENSIC_CMDS.find(c => c.cmd === cmd);
              if (!fc) return null;
              return (
                <span key={cmd}
                  onClick={(e) => { e.stopPropagation(); onCmdClick(fc); }}
                  className="text-[9px] font-bold mono-text px-1.5 py-0.5 rounded border cursor-pointer hover:scale-105 transition-transform"
                  style={{ color: fc.color, borderColor: fc.color + '44', backgroundColor: fc.color + '10' }}>
                  {fc.cmd}
                </span>
              );
            })}
            {row.triggered.map((flag, j) => {
              const flagColor = flag === 'PRIVILEGE_ESCALATION' ? '#FF003C'
                              : flag === 'BRUTE_FORCE'          ? '#FF6B00'
                              : flag === 'LOW_REPUTATION_IP'    ? '#FF003C'
                              : flag === 'ODD_ACCESS_TIME'      ? '#FFEA00'
                              : '#94A3B8'
              return (
                <span key={j} className="text-[9px] font-bold mono-text px-2 py-0.5 rounded border"
                  style={{ color: flagColor, borderColor: flagColor+'44', backgroundColor: flagColor+'10' }}>
                  {flag.replace(/_/g,' ')}
                </span>
              )
            })}
          </>
        )}
      </div>
    </div>
    {expanded && row.rawLog && (
      <div className="px-4 pb-3 bg-[#070B14]/60 border-b border-[#1E2D4A]/30">
        <code className="text-[9px] text-[#B026FF] mono-text break-all">{row.rawLog}</code>
      </div>
    )}
    </>
  );
}

// Sample log lines per event type — real dataset patterns
const EVENT_LOGS = {
  LOGIN:       [ 'auth.log: sshd[4821]: Accepted password for root from 10.0.0.42 port 22',
                 'auth.log: sshd[3901]: pam_unix(sshd:session): session opened for user admin',
                 'auth.log: login[1204]: LOGIN on tty1 by USER_07' ],
  BRUTE:       [ 'auth.log: sshd[5532]: Failed password for root from 192.168.1.44 port 22 (attempt 14)',
                 'auth.log: sshd[5533]: Failed password for admin from 10.13.1.9 port 22 (attempt 21)',
                 'security.log: pam_tally2: user root (uid=0) tally 18, deny 5' ],
  FILE_ACCESS: [ 'audit.log: type=SYSCALL msg=audit(1714): exe="/bin/cat" path="/etc/shadow"',
                 'audit.log: type=OPEN flags=O_RDONLY path="/var/log/auth.log" pid=3312',
                 'audit.log: type=SYSCALL exe="/usr/bin/cp" path="/etc/passwd" dest="/tmp/.x"' ],
  LOG_CLEAR:   [ 'syslog: COMMAND: rm -rf /var/log/auth.log by uid=0',
                 'syslog: COMMAND: history -c executed by bash pid=7741',
                 'syslog: wevtutil.exe cl Security — event log cleared by SYSTEM' ],
  PRIV_ESC:    [ 'Apr 11 00:49:49 ubuntu-server sudo: ubuntu : TTY=pts/1 ; PWD=/home/ubuntu ; USER=root ; COMMAND=/bin/bash',
                 'Apr 11 00:50:27 ubuntu-server sudo: deploy : TTY=pts/1 ; PWD=/home/deploy ; USER=root ; COMMAND=/bin/bash',
                 'Apr 11 00:50:08 ubuntu-server sudo: pam_unix(sudo:session): session opened for user root by mayur(uid=1000)' ],
  EXFIL:       [ 'netflow: 10.0.0.42:443 -> 185.220.101.9:443 bytes=4194304 (4MB)',
                 'dns.log: query AAAA evil-c2.xyz from 10.0.0.42 (suspicious domain)',
                 'audit.log: type=CONNECT fd=3 addr=185.220.101.9 port=4444' ],
  NORMAL:      [ 'Apr 11 00:32:23 ubuntu-server nginx: nginx[3386]: worker process 3386 exited on signal 15',
                 'Apr 11 00:37:12 ubuntu-server systemd: systemd[1]: Reached target Multi-User System.',
                 'Apr 11 00:35:47 ubuntu-server CRON: CRON[8331]: (root) CMD (test -x /usr/sbin/anacron)' ],
};

// Short code shown on the shape
const EVENT_CODE = {
  LOGIN:       'AUTH', BRUTE: 'BRF', FILE_ACCESS: 'FACC',
  LOG_CLEAR:   'LCLR', PRIV_ESC: 'PESC', EXFIL: 'EXFL', NORMAL: 'NRM',
};

// What the event means
const EVENT_DESC = {
  LOGIN:       'A user authentication event was recorded. Could be legitimate or the start of an attack chain.',
  BRUTE:       'Multiple failed login attempts detected from the same source. Indicates a brute-force or credential stuffing attack.',
  FILE_ACCESS: 'Sensitive file was opened or read. Common in reconnaissance and credential harvesting phases.',
  LOG_CLEAR:   'System or audit logs were deleted or cleared. Strong indicator of evidence tampering post-compromise.',
  PRIV_ESC:    'A process or user escalated privileges to root/SYSTEM. Critical step in most attack kill chains.',
  EXFIL:       'Large outbound data transfer or suspicious DNS/network connection detected. Possible data exfiltration.',
  NORMAL:      'Routine system activity within expected behavioral baseline. No threat indicators present.',
};

// ── Event shape types mapped to log event types ──────────────────────────────
const EVENT_SHAPES = [
  { type: 'LOGIN',       shape: 'circle',   color: '#00F0FF', icon: 'ph-sign-in',        label: 'Login Attempt'    },
  { type: 'BRUTE',       shape: 'triangle', color: '#FF003C', icon: 'ph-warning-octagon', label: 'Brute Force'      },
  { type: 'FILE_ACCESS', shape: 'square',   color: '#B026FF', icon: 'ph-file-code',       label: 'File Access'      },
  { type: 'LOG_CLEAR',   shape: 'diamond',  color: '#FF6B00', icon: 'ph-trash',           label: 'Log Cleared'      },
  { type: 'PRIV_ESC',    shape: 'hexagon',  color: '#FFEA00', icon: 'ph-arrow-up',        label: 'Privilege Escal.' },
  { type: 'EXFIL',       shape: 'star',     color: '#FF003C', icon: 'ph-export',          label: 'Data Exfil'       },
  { type: 'NORMAL',      shape: 'circle',   color: '#39FF14', icon: 'ph-check-circle',    label: 'Normal Event'     },
];

// Transition rules: which event types normally follow which (normal chains)
const NORMAL_TRANSITIONS = {
  LOGIN: ['FILE_ACCESS', 'NORMAL'],
  FILE_ACCESS: ['NORMAL', 'LOGIN'],
  NORMAL: ['NORMAL', 'LOGIN', 'FILE_ACCESS'],
};

function isUnusualTransition(from, to) {
  const allowed = NORMAL_TRANSITIONS[from?.type] || [];
  return !allowed.includes(to?.type);
}

function randomEventType(prevType) {
  // 70% normal chain, 30% suspicious
  const r = Math.random();
  let shape;
  if (r < 0.55) shape = EVENT_SHAPES.find(e => e.type === 'NORMAL');
  else if (r < 0.70) shape = EVENT_SHAPES.find(e => e.type === 'LOGIN');
  else if (r < 0.78) shape = EVENT_SHAPES.find(e => e.type === 'FILE_ACCESS');
  else if (r < 0.84) shape = EVENT_SHAPES.find(e => e.type === 'BRUTE');
  else if (r < 0.89) shape = EVENT_SHAPES.find(e => e.type === 'LOG_CLEAR');
  else if (r < 0.94) shape = EVENT_SHAPES.find(e => e.type === 'PRIV_ESC');
  else shape = EVENT_SHAPES.find(e => e.type === 'EXFIL');
  const logs = EVENT_LOGS[shape.type] || [];
  const log = logs[Math.floor(Math.random() * logs.length)] || '';
  return { ...shape, log };
}

function EventShape({ shape, color, size = 28, pulse = false }) {
  const s = size;
  const half = s / 2;
  const style = { filter: `drop-shadow(0 0 ${pulse ? 8 : 4}px ${color})` };
  if (shape === 'circle')
    return <svg width={s} height={s} style={style}><circle cx={half} cy={half} r={half - 2} fill={color + '22'} stroke={color} strokeWidth={pulse ? 2 : 1.5} className={pulse ? 'animate-pulse' : ''} /></svg>;
  if (shape === 'square')
    return <svg width={s} height={s} style={style}><rect x={2} y={2} width={s-4} height={s-4} rx={3} fill={color + '22'} stroke={color} strokeWidth={pulse ? 2 : 1.5} className={pulse ? 'animate-pulse' : ''} /></svg>;
  if (shape === 'triangle')
    return <svg width={s} height={s} style={style}><polygon points={`${half},2 ${s-2},${s-2} 2,${s-2}`} fill={color + '22'} stroke={color} strokeWidth={pulse ? 2 : 1.5} className={pulse ? 'animate-pulse' : ''} /></svg>;
  if (shape === 'diamond')
    return <svg width={s} height={s} style={style}><polygon points={`${half},2 ${s-2},${half} ${half},${s-2} 2,${half}`} fill={color + '22'} stroke={color} strokeWidth={pulse ? 2 : 1.5} className={pulse ? 'animate-pulse' : ''} /></svg>;
  if (shape === 'hexagon') {
    const pts = [0,1,2,3,4,5].map(i => {
      const a = (Math.PI / 3) * i - Math.PI / 6;
      return `${(half + (half-2)*Math.cos(a)).toFixed(1)},${(half + (half-2)*Math.sin(a)).toFixed(1)}`;
    }).join(' ');
    return <svg width={s} height={s} style={style}><polygon points={pts} fill={color + '22'} stroke={color} strokeWidth={pulse ? 2 : 1.5} className={pulse ? 'animate-pulse' : ''} /></svg>;
  }
  if (shape === 'star') {
    const pts = Array.from({length:10}, (_,i) => {
      const a = (Math.PI / 5) * i - Math.PI / 2;
      const r2 = i % 2 === 0 ? half - 2 : (half - 2) * 0.45;
      return `${(half + r2*Math.cos(a)).toFixed(1)},${(half + r2*Math.sin(a)).toFixed(1)}`;
    }).join(' ');
    return <svg width={s} height={s} style={style}><polygon points={pts} fill={color + '22'} stroke={color} strokeWidth={pulse ? 2 : 1.5} className={pulse ? 'animate-pulse' : ''} /></svg>;
  }
  return null;
}

/** Map a scored event from the pipeline onto one of the chain's shapes. */
function shapeForEvent(ev) {
  const byAttack = {
    BRUTE_FORCE:          'BRUTE',
    PRIVILEGE_ESCALATION: 'PRIV_ESC',
    REMOTE_EXECUTION:     'FILE_ACCESS',
  };
  const type = byAttack[ev.attack_type]
    || (ev.status && ev.status !== 'NORMAL' ? 'BRUTE' : 'NORMAL');
  const shape = EVENT_SHAPES.find(e => e.type === type) || EVENT_SHAPES.find(e => e.type === 'NORMAL');
  return {
    ...shape,
    log: `${ev.ip} — ${ev.status} score=${(ev.risk_score ?? 0).toFixed(1)}`
       + (ev.reason && ev.reason !== 'N/A' ? ` (${ev.reason})` : ''),
  };
}

function Layer3Panel({ events = [] }) {
  const MAX_NODES = 18;
  // Real scored events drive the chain; the random walk is only a placeholder
  // for when the pipeline has produced nothing yet.
  const live = events.length > 0;

  const [nodes, setNodes] = useState(() => {
    const first = EVENT_SHAPES.find(e => e.type === 'LOGIN');
    const logs = EVENT_LOGS['LOGIN'];
    return [{ ...first, id: 0, ts: Date.now(), log: logs[0] }];
  });
  const [unusual, setUnusual] = useState(false);
  const [unusualStreak, setUnusualStreak] = useState(0);
  const [lastTransition, setLastTransition] = useState(null);
  const [paused, setPaused] = useState(false);
  const [selectedNode, setSelectedNode] = useState(null);
  // Captures whether the feed was already paused the moment the Node-Detail
  // modal opened, so closing it restores that state instead of always
  // resuming — a ref (not state) because it's only ever read inside the
  // close handler, never needs to trigger a re-render.
  const pausedBeforeModalRef = useRef(false);

  const closeNodeModal = useCallback(() => {
    setSelectedNode(null);
    setPaused(pausedBeforeModalRef.current);
  }, []);
  useModalEscapeAndScrollLock(!!selectedNode, closeNodeModal);

  // Build the chain from real events, oldest → newest
  useEffect(() => {
    if (!live) return;
    const chain = [...events].slice(0, MAX_NODES).reverse()
      .map((ev, i) => ({ ...shapeForEvent(ev), id: `${ev.ip}-${ev.timestamp}-${i}` }));
    setNodes(chain);
    const a = chain[chain.length - 2], b = chain[chain.length - 1];
    if (b) {
      const odd = isUnusualTransition(a, b);
      setLastTransition({ from: a, to: b, unusual: odd });
      setUnusual(odd);
      setUnusualStreak(chain.filter(n => n.type !== 'NORMAL').length);
    }
  }, [events, live]);

  useEffect(() => {
    if (paused || live) return;
    const interval = setInterval(() => {
      setNodes(prev => {
        const last = prev[prev.length - 1];
        const next = randomEventType(last?.type);
        const isUnusual = isUnusualTransition(last, next);
        setLastTransition({ from: last, to: next, unusual: isUnusual });
        setUnusualStreak(s => isUnusual ? s + 1 : Math.max(0, s - 1));
        setUnusual(isUnusual);
        const newNode = { ...next, id: Date.now() };
        const updated = [...prev, newNode];
        return updated.length > MAX_NODES ? updated.slice(updated.length - MAX_NODES) : updated;
      });
    }, 1400);
    return () => clearInterval(interval);
  }, [paused, live]);

  const isAlert = unusualStreak >= 2;

  const FLAG_META = {
    BRUTE_FORCE:       { label: 'Brute Force',       color: '#FF003C' },
    LOW_REPUTATION_IP: { label: 'Low Rep IP',        color: '#FF003C' },
    ODD_ACCESS_TIME:   { label: 'Odd Access Time',   color: '#FFEA00' },
    LONG_SESSION:      { label: 'Long Session',      color: '#FFEA00' },
  };
  const RISK_COLORS = { CRITICAL: '#FF003C', HIGH: '#FF6B00', MEDIUM: '#FFEA00', LOW: '#39FF14' };
  const PROTO_COLORS = { TCP: '#00F0FF', UDP: '#B026FF', HTTP: '#39FF14', ICMP: '#FF6B00' };

  return (
    <>
    <div className={`cyber-panel border-t-2 p-8 transition-all duration-500 ${isAlert ? 'border-t-[#FF003C]' : 'border-t-[#39FF14]'}`}
      style={isAlert ? { boxShadow: '0 0 40px rgba(255,0,60,0.15)' } : {}}>

      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center gap-4 mb-8">
        <div className="flex items-center gap-3">
          <i className={`ph ph-graph text-3xl ${isAlert ? 'text-[#FF003C]' : 'text-[#39FF14]'}`} />
          <div>
            <h3 className={`text-2xl font-bold font-['Rajdhani'] uppercase tracking-widest ${isAlert ? 'text-[#FF003C]' : 'text-[#39FF14]'}`}>
              Layer 3: Event Log Pattern Detection
            </h3>
            <p className="text-xs text-[#94A3B8] mono-text uppercase tracking-widest mt-0.5 opacity-70">
              Live event chain — each shape is a log event, connections show sequence flow
            </p>
          </div>
        </div>
        <div className={`h-[1px] flex-1 bg-gradient-to-r opacity-30 ${isAlert ? 'from-[#FF003C]' : 'from-[#39FF14]'} to-transparent`} />
        <button onClick={() => setPaused(p => !p)}
          className={`cyber-btn h-9 px-4 text-[11px] ${paused ? 'border-[#FFEA00] text-[#FFEA00]' : 'border-[#39FF14] text-[#39FF14]'}`}>
          <i className={`ph ${paused ? 'ph-play' : 'ph-pause'} text-sm`} />
          {paused ? 'Resume' : 'Pause'}
        </button>
      </div>

      {/* Shape legend */}
      <div className="flex flex-wrap gap-3 mb-6 bg-[#070B14] border border-[#1E2D4A] rounded-lg p-3">
        {EVENT_SHAPES.map(e => (
          <div key={e.type} className="flex items-center gap-2">
            <EventShape shape={e.shape} color={e.color} size={18} />
            <span className="text-[9px] mono-text font-bold uppercase" style={{ color: e.color }}>{e.label}</span>
          </div>
        ))}
      </div>

      {/* Event chain canvas */}
      <div className={`relative bg-[#070B14] border rounded-xl overflow-hidden transition-all duration-300 ${isAlert ? 'border-[#FF003C]/60' : 'border-[#1E2D4A]'}`}
        style={{ minHeight: '160px' }}>

        {/* Alert flash overlay */}
        {isAlert && (
          <div className="absolute inset-0 pointer-events-none rounded-xl animate-pulse"
            style={{ background: 'radial-gradient(ellipse at center, rgba(255,0,60,0.08) 0%, transparent 70%)' }} />
        )}

        {/* Scrollable chain */}
        <div className="flex items-center gap-0 px-6 py-8 overflow-x-auto min-w-0"
          style={{ scrollbarWidth: 'none' }}>
          {nodes.map((node, i) => {
            const prev = nodes[i - 1];
            const isUnusualEdge = prev && isUnusualTransition(prev, node);
            const isLast = i === nodes.length - 1;
            const code = EVENT_CODE[node.type] || node.type;
            return (
              <div key={node.id} className="flex items-center flex-shrink-0">
                {/* Connector line */}
                {i > 0 && (
                  <div className="flex items-center" style={{ width: '36px' }}>
                    <div className="flex-1 h-px relative"
                      style={{
                        background: isUnusualEdge
                          ? 'repeating-linear-gradient(90deg, #FF003C 0px, #FF003C 4px, transparent 4px, transparent 8px)'
                          : `linear-gradient(90deg, ${prev.color}, ${node.color})`,
                        boxShadow: isUnusualEdge ? '0 0 6px #FF003C' : undefined,
                        height: isUnusualEdge ? '2px' : '1px',
                      }} />
                    <svg width="8" height="8" style={{ flexShrink: 0 }}>
                      <polygon points="0,0 8,4 0,8" fill={isUnusualEdge ? '#FF003C' : node.color} />
                    </svg>
                  </div>
                )}
                {/* Node — clickable */}
                <div className="flex flex-col items-center gap-1 cursor-pointer group/node relative"
                  onClick={() => {
                    const prevNode = nodes[i - 1] || null;
                    const isUnusual = prevNode ? isUnusualTransition(prevNode, node) : false;
                    pausedBeforeModalRef.current = paused;
                    setSelectedNode({ ...node, index: i, prevNode, isUnusualEdge: isUnusual });
                    setPaused(true);
                  }}>
                  {/* Shape with code label overlaid */}
                  <div className="relative flex items-center justify-center">
                    <EventShape shape={node.shape} color={node.color} size={44} pulse={isLast} />
                    <span className="absolute text-[7px] font-black mono-text select-none"
                      style={{ color: node.color, textShadow: `0 0 6px ${node.color}` }}>
                      {code}
                    </span>
                  </div>
                  <span className="text-[7px] mono-text font-bold uppercase whitespace-nowrap opacity-60"
                    style={{ color: node.color }}>
                    #{i + 1}
                  </span>
                  {/* Hover ring */}
                  <div className="absolute inset-0 rounded-full opacity-0 group-hover/node:opacity-100 transition-opacity pointer-events-none"
                    style={{ boxShadow: `0 0 12px ${node.color}` }} />
                </div>
              </div>
            );
          })}

          {/* Live pulse indicator at end */}
          {!paused && (
            <div className="flex items-center flex-shrink-0 ml-2">
              <div className="w-px h-6 bg-[#1E2D4A] mx-2" />
              <div className="w-2 h-2 rounded-full bg-[#39FF14] animate-pulse"
                style={{ boxShadow: '0 0 8px #39FF14' }} />
            </div>
          )}
        </div>
      </div>

      {/* Pattern Analyzer */}      <div className={`mt-6 rounded-xl border p-5 transition-all duration-500 relative overflow-hidden
        ${isAlert
          ? 'border-[#FF003C]/60 bg-[#FF003C]/5'
          : 'border-[#39FF14]/30 bg-[#39FF14]/5'}`}>

        {/* Alert strobe */}
        {isAlert && (
          <div className="absolute inset-0 pointer-events-none"
            style={{ background: 'repeating-linear-gradient(45deg, transparent, transparent 10px, rgba(255,0,60,0.03) 10px, rgba(255,0,60,0.03) 20px)' }} />
        )}

        <div className="flex items-start gap-4 relative z-10">
          {/* Status icon */}
          <div className={`w-12 h-12 rounded-full border-2 flex items-center justify-center flex-shrink-0 transition-all
            ${isAlert ? 'border-[#FF003C] bg-[#FF003C]/10' : 'border-[#39FF14] bg-[#39FF14]/10'}`}
            style={isAlert ? { boxShadow: '0 0 20px rgba(255,0,60,0.4)', animation: 'pulse 0.6s ease-in-out infinite' } : {}}>
            <i className={`ph text-2xl ${isAlert ? 'ph-warning-octagon text-[#FF003C]' : 'ph-check-circle text-[#39FF14]'}`} />
          </div>

          <div className="flex-1">
            <div className="flex items-center gap-3 mb-2">
              <span className={`text-[10px] font-bold mono-text uppercase tracking-[3px] px-3 py-1 rounded border
                ${isAlert ? 'text-[#FF003C] border-[#FF003C]/40 bg-[#FF003C]/10' : 'text-[#39FF14] border-[#39FF14]/40 bg-[#39FF14]/10'}`}>
                {isAlert ? '⚠ UNUSUAL PATTERN DETECTED' : '✓ PATTERN NOMINAL'}
              </span>
              {isAlert && (
                <span className="text-[9px] text-[#FF003C] mono-text animate-pulse font-bold">
                  STREAK: {unusualStreak} CONSECUTIVE ANOMALIES
                </span>
              )}
            </div>

            <p className={`text-sm leading-relaxed ${isAlert ? 'text-[#FF003C]' : 'text-[#94A3B8]'}`}>
              {isAlert
                ? `Abnormal event sequence detected — ${unusualStreak} consecutive unusual transitions observed. Pattern deviates significantly from baseline login→access→normal flow. Possible evidence of lateral movement or log tampering in progress.`
                : lastTransition
                  ? `Transition from ${lastTransition.from?.label} → ${lastTransition.to?.label} is within expected behavioral baseline. Event chain follows normal session lifecycle patterns.`
                  : 'Monitoring event chain for unusual behavioral patterns...'
              }
            </p>

            {lastTransition && (
              <div className="flex items-center gap-3 mt-3">
                <span className="text-[9px] text-[#94A3B8] mono-text uppercase">Last transition:</span>
                <div className="flex items-center gap-2">
                  <EventShape shape={lastTransition.from?.shape} color={lastTransition.from?.color} size={16} />
                  <span className="text-[9px] mono-text font-bold" style={{ color: lastTransition.from?.color }}>{lastTransition.from?.type}</span>
                  <i className="ph ph-arrow-right text-[#94A3B8] text-xs" />
                  <EventShape shape={lastTransition.to?.shape} color={lastTransition.to?.color} size={16} />
                  <span className="text-[9px] mono-text font-bold" style={{ color: lastTransition.to?.color }}>{lastTransition.to?.type}</span>
                  <span className={`text-[9px] mono-text font-bold ml-2 ${lastTransition.unusual ? 'text-[#FF003C]' : 'text-[#39FF14]'}`}>
                    {lastTransition.unusual ? '⚠ UNUSUAL' : '✓ NORMAL'}
                  </span>
                </div>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>

    {/* Node detail modal */}
    {selectedNode && (
        <div className="fixed inset-0 z-[100] flex items-center justify-center p-4" onClick={closeNodeModal}>
          <div className="absolute inset-0 bg-[#070B14]/80 backdrop-blur-sm" />
          <div className="relative w-full max-w-md max-h-[85vh] bg-[#0D1323] border rounded-xl shadow-2xl overflow-hidden animate-fadeIn flex flex-col"
            style={{ borderColor: selectedNode.color + '55', boxShadow: `0 0 40px ${selectedNode.color}18` }}
            onClick={e => e.stopPropagation()}>

            {/* Accent bar */}
            <div className="h-1 w-full flex-shrink-0" style={{ background: `linear-gradient(to right, ${selectedNode.color}, transparent)` }} />

            {/* Header */}
            <div className="flex items-center gap-3 p-5 border-b border-[#1E2D4A] flex-shrink-0">
              <div className="relative flex items-center justify-center flex-shrink-0">
                <EventShape shape={selectedNode.shape} color={selectedNode.color} size={48} />
                <span className="absolute text-[8px] font-black mono-text"
                  style={{ color: selectedNode.color }}>
                  {EVENT_CODE[selectedNode.type]}
                </span>
              </div>
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2">
                  <span className="text-base font-bold font-['Rajdhani'] uppercase tracking-widest" style={{ color: selectedNode.color }}>
                    {selectedNode.label}
                  </span>
                  <span className="text-[9px] mono-text px-2 py-0.5 rounded border"
                    style={{ color: selectedNode.color, borderColor: selectedNode.color + '44', backgroundColor: selectedNode.color + '10' }}>
                    EVENT #{selectedNode.index + 1}
                  </span>
                </div>
                <span className="text-[9px] text-[#94A3B8] mono-text uppercase tracking-widest">
                  {selectedNode.type} · {selectedNode.shape}
                </span>
              </div>
              <button onClick={closeNodeModal} className="text-[#94A3B8] hover:text-white transition-colors p-1 flex-shrink-0">
                <i className="ph ph-x text-lg" />
              </button>
            </div>

            {/* Log line */}
            <div className="p-5 space-y-4 overflow-y-auto min-h-0">
              <div>
                <div className="text-[9px] font-bold text-[#94A3B8] mono-text uppercase tracking-widest mb-2 flex items-center gap-2">
                  <i className="ph ph-terminal-window text-[#B026FF]" /> Raw Log Entry
                </div>
                <div className="bg-[#070B14] border border-[#1E2D4A] rounded-lg px-4 py-3">
                  <code className="text-[10px] text-[#B026FF] mono-text break-all leading-relaxed">
                    {selectedNode.log}
                  </code>
                </div>
              </div>

              <div>
                <div className="text-[9px] font-bold text-[#94A3B8] mono-text uppercase tracking-widest mb-2 flex items-center gap-2">
                  <i className="ph ph-info text-[#00F0FF]" /> What This Means
                </div>
                <p className="text-sm text-[#E2E8F0] leading-relaxed">
                  {EVENT_DESC[selectedNode.type]}
                </p>
              </div>

              {/* Unusual flag */}
              {selectedNode.index > 0 && (() => {
                const prev = selectedNode.prevNode;
                const unusual = selectedNode.isUnusualEdge;
                return unusual ? (
                  <div className="flex items-center gap-3 bg-[#FF003C]/10 border border-[#FF003C]/30 rounded-lg px-4 py-3">
                    <i className="ph ph-warning-octagon text-[#FF003C] text-lg flex-shrink-0 animate-pulse" />
                    <div>
                      <div className="text-[10px] font-bold text-[#FF003C] mono-text uppercase">Unusual Transition Detected</div>
                      <div className="text-[9px] text-[#94A3B8] mono-text mt-0.5">
                        {prev?.label} → {selectedNode.label} is outside the expected behavioral baseline.
                      </div>
                    </div>
                  </div>
                ) : (
                  <div className="flex items-center gap-3 bg-[#39FF14]/5 border border-[#39FF14]/20 rounded-lg px-4 py-3">
                    <i className="ph ph-check-circle text-[#39FF14] text-lg flex-shrink-0" />
                    <div className="text-[9px] text-[#94A3B8] mono-text">
                      Transition from <span className="text-white font-bold">{prev?.label}</span> is within normal baseline.
                    </div>
                  </div>
                );
              })()}
            </div>

            {/* Footer */}
            <div className="px-5 py-3 border-t border-[#1E2D4A] bg-[#070B14]/40 flex justify-between items-center flex-shrink-0">
              <span className="text-[9px] text-[#94A3B8] mono-text uppercase tracking-widest">TraceShield_X · Event Log Inspector</span>
              <button onClick={closeNodeModal}
                className="text-[10px] font-bold mono-text px-4 py-1.5 rounded border transition-all hover:bg-[#1E2D4A]"
                style={{ color: selectedNode.color, borderColor: selectedNode.color + '44' }}>
                CLOSE
              </button>
            </div>
          </div>
        </div>
      )}
    </>
  );
}

function Node({ label, icon, color }) {
  return (
    <div className="flex flex-col items-center gap-4">
       <div 
         className="w-20 h-20 rounded-2xl border flex items-center justify-center transition-all bg-[#121A2F]/50 group-hover:scale-110 shadow-lg"
         style={{ borderColor: color + '44', backgroundColor: color + '05', boxShadow: `0 0 20px ${color}22` }}
       >
          <i className={`ph ${icon} text-4xl`} style={{ color }} />
       </div>
       <div className="text-[11px] font-bold text-white mono-text uppercase tracking-[2px]">{label}</div>
    </div>
  )
}

function StatRow({ label, value, color, pulse = false }) {
  return (
    <div className="flex justify-between items-center bg-[#121A2F]/30 p-4 rounded-lg border border-[#1E2D4A] hover:border-[#00F0FF]/30 transition-all group/stat">
       <span className="text-xs text-[#94A3B8] uppercase tracking-[2px] font-['Rajdhani'] font-bold group-hover/stat:text-white transition-colors">{label}</span>
       <div className="flex items-center gap-3">
         {pulse && <div className="w-2 h-2 rounded-full bg-[#FF003C] animate-pulse shadow-[0_0_10px_#FF003C]" />}
         <span className={`text-xs font-bold mono-text tracking-widest ${pulse ? 'animate-pulse' : ''}`} style={{ color }}>{value}</span>
       </div>
    </div>
  )
}

function SmallCard({ icon, label, value, color }) {
  return (
    <div className="cyber-panel flex items-center gap-4 bg-[#121A2F]/30 hover:bg-[#121A2F]/60 transition-all">
       <div className="w-10 h-10 rounded border flex items-center justify-center" style={{ borderColor: color + '33', color }}>
          <i className={`ph ${icon} text-2xl`} />
       </div>
       <div>
          <div className="text-[8px] text-[#94A3B8] uppercase tracking-widest mono-text">{label}</div>
          <div className="text-sm font-bold text-white tracking-widest font-['Rajdhani'] uppercase" style={{ color }}>{value}</div>
       </div>
    </div>
  )
}
