import { useState, useEffect } from 'react'

const STATUS_COLORS = {
  EXTREME_RISK: { bg: 'bg-red-950/40',    text: 'text-red-400',    border: 'border-red-800/60',    dot: 'bg-red-500' },
  HIGH_RISK:    { bg: 'bg-orange-950/40', text: 'text-orange-400', border: 'border-orange-800/60', dot: 'bg-orange-500' },
  SUSPICIOUS:   { bg: 'bg-yellow-950/40', text: 'text-yellow-400', border: 'border-yellow-800/60', dot: 'bg-yellow-500' },
  NORMAL:       { bg: 'bg-[#0D1323]/60',  text: 'text-[#39FF14]',  border: 'border-[#1E2D4A]',     dot: 'bg-[#39FF14]' },
}

const MAX_EVENTS = 100

const ATTACK_BADGES = {
  PRIVILEGE_ESCALATION: { label: '🔴 PRIV_ESC',    cls: 'bg-red-950 text-red-400 border-red-800' },
  REMOTE_EXECUTION:     { label: '🟠 REMOTE_EXEC', cls: 'bg-orange-950 text-orange-400 border-orange-800' },
  PATH_TRAVERSAL:       { label: '🟠 PATH_TRAVERSAL', cls: 'bg-amber-950 text-amber-400 border-amber-800' },
  BRUTE_FORCE:          { label: '🟡 BRUTE_FORCE', cls: 'bg-yellow-950 text-yellow-400 border-yellow-800' },
  // Not a confirmed attack category — flagged anomalous with no log signature.
  BEHAVIORAL_ANOMALY:   { label: '🔵 ANOMALY',      cls: 'bg-cyan-950 text-cyan-400 border-cyan-800' },
}

function ActionBadge({ action }) {
  if (action === 'blocked')
    return <span className="text-[9px] font-bold px-1.5 py-0.5 rounded bg-red-950 text-red-400 border border-red-800 uppercase mono-text">BLOCKED</span>
  if (action === 'redirected_to_honeypot')
    return <span className="text-[9px] font-bold px-1.5 py-0.5 rounded bg-purple-950 text-purple-400 border border-purple-800 uppercase mono-text">HONEYPOT</span>
  if (action === 'flagged')
    return <span className="text-[9px] font-bold px-1.5 py-0.5 rounded bg-yellow-950 text-yellow-400 border border-yellow-800 uppercase mono-text">FLAGGED</span>
  return null
}

/**
 * LiveFeed — real-time event stream panel.
 *
 * Props:
 *   events   — shared event array from App (persists across navigation)
 *   onEvents — setter for shared event array
 *
 * Falls back to local state if props not provided.
 */
export default function LiveFeed({ events: externalEvents, onEvents, wsStatus = 'disconnected', datasetPausedUntil = null, datasetSummary = null }) {
  const [localEvents, setLocalEvents] = useState([])
  const [now, setNow] = useState(new Date())

  // Tick every 10s to update countdown
  useEffect(() => {
    if (!datasetPausedUntil) return
    const t = setInterval(() => setNow(new Date()), 10000)
    return () => clearInterval(t)
  }, [datasetPausedUntil])

  const isPaused = datasetPausedUntil && now < new Date(datasetPausedUntil)
  const minutesLeft = isPaused
    ? Math.ceil((new Date(datasetPausedUntil) - now) / 60000)
    : 0

  // Use external (App-level) state if provided, else local
  const events    = externalEvents ?? localEvents

  const wsIndicator = {
    connected:    { color: 'text-[#39FF14]', dot: 'bg-[#39FF14]', pulse: true,  label: 'Live: Connected' },
    disconnected: { color: 'text-[#94A3B8]', dot: 'bg-[#1E2D4A]', pulse: false, label: 'Live: Disconnected' },
    error:        { color: 'text-[#FF003C]', dot: 'bg-[#FF003C]', pulse: false, label: 'Live: Error' },
  }[wsStatus]

  return (
    <div className="rounded-xl border border-[#1E2D4A] bg-[#0D1323]/60 p-5">
      {/* Dataset mode banner with attack summary */}
      {isPaused && (
        <div className="mb-3 rounded-lg border border-[#00F0FF]/20 bg-[#00F0FF]/5 p-3">
          <div className="flex items-center gap-2 mb-2">
            <i className="ph ph-database text-[#00F0FF] text-sm" />
            <span className="text-[10px] font-bold text-[#00F0FF] mono-text uppercase tracking-widest">Dataset Mode</span>
            <span className="text-[10px] text-[#94A3B8] mono-text">· live feed resumes in {minutesLeft} min</span>
            {datasetSummary?.filename && (
              <span className="ml-auto text-[9px] text-[#00F0FF]/60 mono-text truncate max-w-[160px]">📁 {datasetSummary.filename}</span>
            )}
          </div>
          {datasetSummary?.results?.length > 0 && (() => {
            const results = datasetSummary.results
            const attackCounts = {}
            const statusCounts = { EXTREME_RISK: 0, HIGH_RISK: 0, SUSPICIOUS: 0, NORMAL: 0 }
            results.forEach(r => {
              const at = r.attack_type || 'NORMAL_ACTIVITY'
              if (at !== 'NORMAL_ACTIVITY') attackCounts[at] = (attackCounts[at] || 0) + 1
              if (statusCounts[r.status] !== undefined) statusCounts[r.status]++
            })
            const totalAttacks = Object.values(attackCounts).reduce((a, b) => a + b, 0)
            const ABADGE = { PRIVILEGE_ESCALATION: '🔴 PRIV_ESC', REMOTE_EXECUTION: '🟠 REMOTE_EXEC', BRUTE_FORCE: '🟡 BRUTE_FORCE' }
            return (
              <div className="space-y-2">
                {/* Status counts */}
                <div className="flex gap-3 flex-wrap">
                  {[['EXTREME_RISK','#FF003C'],['HIGH_RISK','#FF6B00'],['SUSPICIOUS','#FFEA00'],['NORMAL','#39FF14']].map(([k,c]) => statusCounts[k] > 0 && (
                    <span key={k} className="text-[10px] mono-text font-bold" style={{ color: c }}>
                      {statusCounts[k]} {k.replace('_',' ')}
                    </span>
                  ))}
                </div>
                {/* Attack type badges */}
                {totalAttacks > 0 && (
                  <div className="flex gap-2 flex-wrap items-center">
                    <span className="text-[9px] text-[#94A3B8] mono-text uppercase">Attack types:</span>
                    {Object.entries(attackCounts).map(([type, count]) => ABADGE[type] && (
                      <span key={type} className="text-[9px] font-bold px-1.5 py-0.5 rounded border border-[#FF003C]/40 bg-[#FF003C]/10 text-[#FF003C] mono-text">
                        {ABADGE[type]} ×{count}
                      </span>
                    ))}
                  </div>
                )}
              </div>
            )
          })()}
        </div>
      )}
      {/* Header */}
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center gap-2">
          <i className={`ph ${isPaused ? 'ph-database' : 'ph-broadcast'} text-[#00F0FF] text-base`} />
          <span className="text-[11px] font-bold text-[#94A3B8] uppercase tracking-widest mono-text">
            {isPaused ? 'Dataset Event Stream' : 'Live Event Stream'}
          </span>
          {events.length > 0 && (
            <span className="text-[9px] text-[#94A3B8] mono-text">({events.length})</span>
          )}
        </div>
        <span className={`flex items-center gap-1.5 text-[11px] mono-text font-bold ${isPaused ? 'text-[#00F0FF]' : wsIndicator.color}`}>
          <span className={`w-2 h-2 rounded-full ${isPaused ? 'bg-[#00F0FF]' : wsIndicator.dot} ${isPaused || wsIndicator.pulse ? 'animate-pulse' : ''}`} />
          {isPaused ? `Dataset Mode (${minutesLeft}m)` : wsIndicator.label}
        </span>
      </div>

      {/* Event list */}
      {events.length === 0 ? (
        <p className="text-[#1E2D4A] text-xs text-center py-6 mono-text">
          {wsStatus === 'connected'
            ? 'Waiting for events... POST to /ingest to see live data.'
            : 'Connecting to event stream...'}
        </p>
      ) : (
        <div className="space-y-1.5 max-h-72 overflow-y-auto pr-1">
          {events.map((ev, i) => {
            const c          = STATUS_COLORS[ev.status] || STATUS_COLORS.NORMAL
            const actions    = ev?.actions || []
            const attackBadge = ATTACK_BADGES[ev?.attack_type]
            return (
              <div key={i}
                className={`rounded-lg border px-3 py-2 text-xs mono-text ${c.bg} ${c.border}`}>
                <div className="flex items-center justify-between gap-2 flex-wrap">
                  <div className="flex items-center gap-2">
                    <span className={`w-1.5 h-1.5 rounded-full flex-shrink-0 ${c.dot}`} />
                    <span className={`font-bold ${c.text}`}>{ev.status}</span>
                    {ev.source === 'dataset' && (
                      <span className="text-[8px] font-bold px-1 py-0.5 rounded bg-[#00F0FF]/10 text-[#00F0FF] border border-[#00F0FF]/20 uppercase mono-text">
                        📁 {ev.filename || 'dataset'}
                      </span>
                    )}
                    {attackBadge && (
                      <span className={`text-[9px] font-bold px-1.5 py-0.5 rounded border ${attackBadge.cls}`}>
                        {attackBadge.label}
                      </span>
                    )}
                    <span className="text-[#94A3B8]">{ev.ip}</span>
                    <span className="text-[#1E2D4A]">→</span>
                    <span className="text-[#E2E8F0]">{ev.device}</span>
                  </div>
                  <div className="flex items-center gap-1.5 flex-wrap">
                    {actions.map((a, j) => <ActionBadge key={j} action={a} />)}
                    <span className="text-[#94A3B8] text-[10px]">
                      {new Date(ev.timestamp).toLocaleTimeString()}
                    </span>
                  </div>
                </div>
                <div className="flex items-center gap-4 mt-1 text-[10px] text-[#94A3B8]">
                  <span>score <span className="text-[#E2E8F0]">{ev.risk_score?.toFixed(1)}</span></span>
                  <span>ml <span className="text-[#00F0FF]">{ev.ml_score?.toFixed(1)}</span></span>
                  {(ev?.log_score ?? 0) > 0 && (
                    <span>logs <span className="text-yellow-400">{ev.log_score?.toFixed(1)}</span></span>
                  )}
                  {ev?.reason && ev.reason !== 'N/A' && (
                    <span className="text-[#1E2D4A] truncate max-w-[240px]">{ev.reason}</span>
                  )}
                </div>
              </div>
            )
          })}
        </div>
      )}
    </div>
  )
}
