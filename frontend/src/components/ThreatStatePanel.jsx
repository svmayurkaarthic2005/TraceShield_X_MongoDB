import { useEffect, useState } from 'react'
import api, { ingest } from '../services/api'

function Badge({ label, color }) {
  const styles = {
    red:    'bg-[#FF003C]/10 border-[#FF003C]/40 text-[#FF003C]',
    purple: 'bg-purple-900/20 border-purple-700/40 text-purple-400',
    yellow: 'bg-yellow-900/20 border-yellow-700/40 text-yellow-400',
  }
  return (
    <span className={`text-[9px] font-bold px-1.5 py-0.5 rounded border uppercase mono-text ${styles[color]}`}>
      {label}
    </span>
  )
}

export default function ThreatStatePanel() {
  const [state, setState]     = useState(null)
  const [loading, setLoading] = useState(false)

  const fetch = async () => {
    setLoading(true)
    try {
      const r = await api.get(ingest('/blocked'))
      setState(r.data)
    } catch {}
    setLoading(false)
  }

  // Detection state persists for the life of the service, so an earlier run
  // keeps skewing later ones until it is cleared.
  const resetState = async () => {
    if (!window.confirm('Clear all blocks, honeypots, flags and per-IP log signals?')) return
    setLoading(true)
    try { await api.post(ingest('/state/reset')) } catch {}
    await fetch()
  }

  const unblockIp = async (ip) => {
    setLoading(true)
    try { await api.delete(ingest(`/blocked/${ip}`)) } catch {}
    await fetch()
  }

  useEffect(() => {
    fetch()
    const interval = setInterval(fetch, 5000)  // refresh every 5s
    return () => clearInterval(interval)
  }, [])

  if (!state) return null

  const blocked  = Object.entries(state.blocked_ips  || {})
  const honeypot = Object.entries(state.honeypot_ips || {})
  const flagged  = Object.entries(state.flagged_ips  || {})
  const total    = blocked.length + honeypot.length + flagged.length

  return (
    <div className="rounded-xl border border-[#1E2D4A] bg-[#0D1323]/60 p-5">
      {/* Header */}
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center gap-2">
          <i className="ph ph-shield-warning text-[#FF003C] text-base" />
          <span className="text-[11px] font-bold text-[#94A3B8] uppercase tracking-widest mono-text">
            Active Threat State
          </span>
        </div>
        <div className="flex items-center gap-3">
          {total === 0 ? (
            <span className="text-[10px] text-[#39FF14] mono-text flex items-center gap-1">
              <span className="w-1.5 h-1.5 rounded-full bg-[#39FF14] animate-pulse" /> All clear
            </span>
          ) : (
            <span className="text-[10px] text-[#FF003C] mono-text font-bold">{total} active</span>
          )}
          <button onClick={fetch} disabled={loading} title="Refresh"
            className="text-[10px] text-[#94A3B8] hover:text-[#00F0FF] mono-text transition-colors">
            <i className={`ph ${loading ? 'ph-spinner animate-spin' : 'ph-arrows-clockwise'} text-xs`} />
          </button>
          <button onClick={resetState} disabled={loading || total === 0}
            title="Clear all detection state"
            className="text-[9px] font-bold uppercase tracking-widest mono-text px-2 py-1 rounded border
                       border-[#FF003C]/40 text-[#FF003C] hover:bg-[#FF003C]/10 transition-colors
                       disabled:opacity-30 disabled:cursor-not-allowed">
            Reset
          </button>
        </div>
      </div>

      {total === 0 ? (
        <p className="text-[#1E2D4A] text-xs mono-text text-center py-4">
          No blocked, honeypotted, or flagged IPs
        </p>
      ) : (
        <div className="space-y-4">

          {/* Blocked IPs */}
          {blocked.length > 0 && (
            <div>
              <div className="flex items-center gap-1.5 mb-2">
                <i className="ph ph-prohibit text-[#FF003C] text-xs" />
                <span className="text-[9px] font-bold text-[#FF003C] uppercase tracking-widest mono-text">
                  Blocked ({blocked.length})
                </span>
              </div>
              <div className="space-y-1.5">
                {blocked.map(([ip, data]) => (
                  <div key={ip} className="rounded-lg border border-[#FF003C]/30 bg-[#FF003C]/5 px-3 py-2 mono-text text-[11px]">
                    <div className="flex items-start justify-between gap-2">
                      <div className="flex items-center gap-2 min-w-0 flex-wrap">
                        <span className="w-1.5 h-1.5 rounded-full bg-[#FF003C] animate-pulse flex-shrink-0" />
                        <span className="font-bold text-[#FF003C] truncate max-w-[180px]" title={ip}>{ip}</span>
                        <Badge label="BLOCKED" color="red" />
                        <button onClick={() => unblockIp(ip)} disabled={loading}
                          title={`Unblock ${ip}`}
                          className="text-[9px] text-[#94A3B8] hover:text-[#39FF14] mono-text flex-shrink-0
                                     uppercase tracking-wider transition-colors disabled:opacity-30">
                          unblock
                        </button>
                      </div>
                      <span className="text-[#94A3B8] text-[10px] flex-shrink-0 whitespace-nowrap">
                        expires {new Date(data.expires_at).toLocaleTimeString()}
                      </span>
                    </div>
                    <div className="text-[#94A3B8] text-[10px] mt-1 truncate" title={data.reason}>
                      reason: {data.reason}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Honeypot IPs */}
          {honeypot.length > 0 && (
            <div>
              <div className="flex items-center gap-1.5 mb-2">
                <i className="ph ph-bug text-purple-400 text-xs" />
                <span className="text-[9px] font-bold text-purple-400 uppercase tracking-widest mono-text">
                  Honeypot ({honeypot.length})
                </span>
              </div>
              <div className="space-y-1.5">
                {honeypot.map(([ip, data]) => (
                  <div key={ip} className="rounded-lg border border-purple-700/30 bg-purple-900/10 px-3 py-2 mono-text text-[11px]">
                    <div className="flex items-start justify-between gap-2">
                      <div className="flex items-center gap-2 min-w-0 flex-wrap">
                        <span className="w-1.5 h-1.5 rounded-full bg-purple-400 flex-shrink-0" />
                        <span className="font-bold text-purple-300 truncate max-w-[180px]" title={ip}>{ip}</span>
                        <Badge label="HONEYPOT" color="purple" />
                        <span className="text-[9px] text-purple-400 truncate max-w-[120px]" title={data.honeypot_id}>{data.honeypot_id}</span>
                      </div>
                      <span className="text-[#94A3B8] text-[10px] flex-shrink-0 whitespace-nowrap">
                        {data.interaction_count} interaction{data.interaction_count !== 1 ? 's' : ''}
                      </span>
                    </div>
                    {data.fake_data_accessed?.length > 0 && (
                      <div className="mt-1.5 space-y-0.5">
                        {data.fake_data_accessed.slice(-2).map((cmd, i) => (
                          <div key={i} className="text-[9px] text-purple-400/70 font-mono truncate" title={cmd}>
                            $ {cmd}
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Flagged IPs */}
          {flagged.length > 0 && (
            <div>
              <div className="flex items-center gap-1.5 mb-2">
                <i className="ph ph-flag text-yellow-400 text-xs" />
                <span className="text-[9px] font-bold text-yellow-400 uppercase tracking-widest mono-text">
                  Flagged ({flagged.length})
                </span>
              </div>
              <div className="space-y-1.5">
                {flagged.map(([ip, data]) => (
                  <div key={ip} className="rounded-lg border border-yellow-700/30 bg-yellow-900/10 px-3 py-2 mono-text text-[11px]">
                    <div className="flex items-start justify-between gap-2">
                      <div className="flex items-center gap-2 min-w-0 flex-wrap">
                        <span className="w-1.5 h-1.5 rounded-full bg-yellow-400 flex-shrink-0" />
                        <span className="font-bold text-yellow-300 truncate max-w-[180px]" title={ip}>{ip}</span>
                        <Badge label="FLAGGED" color="yellow" />
                        <span className="text-[9px] text-yellow-400 flex-shrink-0">×{data.flag_count}</span>
                      </div>
                    </div>
                    <div className="text-[#94A3B8] text-[10px] mt-1 truncate" title={data.reason}>
                      {data.reason}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

        </div>
      )}
    </div>
  )
}
