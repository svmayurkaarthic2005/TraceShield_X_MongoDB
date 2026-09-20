import { useEffect, useState, useCallback, useRef } from 'react'
import axios from 'axios'
import RiskCard from './components/RiskCard'
import AlertFeed from './components/AlertFeed'
import GraphPanel from './components/GraphPanel'
import LiveFeed from './components/LiveFeed'
import ThreatStatePanel from './components/ThreatStatePanel'
import SimulatedBadge from './components/SimulatedBadge'
import HomePage from './components/HomePage'
import AnalyticsPage from './components/AnalyticsPage'
import DataLogsPage from './components/DataLogsPage'
import ThreatHuntPage from './components/ThreatHuntPage'
import HoneypotPage from './components/HoneypotPage'

const api    = axios.create({ baseURL: 'http://localhost:8000' })
const ingest = axios.create({ baseURL: 'http://127.0.0.1:8001' })

function StatusDot({ ok, label, showLabel = true }) {
  return (
    <div className="flex items-center gap-3 px-3 py-1">
      <div className="relative flex items-center justify-center">
        <span className={`w-2.5 h-2.5 rounded-full ${ok ? 'status-dot-pulse' : 'bg-[#FF003C] danger-blink'}`} />
      </div>
      {showLabel && (
        <span className={`text-[11px] font-bold uppercase tracking-wider mono-text ${ok ? 'text-[#39FF14]' : 'text-[#FF003C]'}`}>
          {label}
        </span>
      )}
    </div>
  )
}

const MAX_EVENTS = 100

// Deduplicate events by ip+timestamp key
function mergeEvents(existing, incoming) {
  const keys = new Set(existing.map(e => `${e.ip}-${e.timestamp}`))
  const fresh = incoming.filter(e => !keys.has(`${e.ip}-${e.timestamp}`))
  return [...fresh, ...existing].slice(0, MAX_EVENTS)
}

export default function App() {
  const [view, setView]             = useState('home')
  const [status, setStatus]         = useState(null)
  const [result, setResult]         = useState(null)
  const [graph, setGraph]           = useState({ nodes: [], edges: [] })
  const [loading, setLoading]       = useState(false)
  const [error, setError]           = useState(null)
  const [autoRefresh, setAutoRefresh] = useState(false)
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false)
  // Shared event state — persists across page navigation
  const [liveEvents, setLiveEvents] = useState([])
  const [wsStatus, setWsStatus]     = useState('disconnected')
  // Dataset upload state — persists across navigation
  const [datasetResults, setDatasetResults] = useState(null)
  const [datasetPausedUntil, setDatasetPausedUntil] = useState(null)
  const datasetPausedUntilRef = useRef(null)   // ref for safe access inside WS closure
  const wsRef = useRef(null)

  // Called by DataLogsPage after a successful upload — clears live feed and shows only dataset events for 10 min
  const onDatasetUploaded = (uploadData) => {
    setDatasetResults(uploadData)
    const until = new Date(Date.now() + 10 * 60 * 1000)
    setDatasetPausedUntil(until)
    datasetPausedUntilRef.current = until

    // Build dataset events
    const dsEvents = (uploadData.results || [])
      .filter(r => r.ip && r.ip !== 'unknown')
      .map(r => ({
        ip:            r.ip,
        device:        r.features?.device || 'dataset_upload',
        request_count: r.features?.total_events || 1,
        status:        r.status,
        risk_score:    r.risk_score,
        attack_type:   r.attack_type || 'NORMAL_ACTIVITY',
        actions:       r.actions || [],
        reason:        r.reason || 'N/A',
        log_score:     r.components?.log_score || 0,
        ml_score:      r.components?.ml_score || 0,
        timestamp:     new Date().toISOString(),
        source:        'dataset',
        filename:      uploadData.filename || 'uploaded_log',
      }))

    // REPLACE all previous events with only dataset results
    setLiveEvents(dsEvents)
  }
  // Single persistent WebSocket — lives for the entire app lifetime
  useEffect(() => {
    let reconnectTimer = null
    let destroyed = false

    function connect() {
      if (destroyed) return
      try {
        const ws = new WebSocket('ws://127.0.0.1:8001/ws')
        wsRef.current = ws

        ws.onopen = () => { if (!destroyed) setWsStatus('connected') }

        ws.onmessage = (e) => {
          if (destroyed) return
          try {
            const event = JSON.parse(e.data)
            // Skip real-time events during dataset pause window (use ref — safe in closure)
            const paused = datasetPausedUntilRef.current
            if (paused && new Date() < new Date(paused)) return
            setLiveEvents(prev => {
              const key = `${event.ip}-${event.timestamp}`
              if (prev.some(p => `${p.ip}-${p.timestamp}` === key)) return prev
              return [event, ...prev].slice(0, MAX_EVENTS)
            })
          } catch { /* ignore malformed */ }
        }

        ws.onclose = () => {
          if (destroyed) return
          setWsStatus('disconnected')
          reconnectTimer = setTimeout(connect, 3000)
        }

        ws.onerror = () => {
          // suppress — onclose will fire next and handle reconnect
          ws.close()
        }
      } catch {
        if (!destroyed) {
          setWsStatus('error')
          reconnectTimer = setTimeout(connect, 5000)
        }
      }
    }

    connect()
    return () => {
      destroyed = true
      clearTimeout(reconnectTimer)
      const ws = wsRef.current
      if (ws) {
        ws.onclose = null  // prevent reconnect on intentional close
        ws.onerror = null
        ws.onmessage = null
        // Closing a socket mid-handshake makes the browser report a failed
        // connection, so wait for it to open before closing it.
        if (ws.readyState === WebSocket.CONNECTING) ws.onopen = () => ws.close()
        else if (ws.readyState === WebSocket.OPEN) ws.close()
      }
      wsRef.current = null
    }
  }, [])

  // Fetch recent events on mount so history is available immediately
  useEffect(() => {
    ingest.get('/events/recent?limit=100')
      .then(r => setLiveEvents(r.data.events || []))
      .catch(() => {})
  }, [])

  // Auto-restore live feed when dataset pause expires
  useEffect(() => {
    if (!datasetPausedUntil) return
    const ms = new Date(datasetPausedUntil) - Date.now()
    if (ms <= 0) return
    const t = setTimeout(() => {
      setDatasetPausedUntil(null)
      setDatasetResults(null)
      datasetPausedUntilRef.current = null
      ingest.get('/events/recent?limit=100')
        .then(r => setLiveEvents(r.data.events || []))
        .catch(() => {})
    }, ms)
    return () => clearTimeout(t)
  }, [datasetPausedUntil])

  useEffect(() => {
    api.get('/api/status')
      .then(r => setStatus(r.data))
      .catch(() => setStatus(null))
  }, [])

  const fetchGraph = useCallback(() =>
    api.get('/api/graph').then(r => setGraph(r.data)).catch(() => {}), [])

  const fetchAnalyze = useCallback(async () => {
    if (loading) return
    setLoading(true)
    setError(null)
    try {
      const r = await api.get('/api/analyze')
      setResult(r.data)
      await fetchGraph()
    } catch {
      setError('Analysis failed. Is the backend running?')
    } finally {
      setLoading(false)
    }
  }, [loading, fetchGraph])

  // Live Hook: run real attack simulations every 2s and stream to live feed + update left panel
  useEffect(() => {
    if (!autoRefresh) return
    const interval = setInterval(async () => {
      try {
        const r = await api.post('/api/simulate', { count: 1 })
        // /api/simulate already ingests the event and broadcasts it over the
        // WebSocket, so the live feed updates without a second post here.
        setResult(r.data[0])
      } catch {}
    }, 2000)
    return () => clearInterval(interval)
  }, [autoRefresh])

  const simulate = async () => {
    setLoading(true)
    setError(null)
    try {
      const r = await api.post('/api/simulate', { count: 1 })

      // Always update the left panel with attack details. /api/simulate has
      // already ingested the event and broadcast it to the live feed.
      setResult(r.data[0])
      await fetchGraph()
    } catch {
      setError('Simulation failed. Is the backend running?')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="flex h-screen w-screen overflow-hidden bg-[#070B14] font-['Inter']">
      {/* Background Overlays */}
      <div className="bg-grid" />
      <div className="scanline" />



      {/* Sidebar */}
      <aside className={`main-sidebar flex flex-col border-r border-[#1E2D4A] bg-[#0D1323] transition-all duration-300 z-50 ${sidebarCollapsed ? 'collapsed' : ''}`}>

        <div className="p-4 flex items-center gap-3 h-[70px] border-b border-[#1E2D4A] cursor-pointer" onClick={() => setView('home')}>
          <div className="w-10 h-10 bg-[#00F0FF] rounded flex items-center justify-center flex-shrink-0 shadow-[0_0_15px_rgba(0,240,255,0.4)]">
             <i className="ph ph-shield-checkered text-[#0D1323] text-2xl" />
          </div>
          {!sidebarCollapsed && (
            <div className="overflow-hidden">
               <h1 className="text-xl font-bold tracking-tight text-white m-0 whitespace-nowrap" style={{ textShadow: '0 0 10px #00F0FF', fontFamily: 'Rajdhani' }}>
                TRACE<span className="text-[#00F0FF]">SHIELD</span>
              </h1>
              <div className="text-[9px] text-[#00F0FF] font-bold tracking-[3px] mono-text opacity-70">X.FORENSICS</div>
            </div>
          )}
        </div>

        <nav className="flex-1 p-3 space-y-1 overflow-y-auto mt-4">
          <NavItem icon="ph-house" label="Home" active={view === 'home'} onClick={() => setView('home')} collapsed={sidebarCollapsed} />
          <NavItem icon="ph-squares-four" label="Dashboard" active={view === 'dashboard'} onClick={() => setView('dashboard')} collapsed={sidebarCollapsed} />
          <NavItem icon="ph-chart-bar" label="Analytics" active={view === 'analytics'} onClick={() => setView('analytics')} collapsed={sidebarCollapsed} />
          <NavItem icon="ph-shield-warning" label="Threat Hunt" active={view === 'threat'}   onClick={() => setView('threat')}   collapsed={sidebarCollapsed} />
          <NavItem icon="ph-terminal-window" label="Data Logs"  active={view === 'logs'}     onClick={() => setView('logs')}     collapsed={sidebarCollapsed} />
          <NavItem icon="ph-bug"             label="Honeypot"   active={view === 'honeypot'} onClick={() => setView('honeypot')} collapsed={sidebarCollapsed} />
        </nav>

        <div className="p-3 border-t border-[#1E2D4A] bg-[#070B14]/30">
           <StatusDot ok={status?.neo4j === true} label="Neo4j" showLabel={!sidebarCollapsed} />
           <StatusDot ok={status?.model_loaded} label="AI Model" showLabel={!sidebarCollapsed} />
           
           {!sidebarCollapsed && status?.dataset_rows != null && (
             <div className="px-3 py-2 mt-2 bg-[#121A2F] border border-[#1E2D4A] rounded-md">
                <div className="text-[10px] text-[#94A3B8] uppercase tracking-widest mono-text">Dataset Scope</div>
                <div className="text-lg font-bold text-white mono-text">{status.dataset_rows.toLocaleString()} <span className="text-[10px] text-[#00F0FF]">RECORDS</span></div>
             </div>
           )}

           <button 
             onClick={() => setSidebarCollapsed(!sidebarCollapsed)}
             className="w-full mt-4 h-10 flex items-center justify-center text-[#94A3B8] hover:text-[#00F0FF] transition-colors border border-dashed border-[#1E2D4A] rounded-md"
           >
             <i className={`ph ${sidebarCollapsed ? 'ph-caret-double-right' : 'ph-caret-double-left'} text-lg`} />
           </button>
        </div>
      </aside>

      {/* Main Content */}
      <main className="flex-1 flex flex-col relative z-20 min-w-0">
        {/* Topbar */}
        <header className="h-[70px] border-b border-[#1E2D4A] backdrop-blur-[10px] flex items-center justify-between px-6 sticky top-0 bg-[#070B14]/80 z-40">
          <div className="flex flex-col">
            <div className="flex items-center gap-2">
              <span className="text-[10px] font-bold text-[#00F0FF] mono-text tracking-widest uppercase bg-[#00F0FF]/10 px-2 py-0.5 rounded">Core_System</span>
              <span className="text-[#1E2D4A] text-xs">/</span>
               <span className="text-[10px] font-bold text-[#94A3B8] mono-text tracking-widest uppercase">
                 {view === 'home' ? 'System_Manual' : view === 'analytics' ? 'Predictive_Data' : view === 'logs' ? 'Event_Viewer' : view === 'threat' ? 'Threat_Hunt' : view === 'honeypot' ? 'Honeypot_Trap' : 'Forensic_Output'}
               </span>
            </div>
            <div className="flex items-center gap-2 mt-0.5">
               <span className="w-1.5 h-1.5 bg-[#39FF14] rounded-full animate-pulse shadow-[0_0_5px_#39FF14]" />
               <span className="text-[11px] text-[#E2E8F0] font-bold tracking-widest uppercase font-['Rajdhani']">Real-time monitoring active</span>
            </div>
          </div>

          <div className="flex items-center gap-6">
             <div className="hidden md:flex flex-col items-end">
                <span className="text-[10px] text-[#94A3B8] mono-text uppercase flex items-center gap-1.5">
                  Network Latency <SimulatedBadge label="sim" title="Static placeholder — latency is never measured" />
                </span>
                <span className="text-sm font-bold text-[#FFB020]/70 mono-text">12.4ms <i className="ph ph-chart-line-up" /></span>
             </div>
             <div className="h-10 w-[1px] bg-[#1E2D4A]" />
             <div className="flex items-center gap-3 cursor-pointer group">
                <div className="text-right hidden sm:block">
                   <div className="text-sm font-bold text-white group-hover:text-[#00F0FF] transition-colors font-['Rajdhani'] flex items-center gap-1.5 justify-end">
                     OPERATOR_01 <SimulatedBadge label="sim" title="Static placeholder — there is no authentication in this build" />
                   </div>
                   <div className="text-[9px] text-[#00F0FF] mono-text">SEC_LVL_04</div>
                </div>
                <div className="w-10 h-10 rounded bg-[#1E2D4A] flex items-center justify-center border border-[#1E2D4A] group-hover:border-[#00F0FF] transition-all overflow-hidden relative">
                   <i className="ph ph-user-focus text-2xl text-[#94A3B8]" />
                   <div className="absolute bottom-0 right-0 w-2.5 h-2.5 bg-[#39FF14] border-2 border-[#0D1323] rounded-full" />
                </div>
             </div>
          </div>
        </header>

        {/* Scrollable Content */}
        <div className="flex-1 overflow-y-auto p-4 md:p-8 relative">
          <div className="max-w-[1400px] mx-auto space-y-8">
            
            {view === 'home' ? (
              <HomePage onStart={() => setView('dashboard')} />
            ) : view === 'analytics' ? (
              <AnalyticsPage lastResult={result} liveEvents={liveEvents} />
            ) : view === 'logs' ? (
              <>
                {/* Detection state carries across uploads, so the reset control
                    belongs on the page where files are uploaded. */}
                <ThreatStatePanel />
                <DataLogsPage
                  liveEvents={liveEvents}
                  datasetResults={datasetResults}
                  onDatasetUploaded={onDatasetUploaded}
                />
              </>
            ) : view === 'threat' ? (
              <ThreatHuntPage lastResult={result} liveEvents={liveEvents} datasetSummary={datasetResults} />
            ) : view === 'honeypot' ? (
              <>
                <ThreatStatePanel />
                <HoneypotPage liveEvents={liveEvents} />
              </>
            ) : (
              <>
                {/* Page Header */}
                <div className="flex flex-col md:flex-row md:items-end justify-between gap-6 pb-6 border-b border-[#1E2D4A]/50 animate-fadeIn">
                  <div>
                    <h2 className="text-4xl font-bold text-white tracking-tight font-['Rajdhani'] uppercase">Security <span className="text-[#00F0FF]">Dashboard</span></h2>
                    <p className="text-[#94A3B8] mt-1 mono-text text-sm">Automated Threat Detection & Vulnerability Analysis Pipeline</p>
                  </div>
                  
                  {/* Action Bar */}
                  <div className="flex flex-wrap gap-3">
                    <button onClick={fetchAnalyze} disabled={loading} className="cyber-btn h-12 px-6">
                      <i className={`ph ${loading ? 'ph-spinner animate-spin' : 'ph-magnifying-glass'} text-xl`} />
                      {!loading ? 'Analyze Sample' : 'Running...'}
                    </button>
                    <button onClick={simulate} disabled={loading} className="cyber-btn cyber-btn-purple h-12 px-6">
                      <i className={`ph ${loading ? 'ph-spinner animate-spin' : 'ph-warning-circle'} text-xl`} />
                      {!loading ? 'Simulate Attack' : 'Injecting...'}
                    </button>
                    <button 
                      onClick={() => setAutoRefresh(v => !v)}
                      className={`cyber-btn h-12 px-6 ${autoRefresh ? 'border-[#39FF14] text-[#39FF14] shadow-[0_0_15px_rgba(57,255,20,0.1)]' : ''}`}
                    >
                      <i className={`ph ${autoRefresh ? 'ph-broadcast' : 'ph-antenna-off'} text-xl`} />
                      {autoRefresh ? 'Live Hook: ON' : 'Live Hook: OFF'}
                    </button>
                  </div>
                </div>

                {error && (
                  <div className="px-5 py-4 rounded-md bg-[#FF003C]/10 border border-[#FF003C]/30 flex items-center gap-4 text-[#FF003C] animate-pulse">
                    <i className="ph ph-warning-octagon text-2xl" />
                    <div className="mono-text text-sm">
                      <span className="font-bold uppercase">Critical System Error:</span> {error}
                    </div>
                  </div>
                )}

                {result ? (
                  <div className="grid grid-cols-12 gap-8 animate-fadeIn">
                    <div className="col-span-12 xl:col-span-5">
                      <RiskCard
                        risk_score={result.risk_score}
                        risk_level={result.risk_level}
                        risk_color={result.risk_color}
                        anomaly={result.anomaly}
                        anomaly_score={result.anomaly_score}
                        components={result.components}
                        summary={result.summary}
                      />
                    </div>
                    <div className="col-span-12 xl:col-span-7">
                      <AlertFeed
                        flags={result.readable_flags?.length ? result.readable_flags : result.flags}
                        rawFlags={result.flags}
                        breakdown={result.breakdown}
                        timeline={result.timeline || []}
                      />
                    </div>
                  </div>
                ) : (
                  <div className="flex flex-col items-center justify-center py-40 border border-[#1E2D4A] border-dashed rounded-xl bg-[#0D1323]/20 relative overflow-hidden group animate-fadeIn">
                    <div className="absolute inset-0 bg-gradient-to-b from-transparent to-[#00F0FF]/5 opacity-0 group-hover:opacity-100 transition-opacity" />
                    <div className="relative mb-8">
                      <div className="absolute -inset-8 bg-[#00F0FF]/10 rounded-full blur-3xl animate-pulse" />
                      <i className="ph ph-shield-search text-[120px] text-[#1E2D4A] group-hover:text-[#00F0FF]/20 transition-colors" />
                      <div className="absolute inset-0 flex items-center justify-center">
                        <i className="ph ph-fingerprint text-5xl text-[#00F0FF] opacity-40 animate-pulse" />
                      </div>
                    </div>
                    <h3 className="text-2xl text-[#E2E8F0] font-bold font-['Rajdhani'] tracking-[4px] uppercase mb-2">System Ready</h3>
                    <p className="text-sm text-[#94A3B8] mono-text max-w-md text-center opacity-70">
                      Select an operational mode to begin real-time packet capture and anomaly detection profiling.
                    </p>
                    <div className="mt-8 flex gap-4 opacity-40">
                      <div className="w-2 h-2 rounded-full bg-[#1E2D4A]" />
                      <div className="w-2 h-2 rounded-full bg-[#1E2D4A]" />
                      <div className="w-2 h-2 rounded-full bg-[#1E2D4A]" />
                    </div>
                  </div>
                )}

                {/* Live Event Stream — always visible */}
                <LiveFeed events={liveEvents} onEvents={setLiveEvents} wsStatus={wsStatus} datasetPausedUntil={datasetPausedUntil} datasetSummary={datasetResults} />

                {/* Active Threat State — blocked / honeypot / flagged IPs */}
                <ThreatStatePanel />
              </>
            )}

          </div>
        </div>
      </main>
    </div>
  )
}

function NavItem({ icon, label, active = false, collapsed = false, onClick }) {
  return (
    <div 
      title={collapsed ? label : ''}
      onClick={onClick}
      className={`flex items-center gap-4 px-4 py-3 rounded-md cursor-pointer transition-all duration-300 group relative ${active ? 'bg-[#00F0FF]/10 border-l-4 border-[#00F0FF]' : 'text-[#94A3B8] hover:bg-[#121A2F] hover:text-[#E2E8F0] border-l-4 border-transparent'}`}
    >

      <i className={`ph ${icon} text-2xl ${active ? 'text-[#00F0FF]' : 'group-hover:text-[#00F0FF]'}`} />
      {!collapsed && (
        <span className="font-bold text-[13px] tracking-wider uppercase font-['Rajdhani'] whitespace-nowrap">{label}</span>
      )}
      {active && !collapsed && (
        <div className="ml-auto w-2 h-2 bg-[#00F0FF] rounded-full shadow-[0_0_10px_#00F0FF]" />
      )}
      {active && collapsed && (
        <div className="absolute right-0 top-1/2 -translate-y-1/2 w-1.5 h-6 bg-[#00F0FF] rounded-l-full shadow-[0_0_15px_#00F0FF]" />
      )}
    </div>
  )
}
