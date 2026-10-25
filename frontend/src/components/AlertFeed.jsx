import { computeBarFillPct } from '../utils/barFill'

const RAW_SEVERITY = {
  BRUTE_FORCE:       'HIGH',
  LOW_REPUTATION_IP: 'HIGH',
  LONG_SESSION:      'MEDIUM',
  ODD_ACCESS_TIME:   'MEDIUM',
}

// Labels name the component each bar actually carries, and `max` is that
// component's own ceiling — weight(0-1) * 100 (see risk_engine.W_*) — since
// each component contributes a different maximum number of points to the
// final score. Bar fill = contribution / max, NOT contribution / 100.
const BAR_LABELS = [
  { key: 'ml_contribution',       label: 'ML Anomaly (20%)',    color: '#B026FF', max: 20 },
  { key: 'log_contribution',      label: 'Log Signals (20%)',   color: '#FF003C', max: 20 },
  { key: 'count_contribution',    label: 'Request Count (20%)', color: '#FFEA00', max: 20 },
  { key: 'temporal_contribution', label: 'Temporal Rate (15%)', color: '#00F0FF', max: 15 },
  { key: 'spike_contribution',    label: 'Spike Deviation (15%)', color: '#FF6B00', max: 15 },
  { key: 'trend_contribution',    label: 'Behavioural Trend (10%)', color: '#39FF14', max: 10 },
]

export default function AlertFeed({ flags = [], rawFlags = [], breakdown = {}, timeline = [] }) {
  const timestamp = new Date().toLocaleTimeString('en-US', { hour12: false });

  return (
    <div className="cyber-panel h-full flex flex-col space-y-8">
      <div className="flex items-center justify-between border-b border-[#1E2D4A] pb-3">
         <h2 className="panel-title text-sm m-0">Event_Log_Stream</h2>
         <div className="flex items-center gap-2 mono-text text-[10px] text-[#39FF14]">
            <span className="w-2 h-2 rounded-full bg-[#39FF14] animate-pulse" />
            LIVE_FEED
         </div>
      </div>

      {/* Flag badges */}
      <section>
        <div className="flex items-center gap-2 mb-4">
           <i className="ph ph-list-bullets text-[#00F0FF]" />
           <p className="text-[#94A3B8] text-[10px] uppercase tracking-widest font-bold font-['Rajdhani']">Triggered Security Rules</p>
        </div>
        
        {flags.length === 0 ? (
          <div className="bg-[#05080F] border border-[#111A2E] p-4 rounded flex items-center gap-3">
            <i className="ph ph-shield-check text-[#39FF14] text-xl" />
            <p className="text-[#39FF14] text-xs mono-text">
               NO_THREATS_DETECTED:: System integrity verified. Continuous monitoring active.
            </p>
          </div>
        ) : (
          <div className="flex flex-wrap gap-3">
            {flags.map((flag, i) => {
              const raw = rawFlags[i] || ''
              const sev = RAW_SEVERITY[raw] || 'MEDIUM'
              const isHigh = sev === 'HIGH'
              return (
                <div key={i} className={`flex items-center gap-2 px-3 py-1.5 rounded border border-l-4 transition-all duration-300 ${
                  isHigh ? 'badge-critical' : 'badge-medium'
                }`}>
                  <i className={`ph ${isHigh ? 'ph-warning-diamond' : 'ph-info'} text-base`} />
                  <span className="text-[11px] font-bold tracking-wider uppercase font-['Rajdhani']">{flag}</span>
                </div>
              )
            })}
          </div>
        )}
      </section>

      {/* Suspicious Event Timeline */}
      <section className="flex-1 flex flex-col">
          <div className="flex items-center gap-2 mb-4">
            <i className="ph ph-clock-counter-clockwise text-[#FFEA00]" />
            <p className="text-[#94A3B8] text-[10px] uppercase tracking-widest font-bold font-['Rajdhani']">Suspicious Event Timeline</p>
            <span className="text-[9px] text-[#94A3B8] mono-text ml-1">{timeline.length} events</span>
          </div>
          <div className="bg-[#070B14] border border-[#1E2D4A] rounded-lg overflow-hidden">
            {/* Header */}
            <div className="grid gap-2 px-4 py-2 border-b border-[#1E2D4A] bg-[#0D1323]"
              style={{ gridTemplateColumns: '150px 110px 1fr' }}>
              {['Timestamp', 'Log Source', 'Description & Evidence'].map(h => (
                <span key={h} className="text-[9px] font-bold text-[#94A3B8] mono-text uppercase tracking-widest">{h}</span>
              ))}
            </div>
            {/* Rows */}
            <div className="divide-y divide-[#1E2D4A]/40">
              {timeline.map((evt, i) => {
                const isObj = typeof evt === 'object' && evt !== null;
                return (
                  <div key={i} className="grid gap-2 px-4 py-3 hover:bg-[#0D1323]/60 transition-colors"
                    style={{ gridTemplateColumns: '150px 110px 1fr' }}>
                    <span className="text-[10px] text-[#FFEA00] mono-text font-bold">
                      {isObj ? evt.time : timestamp}
                    </span>
                    <span className="text-[10px] text-[#B026FF] mono-text font-bold">
                      {isObj ? evt.source : 'syslog'}
                    </span>
                    <div className="flex flex-col gap-1">
                      <span className="text-[11px] text-white">
                        {isObj ? evt.description : evt}
                      </span>
                      {isObj && evt.evidence && (
                        <code className="text-[9px] text-[#94A3B8] mono-text break-all">{evt.evidence}</code>
                      )}
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        </section>

      {/* Breakdown bars */}
      {Object.keys(breakdown).length > 0 && (
        <section>
          <div className="flex items-center gap-2 mb-4">
             <i className="ph ph-chart-pie text-[#00F0FF]" />
             <p className="text-[#94A3B8] text-[10px] uppercase tracking-widest font-bold font-['Rajdhani']">Vector Contribution</p>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-x-8 gap-y-4">
            {BAR_LABELS.map(({ key, label, color, max }) => {
              const val = breakdown[key] ?? 0
              const pct = computeBarFillPct(val, max)
              return (
                <div key={key}>
                  <div className="flex justify-between text-[10px] mono-text mb-1.5">
                    <span className="text-[#94A3B8]">{label}</span>
                    <span style={{ color }}>{val.toFixed(1)} / {max} pts</span>
                  </div>
                  <div className="progress-track bg-[#1E2D4A]/30 h-1">
                    <div 
                       className="h-full rounded-full transition-all duration-700 ease-out"
                       style={{ width: `${pct}%`, backgroundColor: color, boxShadow: `0 0 10px ${color}66` }} 
                    />
                  </div>
                </div>
              )
            })}
          </div>
        </section>
      )}
    </div>
  )
}
