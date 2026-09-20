import { useEffect, useState } from 'react'

const LEVEL_CONFIG = {
  CRITICAL: { icon: 'ph-fire', color: '#FF003C', border: 'border-t-[#FF003C]' },
  HIGH:     { icon: 'ph-warning', color: '#FFEA00', border: 'border-t-[#FFEA00]' },
  MEDIUM:   { icon: 'ph-lightning', color: '#B026FF', border: 'border-t-[#B026FF]' },
  LOW:      { icon: 'ph-check-circle', color: '#39FF14', border: 'border-t-[#39FF14]' },
}

export default function RiskCard({ risk_score, risk_level, risk_color, anomaly, anomaly_score, summary, components }) {
  // A blocked IP short-circuits scoring and returns no components, so a 0 here
  // means "never scored", not "no anomaly".
  const notScored = !components || Object.keys(components).length === 0
  const [displayed, setDisplayed] = useState(0)

  useEffect(() => {
    if (risk_score == null) return
    setDisplayed(0)
    const steps = 40
    const increment = risk_score / steps
    let current = 0
    const timer = setInterval(() => {
      current += increment
      if (current >= risk_score) {
        setDisplayed(risk_score)
        clearInterval(timer)
      } else {
        setDisplayed(parseFloat(current.toFixed(1)))
      }
    }, 20)
    return () => clearInterval(timer)
  }, [risk_score])

  if (risk_score == null) return null

  const config = LEVEL_CONFIG[risk_level] || LEVEL_CONFIG.LOW

  return (
    <div className={`cyber-panel border-t-4 transition-all duration-500 hover:scale-[1.01] ${config.border}`}>
      <div className="flex items-center justify-between mb-6">
        <h2 className="panel-title text-sm m-0">Threat_Vector_Analysis</h2>
        <div className={`badge ${risk_level === 'CRITICAL' ? 'badge-critical' : risk_level === 'HIGH' ? 'badge-warning' : risk_level === 'MEDIUM' ? 'badge-medium' : 'badge-safe'} flex items-center gap-2 px-3 py-1.5`}>
          <i className={`ph ${config.icon} text-base`} />
          <span className="tracking-[2px]">{risk_level}</span>
        </div>
      </div>

      <div className="flex items-end gap-2 mb-8">
        <div className="text-7xl font-bold font-['Rajdhani'] tabular-nums tracking-tighter" style={{ color: config.color, textShadow: `0 0 20px ${config.color}44` }}>
          {displayed}
        </div>
        <div className="text-xl text-[#94A3B8] font-['Rajdhani'] mb-3">/ 100.00</div>
      </div>

      <div className="space-y-6">
         <div className="grid grid-cols-2 gap-4">
            <div className="bg-[#121A2F]/50 border border-[#1E2D4A] p-3 rounded">
               <div className="text-[10px] text-[#94A3B8] mono-text uppercase mb-1">Anomaly_Status</div>
               <div className={`text-sm font-bold mono-text ${anomaly ? 'text-[#FF003C]' : 'text-[#39FF14]'}`}>
                  {anomaly ? 'DETECTED' : 'NOMINAL'}
               </div>
            </div>
            <div className="bg-[#121A2F]/50 border border-[#1E2D4A] p-3 rounded">
               <div className="text-[10px] text-[#94A3B8] mono-text uppercase mb-1" title="Isolation Forest + LOF ensemble output, normalised to 0–1">
                  ML_Anomaly
               </div>
               <div className="text-sm font-bold mono-text text-[#E2E8F0]">
                  {notScored
                    ? <span className="text-[#94A3B8] font-normal italic text-[11px]">not scored — blocked</span>
                    : (anomaly_score ?? 0).toFixed(4)}
               </div>
            </div>
         </div>

         {/* Progress Bar Visualization */}
         <div>
            <div className="flex justify-between text-[10px] mono-text mb-2 text-[#94A3B8]">
               <span>RISK_GRADIENT</span>
               <span>{risk_score}%</span>
            </div>
            <div className="progress-track">
               <div className="progress-fill" style={{ width: `${risk_score}%` }} />
            </div>
         </div>

         {summary && (
            <div className="mt-6 p-4 bg-[#05080F] border border-[#111A2E] rounded relative overflow-hidden group">
               <div className="absolute top-0 right-0 p-1 opacity-20">
                  <i className="ph ph-quotes text-[#00F0FF] text-xl" />
               </div>
               <div className="text-[10px] text-[#00F0FF] mono-text mb-2 flex items-center gap-2">
                  <span className="w-1.5 h-1.5 bg-[#00F0FF] rounded-full animate-pulse" />
                  ANALYSIS_SUMMARY
               </div>
               <p className="text-[#94A3B8] text-[13px] leading-relaxed mono-text italic">
                  "{summary}"
               </p>
            </div>
         )}
      </div>
    </div>
  )
}
