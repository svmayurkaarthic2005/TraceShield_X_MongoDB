import React from 'react';

export default function HomePage() {
  return (
    <div className="animate-fadeIn space-y-12 pb-20">
      {/* Hero Section */}
      <section className="relative overflow-hidden cyber-panel p-8 md:p-12 min-h-[400px] flex flex-col justify-center border-l-4 border-l-[#00F0FF]">
        <div className="absolute top-0 right-0 w-1/2 h-full opacity-10 pointer-events-none overflow-hidden">
           <i className="ph ph-shield-checkered text-[350px] -mr-20 -mt-10 text-[#00F0FF]" />
        </div>
        
        <div className="relative z-10 max-w-2xl">
           <div className="flex items-center gap-3 mb-6">
              <span className="h-[1px] w-12 bg-[#00F0FF]" />
              <span className="text-[12px] font-bold text-[#00F0FF] tracking-[4px] uppercase mono-text">Mission_Briefing</span>
           </div>
           <h1 className="text-5xl md:text-6xl font-bold font-['Rajdhani'] uppercase mb-6 leading-tight">
              Next-Gen <br />
              <span className="text-[#00F0FF]" style={{ textShadow: '0 0 20px rgba(0,240,255,0.4)' }}>Cyber Forensic</span> <br />
              Intelligence
           </h1>
           <p className="text-[#94A3B8] text-lg leading-relaxed mb-8 font-['Inter']">
              TraceShield X++ is an advanced security orchestration platform designed to bridge the gap between 
              raw system logs and actionable forensic intelligence using AI-driven anomaly detection and graph-based relationship mapping.
           </p>
           <div className="flex flex-wrap gap-4">
              <div className="px-6 py-2 border border-[#00F0FF] text-[#00F0FF] font-['Rajdhani'] font-bold uppercase tracking-widest text-sm rounded bg-[#00F0FF]/5">
                 System_Ready
              </div>
              <div className="px-6 py-2 border border-[#1E2D4A] text-[#94A3B8] font-['Rajdhani'] font-bold uppercase tracking-widest text-sm rounded">
                 v4.2.0_Stable
              </div>
           </div>
        </div>
      </section>

      {/* How it Works */}
      <section>
        <div className="flex items-center gap-4 mb-10">
           <h2 className="text-2xl font-bold font-['Rajdhani'] uppercase m-0">Operation_Workflow</h2>
           <div className="h-[1px] flex-1 bg-gradient-to-r from-[#1E2D4A] to-transparent" />
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-8">
           <WorkflowStep 
             number="01" 
             icon="ph-broadcast" 
             title="Data Ingestion" 
             desc="Captures real-time system events, process IDs, and network packets across the entire operational environment."
             color="#00F0FF"
           />
           <WorkflowStep 
             number="02" 
             icon="ph-brain" 
             title="AI Analysis" 
             desc="Proprietary ML models profile behavior in real-time to detect subtle anomalies that bypass traditional static rules."
             color="#B026FF"
           />
           <WorkflowStep 
             number="03" 
             icon="ph-intersect-three" 
             title="Topology Mapping" 
             desc="Visualizes complex attack chains and latent relationships within an interactive, multi-dimensional forensic graph."
             color="#39FF14"
           />
        </div>
      </section>

      {/* Sidebar Guide */}
      <section>
        <div className="flex items-center gap-4 mb-10">
           <h2 className="text-2xl font-bold font-['Rajdhani'] uppercase m-0">Command_Structure</h2>
           <div className="h-[1px] flex-1 bg-gradient-to-r from-[#1E2D4A] to-transparent" />
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
           <GuideCard 
             icon="ph-squares-four" 
             title="Dashboard" 
             desc="The primary nerve center. Execute real-time forensics, trigger attack simulations, and view high-level threat scores from the current system snapshot."
           />
           <GuideCard 
             icon="ph-chart-bar" 
             title="Analytics" 
             desc="Deep-dive into historical trends and score distributions. Compare current threat vectors against global baselines and compliance requirements."
           />
           <GuideCard 
             icon="ph-shield-warning" 
             title="Threat Hunt" 
             desc="Active reconnaissance module. Query specific entities, IPs, or process patterns to uncover dormant threats hidden within background noise."
           />
           <GuideCard 
             icon="ph-terminal-window" 
             title="Data Logs" 
             desc="Raw event stream access. Direct look into system heartbeats with filtered forensic tagging for rapid auditing and manual verification."
           />
        </div>
      </section>
    </div>
  )
}

function WorkflowStep({ number, icon, title, desc, color }) {
  return (
    <div className="cyber-panel relative group hover:border-[#00F0FF]/30 transition-all border-b-2" style={{ borderBottomColor: color + '44' }}>
      <div className="absolute -top-4 -right-2 text-6xl font-black font-['Rajdhani'] opacity-5 text-white group-hover:opacity-10 transition-opacity">
        {number}
      </div>
      <div className="w-14 h-14 rounded bg-[#121A2F] border border-[#1E2D4A] flex items-center justify-center mb-6 group-hover:border-[#00F0FF]/30 transition-all shadow-inner">
         <i className={`ph ${icon} text-3xl`} style={{ color }} />
      </div>
      <h3 className="text-lg font-bold font-['Rajdhani'] uppercase mb-3 tracking-wide">{title}</h3>
      <p className="text-[#94A3B8] text-sm leading-relaxed mono-text">
        {desc}
      </p>
      <div className="mt-6 flex gap-1">
         {[1,2,3,4,5].map(i => <div key={i} className={`h-1 w-4 rounded-full ${i <= parseInt(number) ? '' : 'opacity-20'}`} style={{ backgroundColor: color }} />)}
      </div>
    </div>
  )
}

function GuideCard({ icon, title, desc }) {
  return (
    <div className="flex items-start gap-6 p-6 bg-[#0D1323]/50 border border-[#1E2D4A] rounded-lg hover:bg-[#121A2F]/50 transition-all group cursor-default">
      <div className="w-12 h-12 rounded flex items-center justify-center bg-[#070B14] border border-[#1E2D4A] text-[#00F0FF] group-hover:shadow-[0_0_15px_rgba(0,240,255,0.2)] transition-all flex-shrink-0">
         <i className={`ph ${icon} text-2xl`} />
      </div>
      <div>
         <h4 className="text-white font-bold font-['Rajdhani'] uppercase tracking-widest mb-1 group-hover:text-[#00F0FF] transition-colors">{title}</h4>
         <p className="text-[#94A3B8] text-sm leading-relaxed">{desc}</p>
      </div>
    </div>
  )
}
