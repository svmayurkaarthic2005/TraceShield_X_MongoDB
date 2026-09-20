import axios from 'axios'

const NODE_META = {
  User:    { bg: 'bg-[#00F0FF]/10', text: 'text-[#00F0FF]', icon: 'ph-user-gear', border: 'border-[#00F0FF]/30' },
  Process: { bg: 'bg-[#B026FF]/10', text: 'text-[#B026FF]', icon: 'ph-cpu', border: 'border-[#B026FF]/30' },
  File:    { bg: 'bg-[#FFEA00]/10', text: 'text-[#FFEA00]', icon: 'ph-file-code', border: 'border-[#FFEA00]/30' },
  Node:    { bg: 'bg-[#94A3B8]/10', text: 'text-[#E2E8F0]', icon: 'ph-cube', border: 'border-[#1E2D4A]' },
}

function getNodeType(node) {
  const name = node.id || node.properties?.name || ''
  if (name.startsWith('user_'))    return 'User'
  if (name.startsWith('process_')) return 'Process'
  if (name.startsWith('/'))        return 'File'
  return 'Node'
}

export default function GraphPanel({ nodes = [], edges = [], onCleared }) {
  const handleClear = async () => {
    try {
      await axios.delete('http://localhost:8000/api/graph/clear')
      if (onCleared) onCleared()
    } catch (e) {
      console.error('Failed to clear graph', e)
    }
  }

  return (
    <div className="cyber-panel relative overflow-hidden">
      <div className="absolute top-0 right-0 p-6 opacity-5 pointer-events-none">
         <i className="ph ph-graph text-9xl text-[#00F0FF]" />
      </div>

      <div className="flex items-center justify-between mb-8 border-b border-[#1E2D4A] pb-4">
        <div>
          <h2 className="panel-title text-sm m-0">Forensic_Relationship_Graph</h2>
          <p className="text-[#94A3B8] text-[10px] items-center gap-2 flex mt-1 mono-text">
             <i className="ph ph-intersect" />
             NODE_TOPOLOGY_MAPPING_V4.2
          </p>
        </div>
        <button onClick={handleClear} className="cyber-btn cyber-btn-danger text-[10px] py-1 px-4 h-8">
          <i className="ph ph-trash" />
          Purge Graph
        </button>
      </div>

      <div className="flex gap-6 mb-8 bg-[#05080F] border border-[#111A2E] p-3 rounded-md w-fit">
        {[['User','#00F0FF','ph-user'],['Process','#B026FF','ph-cpu'],['File','#FFEA00','ph-file']].map(([label, color, icon]) => (
          <span key={label} className="flex items-center gap-2 text-[10px] font-bold uppercase tracking-wider font-['Rajdhani']" style={{ color }}>
            <i className={`ph ${icon} text-sm`} /> {label}
          </span>
        ))}
      </div>

      {nodes.length === 0 ? (
        <div className="flex flex-col items-center justify-center py-20 text-center">
            <div className="w-16 h-16 rounded-full border border-dashed border-[#1E2D4A] flex items-center justify-center mb-4">
               <i className="ph ph-nodes text-[#1E2D4A] text-2xl animate-pulse" />
            </div>
            <p className="text-[#94A3B8] text-xs mono-text">
              NO_ACTIVE_RELATIONSHIPS:: Run analysis sequence to populate topology.
            </p>
        </div>
      ) : (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-10">
          <div className="space-y-4">
            <div className="flex items-center gap-2 mb-4">
               <span className="text-[10px] font-bold text-[#00F0FF] mono-text uppercase bg-[#00F0FF]/10 px-2 py-0.5 rounded">Active_Nodes</span>
               <span className="text-[#94A3B8] text-[10px] mono-text">COUNT: {nodes.length}</span>
            </div>
            <div className="flex flex-wrap gap-3">
              {nodes.map((node, i) => {
                const type = getNodeType(node)
                const meta = NODE_META[type]
                return (
                  <div key={i} className={`flex items-center gap-2 px-3 py-1.5 rounded border ${meta.bg} ${meta.text} ${meta.border} transition-all hover:scale-105 cursor-default`}>
                    <i className={`ph ${meta.icon} text-sm`} />
                    <span className="text-[11px] font-bold mono-text">{node.id}</span>
                  </div>
                )
              })}
            </div>
          </div>

          <div className="space-y-4">
            <div className="flex items-center gap-2 mb-4">
               <span className="text-[10px] font-bold text-[#FFEA00] mono-text uppercase bg-[#FFEA00]/10 px-2 py-0.5 rounded">Active_Edges</span>
               <span className="text-[#94A3B8] text-[10px] mono-text">COUNT: {edges.length}</span>
            </div>
            <div className="space-y-3 bg-[#05080F] border border-[#111A2E] rounded-md p-4 max-h-[400px] overflow-y-auto scrollbar-custom">
               {edges.map((edge, i) => (
                  <div key={i} className="flex items-center gap-3 text-[11px] mono-text p-2 rounded hover:bg-[#121A2F] transition-colors group">
                    <span className="text-[#00F0FF] font-bold px-2 py-0.5 bg-[#00F0FF]/5 rounded">{edge.source}</span>
                    <div className="flex-1 flex flex-col items-center px-2">
                       <span className="text-[#94A3B8] text-[9px] uppercase font-bold tracking-widest mb-1 opacity-0 group-hover:opacity-100 transition-opacity whitespace-nowrap">{edge.type}</span>
                       <div className="w-full h-[1px] bg-gradient-to-r from-transparent via-[#1E2D4A] to-transparent relative">
                          <i className="ph ph-caret-right absolute -right-1 -top-1.5 text-[10px] text-[#1E2D4A]" />
                       </div>
                    </div>
                    <span className="text-[#FFEA00] font-bold px-2 py-0.5 bg-[#FFEA00]/5 rounded">{edge.target}</span>
                  </div>
                ))}
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
