/**
 * Marks UI that shows generated placeholder data rather than anything the
 * detection pipeline produced. Amber is reserved for this — it is not used by
 * any severity level, so simulated content never reads as a real finding.
 */
export default function SimulatedBadge({ label = 'Simulated', title }) {
  return (
    <span
      title={title || 'Generated placeholder data — not produced by the detection pipeline'}
      className="inline-flex items-center gap-1 text-[8px] font-bold uppercase tracking-widest
                 mono-text px-1.5 py-0.5 rounded border border-[#FFB020]/40
                 bg-[#FFB020]/10 text-[#FFB020] whitespace-nowrap align-middle"
    >
      <i className="ph ph-flask text-[9px]" />
      {label}
    </span>
  )
}

/** Dashed amber frame + muted content, so simulated panels recede visually. */
export function SimulatedFrame({ children, note, className = '' }) {
  return (
    <div className={`relative rounded-xl border border-dashed border-[#FFB020]/35 ${className}`}>
      <div className="absolute -top-2 left-4 z-10 bg-[#070B14] px-1.5">
        <SimulatedBadge />
      </div>
      <div className="opacity-70 saturate-[0.65]">{children}</div>
      {note && (
        <p className="px-4 pb-3 text-[9px] text-[#FFB020]/70 mono-text">{note}</p>
      )}
    </div>
  )
}
