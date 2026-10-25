// Bar fill = how saturated a score component is relative to its OWN maximum
// contribution (weight * 100), not relative to a flat constant shared by
// every component. Clamped so malformed/out-of-range values can't produce an
// invalid CSS width.
export function computeBarFillPct(value, max) {
  if (!max) return 0
  return Math.min(Math.max((value / max) * 100, 0), 100)
}
