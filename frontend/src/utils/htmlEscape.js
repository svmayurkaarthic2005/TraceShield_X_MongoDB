// Escapes text for safe interpolation into hand-built HTML strings (the
// forensic report in ThreatHuntPage.jsx is downloaded as a standalone file,
// so it can't rely on React's JSX auto-escaping). Covers the five characters
// that matter in HTML text content: & < > " '
const HTML_ESCAPES = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }

export function escapeHtml(value) {
  if (value === null || value === undefined) return ''
  return String(value).replace(/[&<>"']/g, (ch) => HTML_ESCAPES[ch])
}
