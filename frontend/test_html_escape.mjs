// Regression test for the forensic-report HTML-injection fix (ThreatHuntPage.jsx
// generateHtmlReport). No test framework is configured in this project, so this
// is a plain Node script using the built-in assert module — run with:
//   node frontend/test_html_escape.mjs
import assert from 'node:assert/strict'
import { escapeHtml } from './src/utils/htmlEscape.js'

let passed = 0
function check(name, fn) {
  fn()
  passed++
  console.log(`[PASS] ${name}`)
}

check('malicious <img onerror> payload is neutralized', () => {
  const out = escapeHtml('<img src=x onerror=alert(1)>')
  assert.equal(out, '&lt;img src=x onerror=alert(1)&gt;')
  assert.ok(!out.includes('<img'), 'must not contain a live <img tag')
})

check('script tag is neutralized', () => {
  const out = escapeHtml('<script>alert(1)</script>')
  assert.equal(out, '&lt;script&gt;alert(1)&lt;/script&gt;')
  assert.ok(!/<script/i.test(out))
})

check('ampersands are escaped (and not double-escaped)', () => {
  assert.equal(escapeHtml('Tom & Jerry'), 'Tom &amp; Jerry')
})

check('quotes are escaped so attribute-breakout is not possible', () => {
  assert.equal(escapeHtml(`" onmouseover="alert(1)`), '&quot; onmouseover=&quot;alert(1)')
  assert.equal(escapeHtml(`' onmouseover='alert(1)`), '&#39; onmouseover=&#39;alert(1)')
})

check('angle brackets alone are escaped', () => {
  assert.equal(escapeHtml('5 > 3 and 2 < 4'), '5 &gt; 3 and 2 &lt; 4')
})

check('ordinary log text round-trips unchanged where no special chars exist', () => {
  const line = 'Failed password for invalid user admin from 10.0.0.5 port 51515 ssh2'
  assert.equal(escapeHtml(line), line)
})

check('non-ASCII text is preserved, not mangled', () => {
  const line = 'utilisateur élevé — 日本語テスト'
  assert.equal(escapeHtml(line), line)
})

check('null/undefined render as empty string, not "null"/"undefined"', () => {
  assert.equal(escapeHtml(null), '')
  assert.equal(escapeHtml(undefined), '')
})

check('numbers and other primitives are stringified safely', () => {
  assert.equal(escapeHtml(42), '42')
  assert.equal(escapeHtml(0), '0')
})

console.log(`\nAll ${passed} checks passed.`)
