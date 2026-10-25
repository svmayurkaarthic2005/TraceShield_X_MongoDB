// Regression test for the Vector Contribution bar-scaling fix (AlertFeed.jsx).
// No test framework is configured in this project — plain Node + assert. Run:
//   node frontend/test_bar_fill.mjs
import assert from 'node:assert/strict'
import { computeBarFillPct } from './src/utils/barFill.js'

let passed = 0
function check(name, fn) {
  fn()
  passed++
  console.log(`[PASS] ${name}`)
}

check('component at its own max fills 100%', () => {
  assert.equal(computeBarFillPct(20, 20), 100)
  assert.equal(computeBarFillPct(15, 15), 100)
  assert.equal(computeBarFillPct(10, 10), 100)
})

check('half of max fills ~50% regardless of the max value', () => {
  assert.equal(computeBarFillPct(10, 20), 50)
  assert.equal(computeBarFillPct(7.5, 15), 50)
  assert.equal(computeBarFillPct(5, 10), 50)
})

check('zero contribution is an empty bar', () => {
  assert.equal(computeBarFillPct(0, 20), 0)
})

check('out-of-range (over max) is clamped to 100, not left >100', () => {
  assert.equal(computeBarFillPct(999, 20), 100)
})

check('negative contribution is clamped to 0, not negative', () => {
  assert.equal(computeBarFillPct(-5, 20), 0)
})

check('a zero/missing max does not divide-by-zero into NaN/Infinity', () => {
  assert.equal(computeBarFillPct(10, 0), 0)
  assert.equal(computeBarFillPct(10, undefined), 0)
})

console.log(`\nAll ${passed} checks passed.`)
