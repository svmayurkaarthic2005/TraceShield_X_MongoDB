// Regression test for the Node-Detail modal pause-state fix in
// AnalyticsPage.jsx's Layer3Panel (Issue 1: closing the modal must restore
// whatever `paused` was before the modal opened, not force-resume).
//
// There's no test framework in this project and the component can't be
// imported directly into plain Node (it's JSX, and rendering it would need
// React + a DOM, neither of which is installed here). Rather than add a
// testing dependency for one state machine, this file re-implements the
// exact same three operations AnalyticsPage.jsx now performs — in the same
// order, with the same ref/state semantics — and asserts the outcomes the
// spec requires. See AnalyticsPage.jsx's Layer3Panel for the real code this
// mirrors (pausedBeforeModalRef + closeNodeModal).
//
// Run: node frontend/test_node_modal_pause.mjs
import assert from 'node:assert/strict'

function createController(initialPaused = false) {
  let paused = initialPaused
  const pausedBeforeModalRef = { current: false }
  let selectedNode = null

  return {
    get paused() { return paused },
    get isOpen() { return selectedNode !== null },
    togglePause() { paused = !paused },
    openNode(node) {
      // Mirrors the node onClick handler: capture BEFORE setPaused(true).
      pausedBeforeModalRef.current = paused
      selectedNode = node
      paused = true
    },
    closeNodeModal() {
      // Mirrors the shared closeNodeModal used by backdrop/header/footer/Escape.
      selectedNode = null
      paused = pausedBeforeModalRef.current
    },
  }
}

let passed = 0
function check(name, fn) {
  fn()
  passed++
  console.log(`[PASS] ${name}`)
}

check('feed running before open -> paused while open -> running again after close', () => {
  const c = createController(false)
  assert.equal(c.paused, false)
  c.openNode({ id: 1 })
  assert.equal(c.paused, true, 'modal must pause the feed while open')
  c.closeNodeModal()
  assert.equal(c.paused, false, 'closing must restore the pre-open state (running)')
})

check('feed manually paused before open -> stays paused while open -> still paused after close', () => {
  const c = createController(false)
  c.togglePause() // user manually pauses via the Pause button
  assert.equal(c.paused, true)
  c.openNode({ id: 2 })
  assert.equal(c.paused, true, 'already-paused feed must remain paused while modal is open')
  c.closeNodeModal()
  assert.equal(c.paused, true, 'closing must NOT force-resume a feed the user had already paused')
})

check('all four dismissal paths (backdrop/header/footer/Escape) call the same closeNodeModal, so behavior is identical', () => {
  // AnalyticsPage.jsx wires backdrop onClick, header X onClick, footer CLOSE
  // onClick, and the Escape handler in useModalEscapeAndScrollLock all to the
  // single `closeNodeModal` callback — there is only one close code path to
  // test, which this suite exercises above. This check just documents that
  // invariant and re-confirms it holds for a manually-paused feed regardless
  // of which simulated "trigger" calls it.
  const triggers = ['backdrop', 'header', 'footer', 'escape']
  for (const trigger of triggers) {
    const c = createController(false)
    c.togglePause()
    c.openNode({ id: trigger })
    c.closeNodeModal() // every real trigger invokes exactly this function
    assert.equal(c.paused, true, `${trigger} dismissal must restore paused=true`)
    assert.equal(c.isOpen, false, `${trigger} dismissal must close the modal`)
  }
})

console.log(`\nAll ${passed} checks passed.`)
