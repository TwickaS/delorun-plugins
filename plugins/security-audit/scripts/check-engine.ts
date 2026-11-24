/**
 * A keyless check of the audit engine, run with `node scripts/check-engine.ts`:
 * the skill pack and both of its validators, the coverage-ledger operations,
 * the result gate's contracts, the findings rules and the report's fingerprint
 * checks. It starts no agent and needs no model, so a change to any of these
 * files can be checked in one command.
 */
import assert from 'node:assert/strict'
import { findingsValidator } from '../src/skill.ts'
import {
  applyHunterResult,
  assignUnits,
  closeUnits,
  LedgerError,
  patchUnit,
  reassignUnits,
  seedUnits,
  statusCounts,
  validateLedger,
  type HunterUnitResult,
  type UnitSeed,
} from '../src/ledger.ts'
import { resultProblems, type GateContext } from '../src/gate.ts'
import { expectedFingerprints, findingsProblems, reportProblems } from '../src/report.ts'
import { rcSeedUnits } from '../src/rc-profile.ts'
import { isSafePath } from '../src/tools/intake.ts'
import { blockNames, fencedBlockAfter, REPORT_SCHEMA, schemaBranch, skillBlock, skillFile, skillFileNames } from '../src/skill.ts'

/** A seed for `src/router.ts` under one attack class. */
function seed(surface: string): UnitSeed {
  return {
    canonical_refs: { surface, boundary: 'src/authz.ts#requireOwner', subsystem: 'packages/api', attack_class: 'ATTACK-CLASSES.md#Access control' },
    surface,
    boundary: 'requireOwner',
    subsystem: 'packages/api',
    attack_class: 'Access control',
    starting_paths: ['src/router.ts', 'src/authz.ts'],
    ordinary_attack_class_block: 'ATTACK-CLASSES.md#Access control',
    selected_companion_blocks: [],
    excluded_blocks: [],
  }
}

/** A needs_validation record the skill's validator accepts. */
const RECORD = {
  verdict: 'needs_validation',
  fingerprint: 'router-owner-check',
  title: 'Owner check trusts a header',
  description: 'The owner check reads a caller-supplied header.',
  claimed_root_cause: 'requireOwner compares a header with the owner column.',
  trace: [{ kind: 'entrypoint', file: 'src/router.ts', line: 12, scope: 'GET /items/:id', description: 'route entry' }],
  evidence: [{ file: 'src/authz.ts', line: 7, description: 'header read' }],
  blockers: ['the proxy that sets the header is not in source'],
  validation_plan: { deployment: 'Observe whether the proxy strips a client header.' },
}

// The pack: every file is vendored, and a block is its exact text.
assert.equal(skillFileNames().length, 23)
assert.ok(skillFile('SKILL.md').startsWith('---'))
assert.ok(skillBlock('ATTACK-CLASSES.md#Access control').startsWith('**Access control**'))
assert.ok(blockNames('ATTACK-CLASSES.md').includes('Access control'))
assert.ok(fencedBlockAfter('VALIDATION-AND-REPORTING.md', 'Copy this promotion procedure').startsWith('Artifact promotion procedure'))
assert.equal(JSON.parse(schemaBranch('confirmed')).properties.verdict.const, 'confirmed')

// The ledger: canonical ids, one state machine, an append-only archive.
const first = seedUnits([], [seed('src/router.ts#GET /items/:id'), seed('src/router.ts#POST /items')])
assert.equal(first.added.length, 2)
assert.deepEqual(validateLedger(first.ledger), [])
assert.throws(() => seedUnits(first.ledger, [seed('src/router.ts#GET /items/:id')]), LedgerError)
const [a, b] = first.added as [string, string]
let ledger = assignUnits(first.ledger, [a, b], 'hunter-1')
assert.ok(ledger.every(unit => unit.status === 'in_progress'))
const results: HunterUnitResult[] = [
  { coverage_id: a, disposition: 'covered', reviewed_paths: ['src/router.ts'], checks: [{ agent_id: 'hunter-1', reviewed_paths: ['src/router.ts'], invariant: 'the owner is checked', method: 'source', result: 'the owner is checked', artifact: null }], candidate_fingerprints: [], unresolved: [] },
  { coverage_id: b, disposition: 'blocked', reviewed_paths: ['src/router.ts'], checks: [{ agent_id: 'hunter-1', reviewed_paths: ['src/router.ts'], invariant: 'the body is parsed', method: 'source', result: 'no parser found', artifact: null }], candidate_fingerprints: [], unresolved: ['the parser is generated'] },
]
ledger = applyHunterResult(ledger, 'hunter-1', results, ['Prefer a shared owner helper.'])
assert.equal(statusCounts(ledger).covered, 1)
assert.deepEqual(ledger.find(unit => unit.coverage_id === a)?.harness_hardening, ['Prefer a shared owner helper.'])
ledger = reassignUnits(ledger, [a], 'the critic found a second route into the same check', 'planned')
const reopened = ledger.find(unit => unit.coverage_id === a)
assert.equal(reopened?.wave, 2)
assert.equal(reopened?.status, 'planned')
assert.equal(reopened?.attempts.length, 1)
assert.deepEqual(validateLedger(ledger), [])
assert.throws(() => patchUnit(ledger, a, { coverage_id: 'x' }), LedgerError)
assert.throws(() => closeUnits(ledger, [b], 'deferred', 'budget'), LedgerError)
const third = seedUnits(ledger, [seed('src/router.ts#DELETE /items')])
ledger = closeUnits(third.ledger, third.added, 'out_of_scope', 'the route is out of this run scope')
assert.deepEqual(ledger.find(unit => unit.coverage_id === third.added[0])?.unresolved, ['the route is out of this run scope'])

// The gate: a hunter result must account for its units, and a confirmed
// verification needs a promoted artifact.
const context: GateContext = { agentId: 'hunter-1', assigned: [a], promoted: new Set(['out.txt']), ownedUnits: [], scopePaths: [] }
const hunterValue = {
  units: [{ coverage_id: a, disposition: 'covered', reviewed_paths: ['src/router.ts'], checks: [{ agent_id: 'hunter-1', reviewed_paths: ['src/router.ts'], invariant: 'the owner is checked', method: 'source', result: 'the owner is checked', artifact: null }], candidate_fingerprints: [], unresolved: [] }],
  candidates: [],
  uncovered: [],
  hardening: [],
}
assert.deepEqual(resultProblems('hunt', hunterValue, context), [])
assert.deepEqual(resultProblems('hunt', { ...hunterValue, units: [] }, context).length, 1)
assert.ok(resultProblems('verify', { decision: 'confirmed', record: { ...RECORD, verdict: 'confirmed' }, checks: [] }, context).length > 0)

// The findings document and the report's fingerprint footer.
assert.deepEqual(findingsProblems([RECORD]), [])
assert.ok(findingsProblems([{ ...RECORD, severity: 'high' }]).length > 0)
assert.deepEqual(expectedFingerprints('NEEDS_VALIDATION', [RECORD]), [RECORD.fingerprint])
assert.deepEqual(reportProblems('NEEDS_VALIDATION', 'text', [RECORD]).length, 1)
assert.deepEqual(reportProblems('NEEDS_VALIDATION', 'text\n<!-- audit-fingerprints: router-owner-check -->', [RECORD]), [])

// The release-candidate seed: one valid, planned unit for each boundary of Delorun's
// threat model, in the page's order, with the package that implements the defence.
const rcSeeds = rcSeedUnits()
assert.deepEqual(rcSeeds.map(row => row.canonical_refs.boundary), [
  'Confinement of native commands',
  "The home's control channels",
  'Container isolation',
  'Admission and listeners',
  'Device approval',
  'Reach providers',
  'Sign-in',
  'Releases, the log and the rebuild',
  'The catalogue and revocation',
  'Updates and rollback',
  'Archives and untrusted chats',
  'Logs and redaction',
  'Verification',
  'Parity',
  'The web_fetch guard',
  'Data sharing',
])
const rcSeeded = seedUnits([], rcSeeds)
assert.equal(rcSeeded.added.length, 16)
assert.deepEqual(validateLedger(rcSeeded.ledger), [])
assert.ok(rcSeeded.ledger.every(unit => unit.status === 'planned' && unit.starting_paths.length > 0 && unit.ordinary_attack_class_block !== null))
assert.equal(new Set(rcSeeds.map(row => row.starting_paths[0])).size > 8, true)

// The skill's path rule, which intake and the gate share.
assert.equal(isSafePath('src/router.ts'), true)
assert.equal(isSafePath('../router.ts'), false)
assert.equal(isSafePath('/etc/passwd'), false)

console.log('check-engine: ' + String(rcSeeded.added.length) + ' rc boundaries, ' + String(REPORT_SCHEMA === null ? 0 : 1) + ' schema, ' + String(skillFileNames().length) + ' pack files, ' + String(findingsValidator.validateDocument([RECORD], REPORT_SCHEMA).length) + ' findings problems, all checks passed')
