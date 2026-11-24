/**
 * A screenshot harness: renders the security-audit pane over fixture run data, in
 * either mode, so the pictures do not need a live run. \`?mode=report\` draws Report
 * mode; anything else draws Live. It is build input for the shots only, never
 * shipped, so neither tsconfig includes it.
 */
import { createElement } from 'react'
import { createRoot } from 'react-dom/client'
import { en, type SecurityAuditKey } from '../../src/client/locales.ts'
import { parseCandidates, parseControl, parseCoverage, parseFindings, parseMetadata } from '../../src/client/runs.ts'
import type { AuditDigest } from '../../src/client/controller.ts'
import { SecurityAuditPane, type SecurityAuditPaneProps } from '../../src/client/pane.tsx'
import { injectStyles } from '../../src/client/styles.ts'

/** The translate seat, over the English dictionary. */
function translate(key: SecurityAuditKey, params?: Readonly<Record<string, string | number>>): string {
  const text = en[key]
  if (params === undefined) return text
  return text.replace(/\{(\w+)\}/gu, (whole, name: string) => {
    const value = params[name]
    return value === undefined ? whole : String(value)
  })
}

const t = translate as SecurityAuditPaneProps['t']

/** One settled run, stopped incomplete part way through hunting. */
const RUN = '.security-audit/run-3'

const metadata = parseMetadata(JSON.stringify({
  run_id: 'run-3',
  repo: 'delorun',
  target: '/home/vadim/delorun/code',
  profile: 'deep',
  seed: 'rc',
  scope_paths: ['packages/sandbox', 'packages/core/agent'],
  budget: 40,
  run_status: 'incomplete',
  incomplete_reason: 'the budget ran out in wave 3 with 6 units still open',
  stage: 'validation',
  created_at: '2026-11-24T08:00:00Z',
  updated_at: '2026-11-24T09:12:00Z',
  agents: { total: 11, invocations: 31, budget: 40 },
  source_ref: { commit: '4c9a1e7', dirty: false },
  candidates: { total: 9, proposed: 2, confirmed: 3, needs_validation: 2, rejected: 2, final_verified: 3 },
}))

const coverage = parseCoverage(JSON.stringify([
  { coverage_id: 'sandbox%2Flandlock%2Ffs-write%2Fpath-escape', surface: 'packages/sandbox/sandbox-local/src', boundary: 'Confinement of native commands', attack_class: 'Access control', status: 'covered', agent_id: 'hunter-3', wave: 1 },
  { coverage_id: 'sandbox%2Fbwrap%2Fnet%2Funshare', surface: 'packages/sandbox/sandbox-local/src/bwrap.ts', boundary: 'Confinement of native commands', attack_class: 'Resource exhaustion', status: 'covered', agent_id: 'hunter-4', wave: 1 },
  { coverage_id: 'sandbox%2Fbwrap%2Fdisk%2Ffloor', surface: 'packages/sandbox/sandbox-local/src/limits.ts', boundary: 'Confinement of native commands', attack_class: 'Resource exhaustion', status: 'blocked', agent_id: 'hunter-4', wave: 2 },
  { coverage_id: 'agent%2Fsubagent%2Fdepth', surface: 'packages/core/agent/src/subagent.ts', boundary: "The home's control channels", attack_class: 'Access control', status: 'candidate', agent_id: 'hunter-5', wave: 2 },
  { coverage_id: 'agent%2Fapproval%2Fforged', surface: 'packages/core/agent/src/approval.ts', boundary: "The home's control channels", attack_class: 'Access control', status: 'covered', agent_id: 'hunter-5', wave: 2 },
  { coverage_id: 'agent%2Fqueue%2Freplay', surface: 'packages/core/agent/src/queue.ts', boundary: "The home's control channels", attack_class: 'Injection', status: 'in_progress', agent_id: 'hunter-6', wave: 3 },
  { coverage_id: 'agent%2Fgoal%2Fceiling', surface: 'packages/core/agent/src/goal.ts', boundary: 'Admission and listeners', attack_class: 'Resource exhaustion', status: 'deferred', agent_id: null, wave: 3 },
  { coverage_id: 'agent%2Ftool%2Fexec', surface: 'packages/core/agent/src/tool-exec.ts', boundary: 'Admission and listeners', attack_class: 'Access control', status: 'planned' },
]))

const findings = parseFindings(JSON.stringify([
  {
    verdict: 'confirmed',
    fingerprint: 'sandbox-landlock-path-escape',
    title: 'A workspace write reaches outside the policy root through a relative parent segment',
    description: 'The Landlock ruleset is derived from the policy root but the write target is normalised after the ruleset is installed, so a parent segment in the tool argument escapes the allowed tree. The escape needs no privileges of its own.',
    boundary: 'Confinement of native commands',
    trace: [
      { kind: 'entrypoint', file: 'packages/core/tool-executor-native/src/write.ts', line: 88, scope: 'resolveTarget', description: 'the tool argument is taken as written' },
      { kind: 'sink', file: 'packages/sandbox/sandbox-local/src/landlock.ts', line: 143, scope: 'installRuleset', description: 'the ruleset is installed from the policy root' },
    ],
    evidence: [{ file: 'packages/sandbox/sandbox-local/src/landlock.ts', line: 149, description: 'the relative join keeps parent segments' }],
    severity: { likelihood: { score: 'high', reason: 'any model-written path can carry one' }, impact: { score: 'high', reason: 'the write lands in the person’s home' }, overall_severity: { score: 'high', reason: 'both factors score high' } },
    confidence: { score: 'high', reason: 'reproduced in the role’s own copy' },
    root_cause: 'normalisation happens after the ruleset is installed',
    intended_behavior: 'the resolved path is joined and normalised before the ruleset is installed',
    conditions: [{ kind: 'authentication_level', description: 'a chat with workspace write' }],
    execution: { attacker_perspective: 'write through the file tool', payloads: ['../../escape.txt'], instructions: ['call the write tool with the payload'], observed_result: 'the file lands in the parent of the policy root' },
    remediation: { strategy: 'normalise the target before installing the ruleset' },
    denial_test: { file: 'packages/sandbox/sandbox-local/tests/landlock.spec.ts', assertion: 'expect(landlock.allows(escapeTarget)).toBe(false)', proven: true },
  },
  {
    verdict: 'confirmed',
    fingerprint: 'subagent-depth-unbounded',
    title: 'Subagent depth is read once, so a nested spawn can deepen past the ceiling',
    description: 'The configured depth ceiling is read when the child starts and never re-checked, so a role that spawns its own child can pass the ceiling by one level.',
    boundary: "The home's control channels",
    trace: [{ kind: 'sink', file: 'packages/core/agent/src/subagent.ts', line: 210, scope: 'spawn', description: 'the ceiling is not compared' }],
    evidence: [],
    severity: { likelihood: { score: 'medium', reason: 'needs a spawning role' }, impact: { score: 'medium', reason: 'one extra level of nesting' }, overall_severity: { score: 'medium', reason: 'bounded either way' } },
    confidence: { score: 'medium', reason: 'source-only reading' },
    root_cause: 'a missing comparison',
    intended_behavior: 'the ceiling refuses the spawn',
    conditions: [],
    execution: { attacker_perspective: 'a hunting role', payloads: [], instructions: ['spawn a child from a child'], observed_result: 'depth reaches ceiling plus one' },
    remediation: { strategy: 'compare before spawning' },
    denial_test: { file: 'packages/core/agent/tests/depth.spec.ts', assertion: 'expect(spawn).toThrow()', proven: false },
  },
  {
    verdict: 'needs_validation',
    fingerprint: 'queue-replay-check',
    title: 'A queued message may be replayed after a restart',
    description: 'The queue file is rewritten without a sequence guard, and the restart path reads it unconditionally.',
    trace: [{ kind: 'entrypoint', file: 'packages/core/agent/src/queue.ts', line: 64, scope: 'restore', description: 'the queue is read at start' }],
    evidence: [],
    blockers: ['a restart cannot be made inside the role’s confinement'],
    validation_plan: { local: 'stop the harness with two messages queued and start it again; both must appear once' },
  },
  {
    verdict: 'needs_validation',
    fingerprint: 'goal-ceiling-check',
    title: 'A goal’s step ceiling may not count nested tool rounds',
    description: 'The ceiling counts turns, and a tool round is a turn only sometimes.',
    trace: [],
    evidence: [],
    blockers: ['the counter is not observable from an audit run'],
    validation_plan: { local: 'run a goal with a ceiling of two and a three-round tool chain' },
  },
]))

const control = parseControl(JSON.stringify({ command: 'pause', reason: 'two roles still running', at: '2026-11-24T09:11:00Z' }))

const digests: readonly AuditDigest[] = [
  { stage: 'hunting', status: 'in_progress', covered: 3, total: 8, spend: 14, budget: 40, kind: 'stage', at: Date.parse('2026-11-24T08:41:00Z') },
  { stage: 'hunting', status: 'in_progress', covered: 5, total: 8, spend: 23, budget: 40, kind: 'units', at: Date.parse('2026-11-24T08:58:00Z') },
  { stage: 'validation', status: 'incomplete', covered: 6, total: 8, spend: 31, budget: 40, kind: 'stage', at: Date.parse('2026-11-24T09:11:00Z') },
]

const snapshot = {
  phase: 'ready' as const,
  digests,
  control,
  report: {
    report: '# delorun security audit\n\nRun-3, deep profile, source 4c9a1e7.\n',
    detail: '## sandbox-landlock-path-escape\n\nHigh. The ruleset is installed before the target is normalised.\n',
    needsValidation: '## queue-replay-check\n\nBlocker: a restart cannot be made inside the role’s confinement.\n',
  },
  runs: [{ directory: RUN, label: 'run-3', recordedAt: Date.parse('2026-11-24T09:12:00Z') }, { directory: '.security-audit/run-2', label: 'run-2', recordedAt: 1 }],
  selected: RUN,
  metadata,
  coverage,
  candidates: parseCandidates(JSON.stringify([])),
  findings,
  elapsedMs: 72 * 60_000,
  problems: [],
  busy: false,
}

const mode = new URLSearchParams(location.search).get('mode') === 'report' ? 'report' : 'live'

/**
 * Press the Report tab once React has drawn it.
 * @param label - the segment to press.
 */
function press(label: string): void {
  const find = (): void => {
    const button = [...document.querySelectorAll('button')].find(candidate => candidate.textContent === label)
    if (button === undefined) { setTimeout(find, 20); return }
    button.click()
  }
  find()
}

const props = {
  useTabInfo: () => ({ tab: { actions: { bindCommands: () => {}, openResource: () => {} } } }),
  sessionId: 'sess-fixture',
  useSessions: (select: (state: { byId: Record<string, { cwd: string }> }) => unknown) => select({ byId: { 'sess-fixture': { cwd: '/home/vadim/delorun/code' } } }),
  useAudit: (select: (state: typeof snapshot) => unknown) => select(snapshot),
  attach: () => () => {},
  select: () => {},
  reload: () => {},
  control: () => Promise.resolve({ ok: true, message: 'Recorded a pause.' }),
  exportReport: () => Promise.resolve({ ok: true, message: 'Wrote REPORT.md.' }),
  inputActions: { insertQuote: () => true },
  t,
} as unknown as SecurityAuditPaneProps

injectStyles()
const root = document.getElementById('pane')
if (root === null) throw new Error('the page has no #pane')
createRoot(root).render(createElement(SecurityAuditPane, props))
if (mode === 'report') press('Report')
