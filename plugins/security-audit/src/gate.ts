/**
 * The validation gate a delegated agent's `structured_output` passes before
 * the run accepts it. It applies the skill's result contracts that the row's
 * JSON Schema cannot express: every assigned unit exactly once, check
 * ownership and promoted artifacts, the disposition rules, candidate and
 * verifier records against `report-schema.json` with the skill's findings
 * validator, and, for a hunter, the ledger the result would produce against
 * the skill's ledger validator. A refused result returns to the agent as a
 * tool error naming each problem, so it corrects the result before it ends.
 * @module delorun-plugin-security-audit/gate
 */
import { applyHunterResult, type HunterUnitResult, type LedgerCheck, type LedgerUnit, validateLedger } from './ledger.ts'
import { findingsValidator, ledgerValidator, skillBlock, SkillReferenceError, REPORT_SCHEMA } from './skill.ts'
import type { BriefKind } from './types.ts'

/** The most problems one refusal lists. */
const MAX_PROBLEMS = 40

/** What the gate knows about the agent whose result it checks. */
export interface GateContext {
  readonly agentId: string
  /** Coverage ids for a hunter, the fingerprint for a verifier. */
  readonly assigned: readonly string[]
  /** Run-relative artifact paths promoted for this agent. */
  readonly promoted: ReadonlySet<string>
  /** The current ledger units a hunter owns, for the simulated update. */
  readonly ownedUnits: readonly LedgerUnit[]
  /** The run's scope paths, if it is scoped. */
  readonly scopePaths: readonly string[]
}

const isObject = (value: unknown): value is Record<string, unknown> => typeof value === 'object' && value !== null && !Array.isArray(value)
const isStringArray = (value: unknown): value is string[] => Array.isArray(value) && value.every(item => typeof item === 'string')

/**
 * Validate records against the report schema and the skill's semantic rules.
 * @param records - the records.
 * @param where - the location prefix for messages.
 * @returns the problems.
 */
export function recordProblems(records: readonly unknown[], where: string): string[] {
  return findingsValidator.validateDocument(records, REPORT_SCHEMA).map(message => `${where}${message.replace(/^\$/u, '')}`)
}

/**
 * Turn a hunter candidate into the record it proposes: `proposed_verdict` becomes `verdict`.
 * @param candidate - the candidate entry.
 * @returns the record.
 */
export function proposedRecord(candidate: Record<string, unknown>): Record<string, unknown> {
  const { proposed_verdict: verdict, ...rest } = candidate
  return { verdict, ...rest }
}

function blockRefProblems(refs: readonly string[], where: string): string[] {
  const problems: string[] = []
  for (const ref of refs) {
    try {
      skillBlock(ref)
    } catch (error: unknown) {
      if (!(error instanceof SkillReferenceError)) throw error
      problems.push(`${where}: ${error.message}`)
    }
  }
  return problems
}

function checkProblems(checks: readonly LedgerCheck[], context: GateContext, where: string): string[] {
  const problems: string[] = []
  for (const [index, check] of checks.entries()) {
    const at = `${where}.checks[${index}]`
    if (check.agent_id !== context.agentId) problems.push(`${at}.agent_id: your checks carry your own agent id ${context.agentId}`)
    if (check.reviewed_paths.length === 0) problems.push(`${at}.reviewed_paths: list the repository-relative paths this check reviewed`)
    for (const path of check.reviewed_paths) if (!ledgerValidator.isSafeRelativePath(path)) problems.push(`${at}.reviewed_paths: ${JSON.stringify(path)} is not a safe repository-relative path`)
    if (check.method === 'source' && check.artifact !== null) problems.push(`${at}.artifact: a source check has artifact null`)
    if (check.method === 'local') {
      if (check.artifact === null || !context.promoted.has(check.artifact)) {
        problems.push(`${at}.artifact: a local check names one file the run promoted for you (promoted: ${[...context.promoted].join(', ') || 'none'})`)
      }
    }
  }
  return problems
}

function hunterProblems(value: Record<string, unknown>, context: GateContext): string[] {
  const problems: string[] = []
  const units = value.units as HunterUnitResult[]
  const candidates = value.candidates as Record<string, unknown>[]
  const seen = new Map<string, number>()
  for (const unit of units) seen.set(unit.coverage_id, (seen.get(unit.coverage_id) ?? 0) + 1)
  for (const id of context.assigned) if (seen.get(id) !== 1) problems.push(`units: assigned unit ${id} must appear exactly once (found ${seen.get(id) ?? 0})`)
  for (const id of seen.keys()) if (!context.assigned.includes(id)) problems.push(`units: ${id} is not assigned to you; report a different boundary under uncovered`)
  const fingerprints = new Map<string, number>()
  for (const [index, candidate] of candidates.entries()) {
    const where = `candidates[${index}]`
    if (!isObject(candidate)) {
      problems.push(`${where}: expected an object`)
      continue
    }
    const verdict = candidate.proposed_verdict
    if (verdict !== 'confirmed' && verdict !== 'needs_validation') problems.push(`${where}.proposed_verdict: use confirmed or needs_validation`)
    if (Object.hasOwn(candidate, 'verdict')) problems.push(`${where}.verdict: a candidate uses proposed_verdict instead`)
    const fingerprint = typeof candidate.fingerprint === 'string' ? candidate.fingerprint : undefined
    if (fingerprint !== undefined) fingerprints.set(fingerprint, (fingerprints.get(fingerprint) ?? 0) + 1)
    problems.push(...recordProblems([proposedRecord(candidate)], where))
  }
  for (const [fingerprint, count] of fingerprints) if (count > 1) problems.push(`candidates: fingerprint ${fingerprint} appears ${count} times; one root cause is one candidate`)
  const linked = new Set<string>()
  for (const [index, unit] of units.entries()) {
    const where = `units[${index}]`
    problems.push(...checkProblems(unit.checks, context, where))
    for (const path of unit.reviewed_paths) if (!ledgerValidator.isSafeRelativePath(path)) problems.push(`${where}.reviewed_paths: ${JSON.stringify(path)} is not a safe repository-relative path`)
    const union = new Set(unit.checks.flatMap(check => check.reviewed_paths))
    const listed = new Set(unit.reviewed_paths)
    if (union.size !== listed.size || [...union].some(path => !listed.has(path))) problems.push(`${where}.reviewed_paths: must equal the union of its checks' reviewed_paths`)
    for (const fingerprint of unit.candidate_fingerprints) {
      linked.add(fingerprint)
      if (!fingerprints.has(fingerprint)) problems.push(`${where}.candidate_fingerprints: ${fingerprint} has no entry in candidates`)
    }
    if (unit.disposition === 'candidate' && unit.candidate_fingerprints.length === 0) problems.push(`${where}: a candidate unit links at least one fingerprint`)
    if (unit.disposition !== 'candidate' && unit.candidate_fingerprints.length > 0) problems.push(`${where}: only a candidate unit links fingerprints`)
    if (unit.disposition === 'covered' && unit.unresolved.length > 0) problems.push(`${where}: a covered unit has no unresolved fact; use blocked`)
    if (unit.disposition === 'blocked' && unit.unresolved.length === 0) problems.push(`${where}: a blocked unit lists its unresolved facts`)
    if (unit.checks.length === 0) problems.push(`${where}.checks: every unit records the checks that support its disposition`)
  }
  for (const fingerprint of fingerprints.keys()) if (!linked.has(fingerprint)) problems.push(`candidates: ${fingerprint} is linked from no unit's candidate_fingerprints`)
  const confirmedFingerprints = new Set(candidates.filter(candidate => candidate.proposed_verdict === 'confirmed').map(candidate => String(candidate.fingerprint)))
  for (const unit of units) {
    if (!unit.candidate_fingerprints.some(fingerprint => confirmedFingerprints.has(fingerprint))) continue
    if (!unit.checks.some(check => check.method === 'local' && check.artifact !== null)) {
      problems.push(`units: ${unit.coverage_id} links a confirmed candidate but has no local check with a promoted artifact; a confirmed record needs bounded local evidence`)
    }
  }
  if (problems.length === 0 && context.ownedUnits.length > 0) {
    try {
      const simulated = applyHunterResult(context.ownedUnits, context.agentId, units, value.hardening as string[])
      problems.push(...validateLedger(simulated.filter(unit => context.assigned.includes(unit.coverage_id))).map(message => `ledger update: ${message}`))
    } catch (error: unknown) {
      problems.push(`ledger update: ${(error as Error).message}`)
    }
  }
  for (const [index, entry] of (value.uncovered as { starting_paths: string[] }[]).entries()) {
    for (const path of entry.starting_paths) if (!ledgerValidator.isSafeRelativePath(path)) problems.push(`uncovered[${index}].starting_paths: ${JSON.stringify(path)} is not a safe repository-relative path`)
  }
  return problems
}

/** A verifier may return another fingerprint for a genuinely different root cause; the coordinator validates that one separately. */
function verifierProblems(value: Record<string, unknown>, context: GateContext): string[] {
  const problems: string[] = []
  const record = value.record
  if (!isObject(record)) return ['record: expected the full record object']
  if (record.verdict !== value.decision) problems.push(`record.verdict: must equal decision ${String(value.decision)}`)
  if (record.fingerprint !== context.assigned[0]) {
    problems.push(`record.fingerprint: you verify ${String(context.assigned[0])}; preserve that fingerprint for the same root cause (report a different root cause as a new candidate)`)
  }
  problems.push(...recordProblems([record], 'record'))
  if (!Array.isArray(value.checks)) return [...problems, 'checks: expected the verifier-owned checks array']
  const checks = value.checks as LedgerCheck[]
  problems.push(...checkProblems(checks, context, 'checks'))
  for (const [index, check] of checks.entries()) {
    for (const path of check.reviewed_paths) if (!ledgerValidator.isSafeRelativePath(path)) problems.push(`checks[${index}].reviewed_paths: ${JSON.stringify(path)} is not a safe repository-relative path`)
  }
  if (value.decision === 'confirmed' && !checks.some(check => check.method === 'local' && check.artifact !== null)) {
    problems.push('checks: a confirmed verification needs a local check with a promoted artifact; a source-only confirmation is needs_validation, not confirmed')
  }
  return problems
}

function finalVerifierProblems(value: Record<string, unknown>, context: GateContext): string[] {
  const problems: string[] = []
  const assigned = context.assigned[0]
  if (value.fingerprint !== assigned) problems.push(`fingerprint: you verify ${String(assigned)}; return that fingerprint`)
  if (value.decision === 'verified') {
    if (Object.hasOwn(value, 'record') || Object.hasOwn(value, 'reason')) problems.push('verified: return only decision and fingerprint')
  } else {
    if (typeof value.reason !== 'string' || value.reason.trim().length === 0) problems.push('reason: a replacement states why')
    if (!isObject(value.record)) problems.push('record: a replacement carries the full record')
    else problems.push(...recordProblems([value.record], 'record'))
  }
  return problems
}

function scopeProblems(paths: readonly string[], context: GateContext, where: string): string[] {
  if (context.scopePaths.length === 0) return []
  return paths
    .filter(path => !context.scopePaths.some(scope => path === scope || path.startsWith(`${scope.replace(/\/$/u, '')}/`)))
    .map(path => `${where}: ${JSON.stringify(path)} is outside this run's scope (${context.scopePaths.join(', ')})`)
}

function criticProblems(value: Record<string, unknown>, context: GateContext): string[] {
  const problems: string[] = []
  const missing = value.missing_units as { starting_paths: string[]; selected_companion_blocks: string[]; excluded_blocks: { block: string }[] }[]
  const reassign = value.reassign_ids as string[]
  if (value.stop === true && (missing.length > 0 || reassign.length > 0)) problems.push('stop: true only when you accept no missing_units and no reassign_ids')
  for (const [index, unit] of missing.entries()) {
    const where = `missing_units[${index}]`
    for (const path of unit.starting_paths) if (!ledgerValidator.isSafeRelativePath(path)) problems.push(`${where}.starting_paths: ${JSON.stringify(path)} is not a safe repository-relative path`)
    problems.push(...scopeProblems(unit.starting_paths, context, `${where}.starting_paths`))
    problems.push(...blockRefProblems([...unit.selected_companion_blocks, ...unit.excluded_blocks.map(entry => entry.block)], where))
  }
  return problems
}

function reconProblems(value: Record<string, unknown>): string[] {
  const problems: string[] = []
  for (const [index, fact] of (value.facts as { refs: unknown }[]).entries()) {
    if (!isStringArray(fact.refs) || fact.refs.length === 0) problems.push(`facts[${index}].refs: every fact cites at least one repository-relative file:line reference`)
  }
  return problems
}

/**
 * The problems that keep a result from being accepted.
 * @param kind - the brief's kind.
 * @param value - the `structured_output` arguments, already valid against the row's schema.
 * @param context - the agent's assignment.
 * @returns at most {@link MAX_PROBLEMS} problems, empty when the result is accepted.
 */
export function resultProblems(kind: BriefKind, value: unknown, context: GateContext): string[] {
  if (!isObject(value)) return ['the result must be a JSON object']
  let problems: string[]
  switch (kind) {
    case 'recon': problems = reconProblems(value); break
    case 'hunt': problems = hunterProblems(value, context); break
    case 'verify': problems = verifierProblems(value, context); break
    case 'final-verify': problems = finalVerifierProblems(value, context); break
    case 'critique':
    case 'final-critique': problems = criticProblems(value, context); break
  }
  return problems.slice(0, MAX_PROBLEMS)
}
