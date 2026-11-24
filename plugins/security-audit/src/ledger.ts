/**
 * Deterministic coverage-ledger operations (RECONNAISSANCE.md, Deterministic
 * coverage ledger; HUNTING.md, Parent consolidation and Coverage-critic
 * waves). Each operation returns a new ledger and never mutates its input; the
 * caller writes the result only when the skill's own validator accepts it, so
 * an operation either applies completely or not at all.
 *
 * The ledger's vocabulary lives in `types.ts`; this module re-exports it so a
 * caller of a ledger operation imports one module.
 * @module delorun-plugin-security-audit/ledger
 */
import { ledgerValidator, skillBlock, SkillReferenceError } from './skill.ts'
import type { HunterUnitResult, LedgerCheck, LedgerUnit, StatusCounts, UnitSeed, UnitStatus } from './types.ts'

export type { CanonicalRefs, ExcludedBlock, HunterUnitResult, LedgerCheck, LedgerUnit, PriorStatus, StatusCounts, UnitSeed, UnitStatus } from './types.ts'

/** Raised for an operation the ledger's current state does not allow. */
export class LedgerError extends Error {
  /** The problems the operation found, one per line. */
  readonly problems: readonly string[]

  /**
   * @param problems - the problems the operation found.
   */
  constructor(problems: readonly string[]) {
    super(problems.join('\n'))
    this.name = 'LedgerError'
    this.problems = problems
  }
}

/**
 * Validate a ledger with the skill's own validator.
 * @param ledger - the units.
 * @returns the validator's messages, empty when valid.
 */
export function validateLedger(ledger: readonly LedgerUnit[]): string[] {
  return ledgerValidator.validateDocument(ledger)
}

/**
 * Parse a ledger file's value.
 * @param value - the parsed JSON, or `undefined` for a run without a ledger yet.
 * @returns the units.
 * @throws {LedgerError} when the value is not an array.
 */
export function parseLedger(value: unknown): LedgerUnit[] {
  if (value === undefined) return []
  if (!Array.isArray(value)) throw new LedgerError(['coverage-ledger.json must hold a top-level array'])
  return value as LedgerUnit[]
}

function sorted(ledger: LedgerUnit[]): LedgerUnit[] {
  return ledger.sort((left, right) => (left.coverage_id < right.coverage_id ? -1 : left.coverage_id > right.coverage_id ? 1 : 0))
}

function blockProblems(ref: string, where: string): string[] {
  try {
    skillBlock(ref)
    return []
  } catch (error: unknown) {
    if (error instanceof SkillReferenceError) return [`${where}: ${error.message}`]
    throw error
  }
}

/**
 * Add planned units, deriving each coverage id from its canonical references.
 * @param ledger - the current units.
 * @param seeds - the units to add.
 * @returns the new ledger, sorted, and the added ids.
 * @throws {LedgerError} for a block reference the pack lacks, a non-canonical reference, or an id already present.
 */
export function seedUnits(ledger: readonly LedgerUnit[], seeds: readonly UnitSeed[]): { readonly ledger: LedgerUnit[]; readonly added: string[] } {
  const problems: string[] = []
  const ids = new Set(ledger.map(unit => unit.coverage_id))
  const units: LedgerUnit[] = []
  for (const [index, seed] of seeds.entries()) {
    const where = `units[${index}]`
    let id: string
    try {
      id = ledgerValidator.canonicalCoverageId(seed.canonical_refs)
    } catch (error: unknown) {
      problems.push(`${where}.canonical_refs: ${(error as Error).message}`)
      continue
    }
    if (ids.has(id)) {
      problems.push(`${where}: coverage id ${id} is already in the ledger or this request`)
      continue
    }
    ids.add(id)
    for (const ref of [...seed.ordinary_attack_class_block === null ? [] : [seed.ordinary_attack_class_block], ...seed.selected_companion_blocks, ...seed.excluded_blocks.map(entry => entry.block)]) {
      problems.push(...blockProblems(ref, where))
    }
    units.push({
      coverage_id: id,
      canonical_refs: seed.canonical_refs,
      surface: seed.surface,
      boundary: seed.boundary,
      subsystem: seed.subsystem,
      attack_class: seed.attack_class,
      ...seed.lifecycle === undefined ? {} : { lifecycle: seed.lifecycle },
      starting_paths: seed.starting_paths,
      ordinary_attack_class_block: seed.ordinary_attack_class_block,
      selected_companion_blocks: seed.selected_companion_blocks,
      excluded_blocks: seed.excluded_blocks,
      prior_status: seed.prior_status ?? 'none',
      attempts: [],
      wave: 1,
      status: 'planned',
      agent_id: null,
      reviewed_paths: [],
      local_checks: [],
      result_fingerprints: [],
      unresolved: [],
    })
  }
  if (problems.length > 0) throw new LedgerError(problems)
  return { ledger: sorted([...ledger, ...units]), added: units.map(unit => unit.coverage_id) }
}

function indexOf(ledger: readonly LedgerUnit[], id: string): number {
  const index = ledger.findIndex(unit => unit.coverage_id === id)
  if (index < 0) throw new LedgerError([`coverage id ${id} is not in the ledger`])
  return index
}

/**
 * Assign planned units to a new owner, moving them to `in_progress`.
 * @param ledger - the current units.
 * @param ids - the coverage ids.
 * @param agentId - the owner.
 * @returns the new ledger.
 * @throws {LedgerError} when a unit is missing or not planned.
 */
export function assignUnits(ledger: readonly LedgerUnit[], ids: readonly string[], agentId: string): LedgerUnit[] {
  const next = [...ledger]
  const problems: string[] = []
  for (const id of ids) {
    const index = indexOf(next, id)
    const unit = next[index] as LedgerUnit
    if (unit.status !== 'planned') problems.push(`${id} is ${unit.status}, not planned; only planned units can be assigned`)
    else next[index] = { ...unit, status: 'in_progress', agent_id: agentId }
  }
  if (problems.length > 0) throw new LedgerError(problems)
  return next
}

/**
 * Apply a hunter's per-unit results to the units it owns.
 * @param ledger - the current units.
 * @param agentId - the hunter.
 * @param units - the result's `units`.
 * @param hardening - the result's `hardening` notes, kept as bookkeeping on each unit.
 * @returns the new ledger.
 * @throws {LedgerError} when a result names a unit the hunter does not own in progress.
 */
export function applyHunterResult(ledger: readonly LedgerUnit[], agentId: string, units: readonly HunterUnitResult[], hardening: readonly string[]): LedgerUnit[] {
  const next = [...ledger]
  const problems: string[] = []
  for (const result of units) {
    const index = next.findIndex(unit => unit.coverage_id === result.coverage_id)
    const unit = next[index]
    if (unit === undefined) {
      problems.push(`${result.coverage_id} is not in the ledger`)
      continue
    }
    if (unit.status !== 'in_progress' || unit.agent_id !== agentId) {
      problems.push(`${result.coverage_id} is ${unit.status} owned by ${unit.agent_id ?? 'nobody'}, not in progress for ${agentId}`)
      continue
    }
    next[index] = {
      ...unit,
      status: result.disposition,
      reviewed_paths: [...result.reviewed_paths],
      local_checks: [...result.checks],
      result_fingerprints: result.disposition === 'candidate' ? [...result.candidate_fingerprints] : [],
      unresolved: [...result.unresolved],
      ...hardening.length > 0 ? { harness_hardening: [...hardening] } : {},
    }
  }
  if (problems.length > 0) throw new LedgerError(problems)
  return next
}

/**
 * Reopen evidence-bearing units a coverage critic named: archive the live
 * terminal state in `attempts`, increment `wave`, and start empty live
 * evidence, `planned` for another assignment or `deferred` with the reason
 * when no assignment follows (the quick profile, or an exhausted budget).
 * @param ledger - the current units.
 * @param ids - the coverage ids.
 * @param reason - the critic's source-backed reassignment reason.
 * @param next - the live state after archiving.
 * @returns the new ledger.
 * @throws {LedgerError} when a unit is missing or has no terminal evidence to archive.
 */
export function reassignUnits(ledger: readonly LedgerUnit[], ids: readonly string[], reason: string, next: 'planned' | 'deferred'): LedgerUnit[] {
  const result = [...ledger]
  const problems: string[] = []
  for (const id of ids) {
    const index = indexOf(result, id)
    const unit = result[index] as LedgerUnit
    if (unit.status !== 'covered' && unit.status !== 'candidate' && unit.status !== 'blocked') {
      problems.push(`${id} is ${unit.status}; only covered, candidate and blocked units can be reassigned`)
      continue
    }
    const attempt = {
      wave: unit.wave,
      status: unit.status,
      agent_id: unit.agent_id,
      reviewed_paths: unit.reviewed_paths,
      local_checks: unit.local_checks,
      result_fingerprints: unit.result_fingerprints,
      unresolved: unit.unresolved,
      reassignment_reason: reason,
    }
    result[index] = {
      ...unit,
      attempts: [...unit.attempts, attempt],
      wave: unit.wave + 1,
      status: next,
      agent_id: null,
      reviewed_paths: [],
      local_checks: [],
      result_fingerprints: [],
      unresolved: next === 'deferred' ? [reason] : [],
    }
  }
  if (problems.length > 0) throw new LedgerError(problems)
  return result
}

/**
 * Close units without an assignment: `deferred`, `out_of_scope` or `not_applicable`, with the reason as their unresolved fact.
 * @param ledger - the current units.
 * @param ids - the coverage ids.
 * @param status - the closing status.
 * @param reason - why, such as `budget_cannot_reserve_critics_and_validation`.
 * @returns the new ledger.
 * @throws {LedgerError} when a unit is missing or carries evidence.
 */
export function closeUnits(ledger: readonly LedgerUnit[], ids: readonly string[], status: 'deferred' | 'out_of_scope' | 'not_applicable', reason: string): LedgerUnit[] {
  const next = [...ledger]
  const problems: string[] = []
  for (const id of ids) {
    const index = indexOf(next, id)
    const unit = next[index] as LedgerUnit
    if (unit.status !== 'planned' && unit.status !== 'deferred' && unit.status !== 'out_of_scope' && unit.status !== 'not_applicable') {
      problems.push(`${id} is ${unit.status}; close only units without live evidence, and reassign evidence-bearing ones`)
      continue
    }
    next[index] = { ...unit, status, agent_id: null, reviewed_paths: [], local_checks: [], result_fingerprints: [], unresolved: [reason] }
  }
  if (problems.length > 0) throw new LedgerError(problems)
  return next
}

/** Fields a patch may not change: identity, and the archive only reassignment appends to. */
const FIXED_FIELDS = new Set(['coverage_id', 'canonical_refs', 'surface', 'boundary', 'subsystem', 'attack_class', 'lifecycle', 'attempts'])

/**
 * Change other fields of one unit, for transitions without a dedicated operation, such as a verifier's check or a carried record's owner.
 * @param ledger - the current units.
 * @param id - the coverage id.
 * @param fields - the replacement field values.
 * @returns the new ledger.
 * @throws {LedgerError} when the patch names an identity or archive field.
 */
export function patchUnit(ledger: readonly LedgerUnit[], id: string, fields: Readonly<Record<string, unknown>>): LedgerUnit[] {
  const fixed = Object.keys(fields).filter(field => FIXED_FIELDS.has(field))
  if (fixed.length > 0) throw new LedgerError([`a patch cannot change ${fixed.join(', ')}`])
  const next = [...ledger]
  const index = indexOf(next, id)
  next[index] = { ...next[index] as LedgerUnit, ...fields } as LedgerUnit
  return next
}

/**
 * Count units by status.
 * @param ledger - the units.
 * @returns the counts, with every status present.
 */
export function statusCounts(ledger: readonly LedgerUnit[]): StatusCounts {
  const counts: StatusCounts = { planned: 0, in_progress: 0, covered: 0, candidate: 0, blocked: 0, deferred: 0, out_of_scope: 0, not_applicable: 0 }
  for (const unit of ledger) counts[unit.status] += 1
  return counts
}
