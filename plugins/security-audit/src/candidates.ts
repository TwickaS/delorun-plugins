/**
 * The candidate store between hunting and final verification. A candidate is
 * a schema-shaped record plus its independent verifier history; only the
 * coordinator writes this file, and only a record with a final independent
 * verification may enter `findings.json`.
 * @module @delorun/plugin-security-audit/candidates
 */
import type { LedgerCheck } from './ledger.ts'
import { type AuditFiles, type RunLocation, inRun, now } from './store.ts'

/** One independent verification of a candidate. */
export interface CandidateVerification {
  readonly agent_id: string
  readonly decision: 'confirmed' | 'needs_validation' | 'rejected'
  readonly record: Record<string, unknown>
  readonly checks: readonly LedgerCheck[]
  readonly at: string
}

/** One candidate and its verification history. */
export interface CandidateEntry {
  readonly fingerprint: string
  status: 'proposed' | 'confirmed' | 'needs_validation' | 'rejected'
  record: Record<string, unknown>
  readonly proposed_by: string
  readonly proposed_at: string
  /** Coverage ids that link this fingerprint. */
  proposed_units: string[]
  readonly verifications: CandidateVerification[]
  final_verified: boolean
  final_by: string | null
  final_at: string | null
  /** A phase-5 replacement awaiting its own independent verifier. */
  pending_record?: Record<string, unknown> | undefined
  /** A coordinator note about a duplicate or a non-material correction. */
  note?: string | undefined
}

/**
 * Read a record's overall severity from the object schema or the string form used by older persisted records.
 * @param record - a candidate record.
 * @returns the severity, or `unknown`.
 */
export function overallSeverityOf(record: Record<string, unknown>): string {
  const severity = record.severity
  if (typeof severity === 'string') return severity
  if (typeof severity === 'object' && severity !== null && !Array.isArray(severity)) {
    const overall = (severity as { overall_severity?: unknown }).overall_severity
    if (typeof overall === 'string') return overall
  }
  return 'unknown'
}

/**
 * Read the candidate store.
 * @param files - file access.
 * @param run - the run.
 * @returns the candidates.
 * @throws {Error} when the file is not an array.
 */
export async function readCandidates(files: AuditFiles, run: RunLocation): Promise<CandidateEntry[]> {
  const value = await files.readJson(inRun(run, 'harness/candidates.json'))
  if (value === undefined) return []
  if (!Array.isArray(value)) throw new Error('harness/candidates.json must hold a top-level array')
  return value as CandidateEntry[]
}

/**
 * Write the candidate store, sorted by fingerprint.
 * @param files - file access.
 * @param run - the run.
 * @param candidates - the candidates.
 */
export async function writeCandidates(files: AuditFiles, run: RunLocation, candidates: readonly CandidateEntry[]): Promise<void> {
  await files.writeJson(inRun(run, 'harness/candidates.json'), [...candidates].sort((left, right) => left.fingerprint < right.fingerprint ? -1 : left.fingerprint > right.fingerprint ? 1 : 0))
}

function stable(value: unknown): string {
  return JSON.stringify(value)
}

/**
 * Whether a replacement changes the finding's evidence or verdict, rather
 * than only its wording.
 * @param current - the current record.
 * @param replacement - the proposed replacement.
 * @returns whether a fresh independent verifier is required.
 */
export function materialChange(current: Record<string, unknown>, replacement: Record<string, unknown>): boolean {
  const fields = ['verdict', 'fingerprint', 'severity', 'root_cause', 'claimed_root_cause', 'trace', 'evidence', 'conditions', 'execution', 'remediation', 'blockers', 'validation_plan']
  return fields.some(field => stable(current[field]) !== stable(replacement[field]))
}

/**
 * Add a hunter's candidate or merge its coverage link into an existing one.
 * @param candidates - the current store.
 * @param record - the schema-shaped record.
 * @param proposedBy - the hunter's agent id.
 * @param units - the coverage ids that link the fingerprint.
 * @returns the updated store and the candidate.
 * @throws {Error} when the record has no string fingerprint.
 */
export function upsertCandidate(
  candidates: readonly CandidateEntry[],
  record: Record<string, unknown>,
  proposedBy: string,
  units: readonly string[],
): { readonly candidates: CandidateEntry[]; readonly candidate: CandidateEntry; readonly added: boolean } {
  const fingerprint = record.fingerprint
  if (typeof fingerprint !== 'string' || fingerprint.length === 0) throw new Error('a candidate needs a string fingerprint')
  const existing = candidates.find(candidate => candidate.fingerprint === fingerprint)
  if (existing !== undefined) {
    for (const unit of units) if (!existing.proposed_units.includes(unit)) existing.proposed_units.push(unit)
    return { candidates: [...candidates], candidate: existing, added: false }
  }
  const candidate: CandidateEntry = {
    fingerprint,
    status: record.verdict === 'needs_validation' ? 'needs_validation' : 'confirmed',
    record,
    proposed_by: proposedBy,
    proposed_at: now(),
    proposed_units: [...new Set(units)],
    verifications: [],
    final_verified: false,
    final_by: null,
    final_at: null,
  }
  return { candidates: [...candidates, candidate], candidate, added: true }
}

/**
 * Record one independent verification and update the candidate's verdict.
 * @param candidates - the store.
 * @param fingerprint - the candidate fingerprint.
 * @param verification - the verifier's decision.
 * @returns the updated store.
 * @throws {Error} when the fingerprint is unknown.
 */
export function recordVerification(candidates: readonly CandidateEntry[], fingerprint: string, verification: CandidateVerification): CandidateEntry[] {
  const index = candidates.findIndex(candidate => candidate.fingerprint === fingerprint)
  if (index < 0) throw new Error(`candidate ${fingerprint} is not in the store`)
  const candidate = candidates[index] as CandidateEntry
  const next: CandidateEntry = {
    ...candidate,
    status: verification.decision,
    record: verification.record,
    verifications: [...candidate.verifications, verification],
    final_verified: verification.decision === 'rejected' ? candidate.final_verified : false,
  }
  return candidates.with(index, next)
}

/**
 * Apply a final verification. A material replacement becomes pending and
 * still needs a fresh verifier; a verified pending replacement becomes final.
 * @param candidates - the store.
 * @param fingerprint - the candidate fingerprint.
 * @param decision - `verified` or `replace`.
 * @param agentId - the verifier.
 * @param replacement - the replacement record for `replace`.
 * @param reason - the replacement reason.
 * @returns the updated store and whether another verifier is required.
 * @throws {Error} when the fingerprint is unknown.
 */
export function applyFinalVerification(
  candidates: readonly CandidateEntry[],
  fingerprint: string,
  decision: 'verified' | 'replace',
  agentId: string,
  replacement: Record<string, unknown> | undefined,
  reason: string | undefined,
): { readonly candidates: CandidateEntry[]; readonly requiresVerifier: boolean; readonly material: boolean } {
  const index = candidates.findIndex(candidate => candidate.fingerprint === fingerprint)
  if (index < 0) throw new Error(`candidate ${fingerprint} is not in the store`)
  const candidate = candidates[index] as CandidateEntry
  if (decision === 'verified') {
    const record = candidate.pending_record ?? candidate.record
    const next: CandidateEntry = {
      ...candidate,
      record,
      pending_record: undefined,
      final_verified: true,
      final_by: agentId,
      final_at: now(),
    }
    return { candidates: candidates.with(index, next), requiresVerifier: false, material: false }
  }
  if (replacement === undefined) throw new Error('a replace decision needs a replacement record')
  const current = candidate.pending_record ?? candidate.record
  const material = materialChange(current, replacement)
  if (!material) {
    const next: CandidateEntry = {
      ...candidate,
      record: replacement,
      pending_record: undefined,
      final_verified: true,
      final_by: agentId,
      final_at: now(),
      ...reason === undefined ? {} : { note: reason },
    }
    return { candidates: candidates.with(index, next), requiresVerifier: false, material: false }
  }
  const next: CandidateEntry = {
    ...candidate,
    pending_record: replacement,
    final_verified: false,
    final_by: null,
    final_at: null,
    ...reason === undefined ? {} : { note: reason },
  }
  return { candidates: candidates.with(index, next), requiresVerifier: true, material: true }
}

/**
 * The records that may enter `findings.json`.
 * @param candidates - the store.
 * @returns the records and the fingerprints that are still unresolved.
 */
export function finalRecords(candidates: readonly CandidateEntry[]): { readonly records: Record<string, unknown>[]; readonly unresolved: string[] } {
  const records: Record<string, unknown>[] = []
  const unresolved: string[] = []
  for (const candidate of candidates) {
    if (candidate.status === 'rejected') {
      const verified = candidate.verifications.some(verification => verification.decision === 'rejected')
      if (verified) records.push(candidate.record)
      else unresolved.push(candidate.fingerprint)
      continue
    }
    if (candidate.final_verified && candidate.verifications.length > 0) records.push(candidate.record)
    else unresolved.push(candidate.fingerprint)
  }
  return { records: records.sort((left, right) => String(left.fingerprint) < String(right.fingerprint) ? -1 : 1), unresolved }
}
