/**
 * `findings.json` and `run-metadata.json`, the report's consistency checks,
 * and the completion gate. `findings.json` is derived only from independently
 * verified records; a report is written only from that file, and a
 * machine-readable fingerprint footer keeps prose and JSON aligned.
 * @module @delorun/plugin-security-audit/report
 */
import type { CandidateEntry, HarnessState, LedgerUnit, ReportDocument, RunMetadata } from './types.ts'
import { finalRecords } from './candidates.ts'
import { validateLedger } from './ledger.ts'
import { findingsValidator, REPORT_SCHEMA } from './skill.ts'
import {
  type AuditFiles,
  type RunLocation,
  ARCHITECTURE_FILE,
  CANDIDATES_FILE,
  COVERAGE_LEDGER_FILE,
  FINDINGS_FILE,
  REPORT_FILES,
  SHARED_RUN_FILES,
  RUN_METADATA_FILE,
  inRun,
  now,
} from './store.ts'

export { REPORT_FILES } from './store.ts'

/** Every file the coordinator writes at the run root: the seven shared files and its own candidate store. */
export const COORDINATOR_FILES: readonly string[] = [...SHARED_RUN_FILES, CANDIDATES_FILE]

/** The machine-readable footer every report document carries. */
export const FINGERPRINT_FOOTER = /<!--\s*audit-fingerprints:\s*([^>]*?)\s*-->/u

/**
 * Build `findings.json` from the candidate store.
 * @param candidates - the candidates.
 * @returns the records that may enter the report and the unresolved fingerprints.
 */
export function findingsDocument(candidates: readonly CandidateEntry[]): { readonly records: Record<string, unknown>[]; readonly unresolved: string[] } {
  return finalRecords(candidates)
}

/**
 * Validate the findings document with the skill's own validator.
 * @param records - the records.
 * @returns the problems, empty when valid.
 */
export function findingsProblems(records: readonly unknown[]): string[] {
  return findingsValidator.validateDocument(records, REPORT_SCHEMA)
}

/**
 * Validate the coverage ledger with the skill's own validator.
 * @param ledger - the units.
 * @returns the problems, empty when valid.
 */
export function ledgerProblems(ledger: readonly LedgerUnit[]): string[] {
  return validateLedger(ledger)
}

/**
 * The fingerprints a report document must account for.
 * @param document - the report document.
 * @param records - the final records.
 * @returns the expected fingerprints, sorted.
 */
export function expectedFingerprints(document: ReportDocument, records: readonly Record<string, unknown>[]): string[] {
  const strings = (value: unknown): string[] => typeof value === 'string' ? [value] : []
  if (document === 'NEEDS_VALIDATION') return records.filter(record => record.verdict === 'needs_validation').flatMap(record => strings(record.fingerprint)).sort()
  if (document === 'FINDINGS_DETAIL') {
    const overall = (record: Record<string, unknown>): string => {
      const severity = record.severity
      if (typeof severity === 'object' && severity !== null) {
        const value = (severity as { overall_severity?: unknown }).overall_severity
        if (typeof value === 'string') return value
        if (typeof value === 'object' && value !== null) {
          const score = (value as { score?: unknown }).score
          if (typeof score === 'string') return score
        }
      }
      return ''
    }
    return records.filter(record => record.verdict === 'confirmed' && ['medium', 'high', 'critical'].includes(overall(record))).flatMap(record => strings(record.fingerprint)).sort()
  }
  return records.filter(record => record.verdict !== 'rejected').flatMap(record => strings(record.fingerprint)).sort()
}

/**
 * Check a report's fingerprint footer and its expected records.
 * @param document - the report document.
 * @param content - its Markdown.
 * @param records - the final records.
 * @returns the problems, empty when consistent.
 */
export function reportProblems(document: ReportDocument, content: string, records: readonly Record<string, unknown>[]): string[] {
  const match = FINGERPRINT_FOOTER.exec(content)
  if (match === null) return [`${REPORT_FILES[document]} must end with <!-- audit-fingerprints: fp1, fp2 -->`]
  const declared = (match[1] ?? '').split(',').map(value => value.trim()).filter(value => value.length > 0)
  const expected = expectedFingerprints(document, records)
  const missing = expected.filter(fingerprint => !declared.includes(fingerprint))
  const extra = declared.filter(fingerprint => !expected.includes(fingerprint))
  const duplicate = declared.filter((fingerprint, index) => declared.indexOf(fingerprint) !== index)
  const problems: string[] = []
  if (missing.length > 0) problems.push(`${REPORT_FILES[document]} is missing fingerprints: ${missing.join(', ')}`)
  if (extra.length > 0) problems.push(`${REPORT_FILES[document]} names fingerprints that do not belong in this document: ${extra.join(', ')}`)
  if (duplicate.length > 0) problems.push(`${REPORT_FILES[document]} repeats fingerprints: ${duplicate.join(', ')}`)
  return problems
}

/**
 * Write `findings.json` after the skill's validator accepts it.
 * @param files - file access.
 * @param run - the run.
 * @param records - the final records.
 * @throws {Error} with every validator problem.
 */
export async function writeFindings(files: AuditFiles, run: RunLocation, records: readonly Record<string, unknown>[]): Promise<void> {
  const problems = findingsProblems(records)
  if (problems.length > 0) throw new Error(`findings.json is invalid:\n${problems.join('\n')}`)
  await files.writeJson(inRun(run, FINDINGS_FILE), records)
}

/**
 * Write `coverage-ledger.json` after the skill's validator accepts it.
 * @param files - file access.
 * @param run - the run.
 * @param ledger - the units.
 * @throws {Error} with every validator problem.
 */
export async function writeLedger(files: AuditFiles, run: RunLocation, ledger: readonly LedgerUnit[]): Promise<void> {
  const problems = ledgerProblems(ledger)
  if (problems.length > 0) throw new Error(`coverage-ledger.json is invalid:\n${problems.join('\n')}`)
  await files.writeJson(inRun(run, COVERAGE_LEDGER_FILE), ledger)
}

/**
 * Build the derived run metadata, the pane's and the report's view of the run.
 * @param state - the run's state.
 * @param ledger - the units.
 * @param candidates - the candidates.
 * @param completedAt - when the run stopped, for a terminal run.
 * @returns the metadata.
 */
export function runMetadata(state: HarnessState, ledger: readonly LedgerUnit[], candidates: readonly CandidateEntry[], completedAt: string | null = null): RunMetadata {
  const companionFiles = [...new Set(ledger.flatMap(unit => unit.selected_companion_blocks.map(ref => ref.slice(0, Math.max(0, ref.indexOf('#'))))))].sort()
  return {
    run_id: state.run_id,
    repo: state.repo_name,
    target: state.target,
    source_ref: state.source_ref,
    profile: state.profile,
    ...state.seed === undefined ? {} : { seed: state.seed },
    scope_paths: state.scope_paths,
    budget: state.budget,
    execution_policy: state.execution_policy,
    check_in: state.check_in,
    intake_note: state.intake_note,
    inputs: state.inputs ?? [],
    run_status: state.run_status,
    incomplete_reason: state.incomplete_reason,
    stage: state.stage,
    created_at: state.created_at,
    updated_at: now(),
    completed_at: completedAt ?? (state.stage === 'done' ? now() : null),
    orchestrator_session: state.orchestrator_session,
    orchestrator_model: state.orchestrator_model,
    agent_models: Object.fromEntries(Object.entries(state.agents).map(([id, agent]) => [id, { role: agent.role, kind: agent.kind, model: agent.model ?? null }])),
    agents: { total: Object.keys(state.agents).length, invocations: state.invocations, budget: state.budget },
    execution: state.execution,
    selected_companion_files: companionFiles,
    prior_runs: state.prior_runs,
    shared_file_owners: Object.fromEntries(SHARED_RUN_FILES.map(name => [name, 'coordinator' as const])),
    candidates: {
      total: candidates.length,
      proposed: candidates.filter(candidate => candidate.status === 'proposed').length,
      confirmed: candidates.filter(candidate => candidate.status === 'confirmed').length,
      needs_validation: candidates.filter(candidate => candidate.status === 'needs_validation').length,
      rejected: candidates.filter(candidate => candidate.status === 'rejected').length,
      final_verified: candidates.filter(candidate => candidate.final_verified).length,
    },
  }
}

/**
 * Write `run-metadata.json`. Every ledger and candidate write ends with this
 * call, so the file's `updated_at` is the pane's liveness signal.
 * @param files - file access.
 * @param run - the run.
 * @param state - the run's state.
 * @param ledger - the units.
 * @param candidates - the candidates.
 * @param completedAt - when the run stopped, for a terminal run.
 */
export async function writeRunMetadata(files: AuditFiles, run: RunLocation, state: HarnessState, ledger: readonly LedgerUnit[], candidates: readonly CandidateEntry[], completedAt: string | null = null): Promise<void> {
  await files.writeJson(inRun(run, RUN_METADATA_FILE), runMetadata(state, ledger, candidates, completedAt))
}

/**
 * Write one report document.
 * @param files - file access.
 * @param run - the run.
 * @param document - the document kind.
 * @param content - its Markdown.
 * @param records - the final records.
 * @throws {Error} with every consistency problem.
 */
export async function writeReport(files: AuditFiles, run: RunLocation, document: ReportDocument, content: string, records: readonly Record<string, unknown>[]): Promise<void> {
  const problems = reportProblems(document, content, records)
  if (problems.length > 0) throw new Error(`the report is not consistent with findings.json:\n${problems.join('\n')}`)
  await files.write(inRun(run, REPORT_FILES[document]), `${content.trimEnd()}\n`)
}

/**
 * The reasons a run cannot yet be marked complete.
 * @param files - file access.
 * @param run - the run.
 * @param state - the run's state.
 * @param ledger - the units.
 * @param candidates - the candidates.
 * @returns the problems, empty when the three documents and both validators agree.
 */
export async function completionProblems(
  files: AuditFiles,
  run: RunLocation,
  state: HarnessState,
  ledger: readonly LedgerUnit[],
  candidates: readonly CandidateEntry[],
): Promise<string[]> {
  const problems: string[] = []
  const ledgerIssues = ledgerProblems(ledger)
  if (ledgerIssues.length > 0) problems.push(...ledgerIssues.map(problem => `ledger: ${problem}`))
  if (state.run_status !== 'incomplete') {
    if (ledger.length === 0) problems.push('the coverage ledger has no units; a complete run must claim coverage')
    const open = ledger.filter(unit => ['planned', 'in_progress', 'blocked', 'deferred'].includes(unit.status)).map(unit => unit.coverage_id)
    if (open.length > 0) problems.push(`coverage units are not terminal: ${open.join(', ')}`)
  }
  const { records, unresolved } = findingsDocument(candidates)
  if (state.run_status !== 'incomplete' && unresolved.length > 0) problems.push(`unverified candidates remain in the ledger: ${unresolved.join(', ')}`)
  const known = new Set(candidates.map(candidate => candidate.fingerprint))
  const orphaned = [...new Set(ledger.flatMap(unit => unit.result_fingerprints.filter(fingerprint => !known.has(fingerprint))))]
  if (orphaned.length > 0) problems.push(`ledger fingerprints have no candidate record: ${orphaned.join(', ')}`)
  const findingIssues = findingsProblems(records)
  if (findingIssues.length > 0) problems.push(...findingIssues.map(problem => `findings: ${problem}`))
  const onDisk = await files.readJson(inRun(run, FINDINGS_FILE))
  if (!Array.isArray(onDisk)) problems.push('findings.json is missing or is not an array')
  else if (JSON.stringify(onDisk) !== JSON.stringify(records)) problems.push('findings.json does not match the independently verified candidate records; run audit_finalize again')
  const ledgerOnDisk = await files.readJson(inRun(run, COVERAGE_LEDGER_FILE))
  if (!Array.isArray(ledgerOnDisk)) problems.push('coverage-ledger.json is missing or is not an array')
  else if (JSON.stringify(ledgerOnDisk) !== JSON.stringify(ledger)) problems.push('coverage-ledger.json does not match the live ledger; run audit_finalize again')
  for (const document of ['REPORT', 'FINDINGS_DETAIL', 'NEEDS_VALIDATION'] as const) {
    const text = await files.read(inRun(run, REPORT_FILES[document]))
    if (text === undefined) problems.push(`${REPORT_FILES[document]} is missing`)
    else problems.push(...reportProblems(document, text, records))
  }
  if (state.run_status === 'incomplete' && (state.incomplete_reason === null || state.incomplete_reason.trim().length === 0)) {
    problems.push('an incomplete run needs `incomplete_reason`')
  }
  return problems
}
