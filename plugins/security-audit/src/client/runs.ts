/**
 * What one security-audit run records in the workspace: where a run lives, which
 * discovered run is newest, and what its shared files say. The parsers are the
 * file boundary — a file the coordinator is still writing, or one that is
 * otherwise malformed, yields `undefined`, so the caller keeps its last good copy
 * and shows a quiet notice.
 * @module delorun-plugin-security-audit/client/runs
 */
import type { WorkspaceDirectoryEntry } from '@deepseek-ai/dsh-api-workspace-files/types'

/** The target-relative directory holding every run. */
export const RUNS_DIRECTORY = '.security-audit'

/** The prefix a run directory carries under {@link RUNS_DIRECTORY}. */
const RUN_PREFIX = 'run-'

/** The run's own record of its setup, state and cost. */
export const RUN_METADATA_FILE = 'run-metadata.json'

/** The coverage plan and its per-unit state. */
export const COVERAGE_LEDGER_FILE = 'coverage-ledger.json'

/** The candidates each validation has settled so far. */
export const CANDIDATES_FILE = 'candidates.json'

/** The structured record of what validation settled. */
export const FINDINGS_FILE = 'findings.json'

/** The shared run files the pane reads, in the order it reads them. */
export type AuditFileName =
  | typeof RUN_METADATA_FILE
  | typeof COVERAGE_LEDGER_FILE
  | typeof CANDIDATES_FILE
  | typeof FINDINGS_FILE

/** Every shared run file the pane reads. */
export const AUDIT_FILES: readonly AuditFileName[] = [
  RUN_METADATA_FILE, COVERAGE_LEDGER_FILE, CANDIDATES_FILE, FINDINGS_FILE,
]

/** One discovered run directory. */
export interface AuditRunRef {
  /** Workspace-relative directory path, `/`-separated. */
  readonly directory: string
  /** The directory's basename, which the switcher shows. */
  readonly label: string
  /**
   * The run's own latest recorded timestamp in epoch milliseconds, read from its
   * metadata. The file vocabulary exposes no modification time, so a run without
   * a readable record sorts by its directory name instead.
   */
  readonly recordedAt: number
}

/** One listed run parent and its direct children. */
export interface AuditListing {
  /** Workspace-relative directory the entries are direct children of. */
  readonly directory: string
  /** The children, as the Host listed them. */
  readonly entries: readonly WorkspaceDirectoryEntry[]
}

/**
 * Whether one child of the runs directory is a run directory.
 * @param name - the child's basename.
 * @returns true for a `run-*` directory.
 */
function isRunDirectory(name: string): boolean {
  return name.startsWith(RUN_PREFIX)
}

/**
 * The run directories a listing holds, before their recency is known.
 * @param listing - the listed runs directory.
 * @returns one entry per run directory, in listing order and with `recordedAt` 0.
 */
export function candidateRuns(listing: AuditListing): AuditRunRef[] {
  const runs: AuditRunRef[] = []
  for (const entry of listing.entries) {
    if (entry.type !== 'directory' || !isRunDirectory(entry.name)) continue
    runs.push({ directory: `${listing.directory}/${entry.name}`, label: entry.name, recordedAt: 0 })
  }
  return runs
}

/**
 * The highest number a run directory's name ends in, which orders runs that
 * record no timestamp.
 * @param label - the run directory's basename.
 * @returns the number, or 0 when the name carries none.
 */
function trailingNumber(label: string): number {
  const match = /(\d+)(?!.*\d)/u.exec(label)
  return match === null ? 0 : Number(match[1])
}

/**
 * Order runs newest first: by the run's own latest recorded timestamp, then by
 * the number its directory name ends in, then by name.
 * @param runs - the discovered runs.
 * @returns a sorted copy.
 */
export function orderRuns(runs: readonly AuditRunRef[]): AuditRunRef[] {
  return [...runs].sort((left, right) =>
    right.recordedAt - left.recordedAt
    || trailingNumber(right.label) - trailingNumber(left.label)
    || right.label.localeCompare(left.label))
}

/** A JSON object read from a run file. */
type JsonObject = Readonly<Record<string, unknown>>

/**
 * Parse one file's text.
 * @param raw - the file's text.
 * @returns the parsed value, or `undefined` when the text is not JSON.
 */
function parseJson(raw: string): unknown {
  try {
    const value: unknown = JSON.parse(raw)
    return value
  } catch (error) {
    // A file caught mid-write is the ordinary case here; the caller keeps its last good copy.
    void error
    return undefined
  }
}

/**
 * Read a parsed value as a JSON object.
 * @param value - the parsed value.
 * @returns the object, or `undefined` for any other JSON value.
 */
function jsonObject(value: unknown): JsonObject | undefined {
  return typeof value === 'object' && value !== null && !Array.isArray(value) ? value as JsonObject : undefined
}

/**
 * Read one non-empty string field.
 * @param value - the field's value.
 * @returns the text, or `undefined` when the field is not a non-empty string.
 */
function textField(value: unknown): string | undefined {
  return typeof value === 'string' && value.trim() !== '' ? value : undefined
}

/**
 * Read one timestamp field.
 * @param value - the field's value.
 * @returns epoch milliseconds, or `undefined` when the field is not a parseable timestamp.
 */
function timestampField(value: unknown): number | undefined {
  const text = textField(value)
  if (text === undefined) return undefined
  const parsed = Date.parse(text)
  return Number.isFinite(parsed) ? parsed : undefined
}

/**
 * Read one finite number field.
 * @param value - the field's value.
 * @returns the number, or `undefined` when the field is not a finite number.
 */
function numberField(value: unknown): number | undefined {
  return typeof value === 'number' && Number.isFinite(value) ? value : undefined
}

/** The run's lifecycle state, as the pane labels it. */
export type AuditRunStatus = 'in_progress' | 'complete' | 'incomplete' | 'unknown'

/** The run's current phase, as the pane labels it. */
export type AuditStage =
  | 'reconnaissance' | 'hunting' | 'validation' | 'final_verification' | 'reporting' | 'done' | 'unknown'

/** The reviewed source revision. */
export interface AuditSourceRef {
  /** The reviewed commit, when the run recorded one. */
  readonly commit: string | undefined
  /** Whether the working tree carried changes beyond that commit. */
  readonly dirty: boolean
}

/** What `run-metadata.json` records that the pane shows. */
export interface AuditMetadata {
  /** The run's identifier, `run-N`. */
  readonly runId: string | undefined
  /** The audited repository's name. */
  readonly repo: string | undefined
  /** The audit profile: quick, standard or deep. */
  readonly profile: string | undefined
  /** When the coordinator may interrupt: straight_through, after_recon or every_stage. */
  readonly checkIn: string | undefined
  /** The maximum agent invocations across all phases, or `null` when the run sets none. */
  readonly budget: number | null | undefined
  /** Agents started so far, which is the budget's own unit. */
  readonly spend: number | undefined
  /** The lifecycle state. */
  readonly status: AuditRunStatus
  /** The phase in progress. */
  readonly stage: AuditStage
  /** Why the run is incomplete, when it records that. */
  readonly statusReason: string | undefined
  /** The reviewed source revision. */
  readonly sourceRef: AuditSourceRef | undefined
  /** When the run started. */
  readonly startedAt: number | undefined
  /** When the run last wrote a shared file. */
  readonly updatedAt: number | undefined
  /** When the run reached a terminal state. */
  readonly finishedAt: number | undefined
  /** The latest timestamp any part of the run records, which orders runs. */
  readonly recordedAt: number
  /** The candidate counts the metadata tracks. */
  readonly candidateCounts: CandidateCounts | undefined
}

/** Candidate totals as `run-metadata.json` counts them. */
export interface CandidateCounts {
  /** Every candidate proposed. */
  readonly total: number
  /** Candidates still awaiting a verifier's verdict. */
  readonly proposed: number
  /** Candidates whose verdict is confirmed. */
  readonly confirmed: number
  /** Candidates whose verdict is needs_validation. */
  readonly needsValidation: number
  /** Candidates whose verdict is rejected. */
  readonly rejected: number
  /** Candidates a fresh agent independently verified. */
  readonly finalVerified: number
}

/**
 * Read one lifecycle field.
 * @param value - the `run_status` field.
 * @returns the known state, or `unknown`.
 */
function runStatus(value: unknown): AuditRunStatus {
  return value === 'in_progress' || value === 'complete' || value === 'incomplete' ? value : 'unknown'
}

/**
 * Read one phase field.
 * @param value - the `stage` field.
 * @returns the known phase, or `unknown`.
 */
function runStage(value: unknown): AuditStage {
  return value === 'reconnaissance' || value === 'hunting' || value === 'validation'
    || value === 'final_verification' || value === 'reporting' || value === 'done'
    ? value
    : 'unknown'
}

/**
 * Read the candidate totals.
 * @param value - the `candidates` field.
 * @returns the counts, or `undefined` when the field is not an object.
 */
function candidateCounts(value: unknown): CandidateCounts | undefined {
  const record = jsonObject(value)
  if (record === undefined) return undefined
  return {
    total: numberField(record.total) ?? 0,
    proposed: numberField(record.proposed) ?? 0,
    confirmed: numberField(record.confirmed) ?? 0,
    needsValidation: numberField(record.needs_validation) ?? 0,
    rejected: numberField(record.rejected) ?? 0,
    finalVerified: numberField(record.final_verified) ?? 0,
  }
}

/**
 * Read the audited source revision.
 * @param value - the `source_ref` field.
 * @returns the revision, or `undefined` when the field is not an object.
 */
function sourceRef(value: unknown): AuditSourceRef | undefined {
  const record = jsonObject(value)
  if (record === undefined) return undefined
  return { commit: textField(record.commit), dirty: record.dirty === true }
}

/**
 * Parse `run-metadata.json`.
 * @param raw - the file's text.
 * @returns what the pane shows, or `undefined` when the top level is not an object.
 */
export function parseMetadata(raw: string): AuditMetadata | undefined {
  const record = jsonObject(parseJson(raw))
  if (record === undefined) return undefined
  const startedAt = timestampField(record.created_at)
  const updatedAt = timestampField(record.updated_at)
  const finishedAt = timestampField(record.completed_at)
  const recordedAt = Math.max(startedAt ?? 0, updatedAt ?? 0, finishedAt ?? 0)
  const budget = record.budget === null ? null : numberField(record.budget)
  const agents = jsonObject(record.agents)
  return {
    runId: textField(record.run_id),
    repo: textField(record.repo),
    profile: textField(record.profile),
    checkIn: textField(record.check_in),
    budget,
    spend: agents === undefined ? undefined : numberField(agents.invocations),
    status: runStatus(record.run_status),
    stage: runStage(record.stage),
    statusReason: textField(record.incomplete_reason),
    sourceRef: sourceRef(record.source_ref),
    startedAt,
    updatedAt,
    finishedAt,
    recordedAt,
    candidateCounts: candidateCounts(record.candidates),
  }
}

/** One coverage unit's state. */
export type CoverageStatus =
  | 'planned' | 'in_progress' | 'covered' | 'candidate' | 'blocked' | 'deferred'
  | 'out_of_scope' | 'not_applicable' | 'unknown'

/** Every status a unit may carry; `unknown` is what the pane reads for anything else. */
const COVERAGE_STATUSES: readonly CoverageStatus[] = [
  'planned', 'in_progress', 'covered', 'candidate', 'blocked', 'deferred',
  'out_of_scope', 'not_applicable', 'unknown',
]

/** One unit a role owns right now. */
export interface CoverageUnit {
  /** The unit's stable canonical identifier. */
  readonly id: string
  /** What the unit covers, as a readable surface and attack class. */
  readonly label: string
  /** The unit's state. */
  readonly status: CoverageStatus
  /** The role that owns it, when one does. */
  readonly owner: string | undefined
  /** Which assignment wave it belongs to. */
  readonly wave: number | undefined
  /** How many archived attempts the unit carries. */
  readonly attempts: number
  /** The unresolved facts its owner recorded. */
  readonly unresolved: number
}

/** The counts and live units the pane shows for one ledger. */
export interface CoverageSummary {
  /** Units the run planned to cover: every unit except the out-of-scope and not-applicable ones. */
  readonly total: number
  /** Units the ledger marks `covered`. */
  readonly covered: number
  /** Units whose state is `candidate`. */
  readonly candidate: number
  /** Units whose state is `blocked`. */
  readonly blocked: number
  /** Units whose state is `deferred`. */
  readonly deferred: number
  /** Units nobody has started yet. */
  readonly planned: number
  /** Units a role is working on now. */
  readonly inProgress: number
  /** How many units carry each state. */
  readonly byStatus: Readonly<Record<CoverageStatus, number>>
  /** The units a role owns now: in progress first, then candidates, in ledger order. */
  readonly active: readonly CoverageUnit[]
  /** Array entries that were not readable units. */
  readonly skipped: number
}

/**
 * Read the ledger state one field names.
 * @param value - the unit's `status` field.
 * @returns the known state, or `unknown`.
 */
function coverageStatus(value: unknown): CoverageStatus {
  return typeof value === 'string' && (COVERAGE_STATUSES as readonly string[]).includes(value)
    ? value as CoverageStatus
    : 'unknown'
}

/**
 * The readable label of one unit: its surface and attack class, or its identifier.
 * @param record - the ledger unit.
 * @param id - the unit's coverage identifier.
 * @returns the label.
 */
function unitLabel(record: JsonObject, id: string): string {
  const surface = textField(record.surface)
  const attackClass = textField(record.attack_class)
  if (surface !== undefined && attackClass !== undefined) return `${surface} — ${attackClass}`
  return surface ?? attackClass ?? id
}

/**
 * Read one ledger unit the pane shows.
 * @param record - the ledger unit.
 * @param index - its position, for a stable key when it carries no identifier.
 * @returns the unit, or `undefined` when it is not an object.
 */
function unitOf(record: JsonObject, index: number): CoverageUnit | undefined {
  const id = textField(record.coverage_id) ?? `unit-${String(index + 1)}`
  const attempts = Array.isArray(record.attempts) ? record.attempts.length : 0
  const unresolved = Array.isArray(record.unresolved) ? record.unresolved.length : 0
  const status = coverageStatus(record.status)
  return {
    id,
    label: unitLabel(record, id),
    status,
    owner: textField(record.agent_id),
    wave: numberField(record.wave),
    attempts,
    unresolved,
  }
}

/**
 * Parse `coverage-ledger.json`.
 * @param raw - the file's text.
 * @returns the counts and live units, or `undefined` when the top level is not the ledger array.
 */
export function parseCoverage(raw: string): CoverageSummary | undefined {
  const parsed = parseJson(raw)
  if (!Array.isArray(parsed)) return undefined
  const byStatus: Record<CoverageStatus, number> = {
    planned: 0, in_progress: 0, covered: 0, candidate: 0, blocked: 0, deferred: 0,
    out_of_scope: 0, not_applicable: 0, unknown: 0,
  }
  const units: CoverageUnit[] = []
  let skipped = 0
  for (const [index, entry] of parsed.entries()) {
    const record = jsonObject(entry)
    const unit = record === undefined ? undefined : unitOf(record, index)
    if (record === undefined || unit === undefined) {
      skipped += 1
      continue
    }
    byStatus[unit.status] += 1
    units.push(unit)
  }
  const total = COVERAGE_STATUSES
    .filter(status => status !== 'out_of_scope' && status !== 'not_applicable')
    .reduce((sum, status) => sum + byStatus[status], 0)
  const active = [
    ...units.filter(unit => unit.status === 'in_progress'),
    ...units.filter(unit => unit.status === 'candidate'),
  ]
  return {
    total,
    covered: byStatus.covered,
    candidate: byStatus.candidate,
    blocked: byStatus.blocked,
    deferred: byStatus.deferred,
    planned: byStatus.planned,
    inProgress: byStatus.in_progress,
    byStatus,
    active,
    skipped,
  }
}

/** A record's verdict. */
export type FindingVerdict = 'confirmed' | 'needs_validation' | 'rejected'

/** One source line a record cites. */
export interface FindingCitation {
  /** The cited file, as the record writes it: repository-relative in the audited target. */
  readonly file: string
  /** The cited 1-based line, when the record names one. */
  readonly line: number | undefined
}

/** One record the pane lists. */
export interface AuditFinding {
  /** What validation settled on. */
  readonly verdict: FindingVerdict
  /** The record's stable identifier, which the prompts use. */
  readonly fingerprint: string | undefined
  /** The record's title. */
  readonly title: string
  /** The confirmed record's overall severity; absent for the other verdicts. */
  readonly severity: string | undefined
  /** The distinct source lines the record cites, trace and evidence together. */
  readonly citations: readonly FindingCitation[]
}

/** The counts and records the pane shows for one findings file. */
export interface FindingsSummary {
  /** Records read. */
  readonly total: number
  /** Records whose verdict is `confirmed`. */
  readonly confirmed: number
  /** Records whose verdict is `needs_validation`. */
  readonly needsValidation: number
  /** Records whose verdict is `rejected`. */
  readonly rejected: number
  /** The records, in file order. */
  readonly items: readonly AuditFinding[]
  /** Array entries that were not readable records. */
  readonly skipped: number
}

/**
 * Read one verdict field.
 * @param value - the record's `verdict` field.
 * @returns the verdict, or `undefined` for anything else.
 */
function findingVerdict(value: unknown): FindingVerdict | undefined {
  return value === 'confirmed' || value === 'needs_validation' || value === 'rejected' ? value : undefined
}

/**
 * The distinct source lines a record cites, in trace-then-evidence order.
 * @param record - the findings record.
 * @returns the citations.
 */
function citationsOf(record: JsonObject): FindingCitation[] {
  const citations: FindingCitation[] = []
  const seen = new Set<string>()
  for (const field of ['trace', 'evidence']) {
    const list = record[field]
    if (!Array.isArray(list)) continue
    for (const entry of list) {
      const citation = jsonObject(entry)
      const file = citation === undefined ? undefined : textField(citation.file)
      if (citation === undefined || file === undefined) continue
      const line = typeof citation.line === 'number' && Number.isInteger(citation.line) && citation.line >= 1
        ? citation.line
        : undefined
      const key = `${file}:${String(line)}`
      if (seen.has(key)) continue
      seen.add(key)
      citations.push({ file, line })
    }
  }
  return citations
}

/**
 * Read one record's overall severity.
 * @param record - the findings record.
 * @returns the severity score, or `undefined` when the record records none.
 */
function severityOf(record: JsonObject): string | undefined {
  const severity = jsonObject(record.severity)
  const overall = severity === undefined ? undefined : jsonObject(severity.overall_severity)
  const score = overall === undefined ? undefined : overall.score
  if (typeof score === 'string') return textField(score)
  return numberField(score) === undefined ? undefined : String(score)
}

/**
 * Read one findings record, defensively: an unknown verdict or a missing title
 * leaves the entry out and the caller reports it as unreadable.
 * @param record - the array entry.
 * @returns the record the pane lists, or `undefined`.
 */
function findingOf(record: JsonObject): AuditFinding | undefined {
  const verdict = findingVerdict(record.verdict)
  const title = textField(record.title)
  if (verdict === undefined || title === undefined) return undefined
  return {
    verdict,
    fingerprint: textField(record.fingerprint),
    title,
    severity: verdict === 'confirmed' ? severityOf(record) : undefined,
    citations: citationsOf(record),
  }
}

/**
 * Parse `findings.json`.
 * @param raw - the file's text.
 * @returns the counts and records, or `undefined` when the top level is not the records array.
 */
export function parseFindings(raw: string): FindingsSummary | undefined {
  const parsed = parseJson(raw)
  if (!Array.isArray(parsed)) return undefined
  const items: AuditFinding[] = []
  let skipped = 0
  for (const entry of parsed) {
    const record = jsonObject(entry)
    const finding = record === undefined ? undefined : findingOf(record)
    if (finding === undefined) {
      skipped += 1
      continue
    }
    items.push(finding)
  }
  const count = (verdict: FindingVerdict): number => items.filter(item => item.verdict === verdict).length
  return {
    total: items.length,
    confirmed: count('confirmed'),
    needsValidation: count('needs_validation'),
    rejected: count('rejected'),
    items,
    skipped,
  }
}

/** One candidate's state. */
export type CandidateStatus = 'proposed' | 'confirmed' | 'needs_validation' | 'rejected' | 'unknown'

/** One candidate as the pane lists it. */
export interface AuditCandidate {
  /** The record's stable identifier. */
  readonly fingerprint: string | undefined
  /** The candidate's state. */
  readonly status: CandidateStatus
  /** The candidate record's title. */
  readonly title: string
  /** The role that proposed it. */
  readonly proposedBy: string | undefined
  /** Whether a fresh agent independently verified it. */
  readonly finalVerified: boolean
}

/** The counts and candidates the pane shows for one candidates file. */
export interface CandidatesSummary {
  /** Candidates read. */
  readonly total: number
  /** Candidates still awaiting a verifier's verdict. */
  readonly proposed: number
  /** Candidates whose verdict is confirmed. */
  readonly confirmed: number
  /** Candidates whose verdict is needs_validation. */
  readonly needsValidation: number
  /** Candidates whose verdict is rejected. */
  readonly rejected: number
  /** The candidates still under validation. */
  readonly pending: readonly AuditCandidate[]
  /** Array entries that were not readable candidates. */
  readonly skipped: number
}

/**
 * Read one candidate state.
 * @param value - the candidate's `status` field.
 * @returns the known state, or `unknown`.
 */
function candidateStatus(value: unknown): CandidateStatus {
  return value === 'proposed' || value === 'confirmed' || value === 'needs_validation' || value === 'rejected'
    ? value
    : 'unknown'
}

/**
 * Parse `candidates.json`.
 * @param raw - the file's text.
 * @returns the counts and the candidates under validation, or `undefined` when the top level is not an array.
 */
export function parseCandidates(raw: string): CandidatesSummary | undefined {
  const parsed = parseJson(raw)
  if (!Array.isArray(parsed)) return undefined
  const pending: AuditCandidate[] = []
  const counts = { proposed: 0, confirmed: 0, needsValidation: 0, rejected: 0 }
  let total = 0
  let skipped = 0
  for (const entry of parsed) {
    const record = jsonObject(entry)
    const finding = record === undefined ? undefined : findingOf(jsonObject(record.record) ?? {})
    if (record === undefined || finding === undefined) {
      skipped += 1
      continue
    }
    total += 1
    const status = candidateStatus(record.status)
    if (status === 'proposed') {
      counts.proposed += 1
      pending.push({
        fingerprint: textField(record.fingerprint) ?? finding.fingerprint,
        status,
        title: finding.title,
        proposedBy: textField(record.proposed_by),
        finalVerified: record.final_verified === true,
      })
    } else if (status === 'confirmed') counts.confirmed += 1
    else if (status === 'needs_validation') counts.needsValidation += 1
    else if (status === 'rejected') counts.rejected += 1
  }
  return { total, ...counts, pending, skipped }
}

/**
 * Join a workspace root with a workspace-relative path, `/`-separated.
 * @param root - the Session's absolute workspace folder.
 * @param path - the workspace-relative path.
 * @returns the absolute path, in the mixed-separator spelling the Host resolves.
 */
export function inWorkspace(root: string, path: string): string {
  return `${root.replace(/[/\\]+$/u, '')}/${path}`
}
