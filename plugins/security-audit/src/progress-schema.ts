/**
 * The machine-readable progress of one run, written beside the other run files on every ledger change.
 *
 * The pane and any other integration read this instead of scraping the ledger, so the shape is versioned and its
 * fields are documented in the README. It is derived: the coverage ledger stays the source of truth, and this file
 * carries no fact the ledger and the run metadata do not already hold.
 * @module delorun-plugin-security-audit/progress-schema
 */

/** The schema id and version this module writes. A reader refuses a version it does not know. */
export const PROGRESS_SCHEMA = 'delorun.security-audit.progress/1'

/** The file a run writes it to, beside the other shared run files. */
export const PROGRESS_FILE = 'progress.json'

/** How many units sit in each ledger state. */
export interface ProgressCounts {
  /** Units not yet assigned. */
  readonly planned: number
  /** Units a role is working on now. */
  readonly in_progress: number
  /** Units a role closed with evidence. */
  readonly covered: number
  /** Units holding a candidate awaiting validation. */
  readonly candidate: number
  /** Units a role could not settle. */
  readonly blocked: number
  /** Units the profile or budget left unassigned. */
  readonly deferred: number
  /** Units outside this run's scope. */
  readonly out_of_scope: number
  /** Units that do not apply to this target. */
  readonly not_applicable: number
}

/** One unit a role is working on, as the pane shows it. */
export interface ProgressUnit {
  /** The unit's stable coverage id. */
  readonly coverage_id: string
  /** The role working on it. */
  readonly owner: string
  /** The wave it was assigned in. */
  readonly wave: number
  /** The boundary it covers, for display. */
  readonly boundary: string
}

/** What a run is doing now. */
export interface ProgressDocument {
  /** The schema id and version. */
  readonly schema: typeof PROGRESS_SCHEMA
  /** The run's id. */
  readonly run_id: string
  /** The run's terminal state, or `in_progress`. */
  readonly status: string
  /** The phase the skill is in. */
  readonly stage: string
  /** The current hunting wave. */
  readonly wave: number
  /** When this document was written, ISO 8601 UTC. */
  readonly written_at: string
  /** Units by state. */
  readonly counts: ProgressCounts
  /** Units a role is working on now. */
  readonly in_progress: readonly ProgressUnit[]
  /** Agent invocations spent. */
  readonly spent: number
  /** The run's budget, or null when it has none. */
  readonly budget: number | null
  /** Invocations left, or null when the budget is unlimited. */
  readonly remaining: number | null
  /** Candidates awaiting validation. */
  readonly candidates_pending: number
  /** Confirmed findings so far. */
  readonly findings_confirmed: number
  /** Findings that need a fact from outside the source. */
  readonly findings_needs_validation: number
}

/**
 * Count the units in each state.
 * @param units - the ledger.
 * @returns the counts, with every state present.
 */
export function progressCounts(units: readonly { readonly status: string }[]): ProgressCounts {
  const counts = { planned: 0, in_progress: 0, covered: 0, candidate: 0, blocked: 0, deferred: 0, out_of_scope: 0, not_applicable: 0 }
  for (const unit of units) {
    if (unit.status in counts) counts[unit.status as keyof ProgressCounts] += 1
  }
  return counts
}

/**
 * Whether a value is a progress document this version can read.
 * @param value - the parsed file.
 * @returns whether it carries this schema id and the fields a reader needs.
 */
export function isProgressDocument(value: unknown): value is ProgressDocument {
  if (typeof value !== 'object' || value === null) return false
  const record = value as Record<string, unknown>
  return record.schema === PROGRESS_SCHEMA
    && typeof record.run_id === 'string'
    && typeof record.status === 'string'
    && typeof record.stage === 'string'
    && typeof record.wave === 'number'
    && typeof record.counts === 'object' && record.counts !== null
    && Array.isArray(record.in_progress)
    && typeof record.spent === 'number'
}
