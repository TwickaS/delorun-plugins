/**
 * The denial test each high or critical finding must carry.
 *
 * The vendored skill's `findings.json` schema is upstream's and is strict: a record carries exactly the fields the
 * skill defines, so a denial test cannot be added to a record without editing the schema, which this plugin never
 * does. Instead a run keeps its denial tests in their own file, keyed by fingerprint, and the gate refuses a run whose
 * high or critical findings lack one. A finding without a test that would fail before its fix is a claim, not a
 * defence, and this project's rule is that a security change carries proof.
 *
 * A record's severity is the schema's object (`{ likelihood, impact, overall_severity }`), never a bare string, so
 * this module reads it through {@link overallSeverityOf}. Reading `record.severity` as a string silently matched
 * nothing and let every high or critical finding through without a test.
 * @module @delorun/plugin-security-audit/denials
 */

import { overallSeverityOf } from './candidates.ts'
import { type AuditFiles, type RunLocation, DENIALS_FILE, inRun } from './store.ts'

export { DENIALS_FILE } from './store.ts'

/** The severities that require a denial test. */
export const DENIAL_SEVERITIES: readonly string[] = ['high', 'critical']

/** One finding's denial test. */
export interface DenialTest {
  /** The fingerprint of the finding it proves. */
  readonly fingerprint: string
  /** The test's file, repository-relative. */
  readonly file: string
  /** The test's name, as the runner reports it. */
  readonly name: string
  /** The assertion that fails before the fix and passes after it. */
  readonly assertion: string
  /**
   * Whether the role ran it: `proven` when it recorded a failure before the fix and a pass after, `proposal` when the
   * role could not run it in its copy and states the test it would write.
   */
  readonly state: 'proven' | 'proposal'
  /** What the role observed, for a proven test. */
  readonly observed?: string | undefined
}

/**
 * Whether a value is a denial test this version can read.
 * @param value - the parsed entry.
 * @returns whether it carries the fields a reader needs.
 */
export function isDenialTest(value: unknown): value is DenialTest {
  if (typeof value !== 'object' || value === null) return false
  const record = value as Record<string, unknown>
  return typeof record.fingerprint === 'string' && record.fingerprint !== ''
    && typeof record.file === 'string' && record.file !== ''
    && typeof record.name === 'string' && record.name !== ''
    && typeof record.assertion === 'string' && record.assertion !== ''
    && (record.state === 'proven' || record.state === 'proposal')
}

/**
 * The problems with a run's denial tests against its final records.
 *
 * A high or critical confirmed finding needs a test. A test naming a fingerprint no record carries is a problem too:
 * it means the test was written for a finding that was later rejected or reworded, and the proof no longer attaches
 * to anything.
 * @param records - the final records, each with a verdict, a fingerprint and a severity when confirmed.
 * @param tests - the denial tests the run holds.
 * @returns the problems, one per line.
 */
export function denialProblems(
  records: readonly Record<string, unknown>[],
  tests: readonly unknown[],
): string[] {
  const problems: string[] = []
  const byFingerprint = new Map<string, DenialTest>()
  for (const [index, entry] of tests.entries()) {
    if (!isDenialTest(entry)) {
      problems.push(`denial-tests.json entry ${String(index)} needs a fingerprint, file, name, assertion and a state of proven or proposal`)
      continue
    }
    if (byFingerprint.has(entry.fingerprint)) {
      problems.push(`denial-tests.json carries two tests for ${entry.fingerprint}; keep one`)
      continue
    }
    byFingerprint.set(entry.fingerprint, entry)
  }
  const known = new Set<string>()
  for (const record of records) {
    if (typeof record.fingerprint !== 'string') continue
    known.add(record.fingerprint)
    if (record.verdict !== 'confirmed') continue
    const severity = overallSeverityOf(record)
    if (!DENIAL_SEVERITIES.includes(severity)) continue
    if (!byFingerprint.has(record.fingerprint)) {
      problems.push(`the ${severity} finding ${record.fingerprint} has no denial test; add one to denial-tests.json, or lower its severity with the evidence that justifies it`)
    }
  }
  for (const fingerprint of byFingerprint.keys()) {
    if (!known.has(fingerprint)) {
      problems.push(`denial-tests.json names ${fingerprint}, which no final record carries; remove it or restore the record`)
    }
  }
  return problems
}

/**
 * The problems with one denial test on its own, before it is stored.
 *
 * A test is only proof when it names the finding it proves, the file and the test name a reader can run, the assertion
 * that fails before the fix and passes after it, and whether the role actually ran it. A `proven` test also states
 * what it observed, because "it passed" is not an observation.
 * @param test - the test as the coordinator supplied it.
 * @returns the problems, one per line.
 */
export function denialTestProblems(test: unknown): string[] {
  if (!isDenialTest(test)) {
    return ['a denial test needs a fingerprint, file, name, assertion and a state of proven or proposal']
  }
  const problems: string[] = []
  if (test.state === 'proven' && (test.observed === undefined || test.observed.trim() === '')) {
    problems.push('a proven denial test states what it observed: the failure before the fix and the pass after it')
  }
  return problems
}

/**
 * Store one denial test for a finding, replacing any test already held for the same fingerprint.
 *
 * The coordinator calls this once per high or critical finding it confirms. `audit_finalize` refuses the run while a
 * high or critical finding has no test here, so this is the only way such a finding reaches the report.
 * @param files - file access.
 * @param run - the run.
 * @param test - the test to store.
 * @returns the tests now held, in fingerprint order.
 * @throws {Error} with every problem the test has.
 */
export async function writeDenialTest(files: AuditFiles, run: RunLocation, test: unknown): Promise<DenialTest[]> {
  const problems = denialTestProblems(test)
  if (problems.length > 0) throw new Error('the denial test is not usable:\n' + problems.join('\n'))
  const stored = test as DenialTest
  const existing = await readDenialTests(files, run)
  const kept = existing.filter(entry => entry.fingerprint !== stored.fingerprint)
  const next = [...kept, stored].sort((left, right) => left.fingerprint < right.fingerprint ? -1 : left.fingerprint > right.fingerprint ? 1 : 0)
  await files.writeJson(inRun(run, DENIALS_FILE), next)
  return next
}

/**
 * Read a run's denial tests as the typed entries the gate reads.
 * @param files - file access.
 * @param run - the run.
 * @returns the tests the run holds, or an empty list when it holds none.
 * @throws {Error} when the file is present and is not a top-level array.
 */
export async function readDenialTests(files: AuditFiles, run: RunLocation): Promise<DenialTest[]> {
  const value = await files.readJson(inRun(run, DENIALS_FILE))
  if (value === undefined) return []
  if (!Array.isArray(value)) throw new Error(`${DENIALS_FILE} must hold a top-level array`)
  return value.filter(isDenialTest)
}
