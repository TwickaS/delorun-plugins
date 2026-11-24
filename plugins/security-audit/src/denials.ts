/**
 * The denial test each high or critical finding must carry.
 *
 * The vendored skill's `findings.json` schema is upstream's and is strict: a record carries exactly the fields the
 * skill defines, so a denial test cannot be added to a record without editing the schema, which this plugin never
 * does. Instead a run keeps its denial tests in their own file, keyed by fingerprint, and the gate refuses a run whose
 * high or critical findings lack one. A finding without a test that would fail before its fix is a claim, not a
 * defence, and this project's rule is that a security change carries proof.
 * @module @delorun/plugin-security-audit/denials
 */

/** The file a run keeps its denial tests in, beside the other shared run files. */
export const DENIALS_FILE = 'denial-tests.json'

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
  records: readonly { readonly verdict?: unknown, readonly fingerprint?: unknown, readonly severity?: unknown }[],
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
    if (typeof record.severity !== 'string' || !DENIAL_SEVERITIES.includes(record.severity)) continue
    if (!byFingerprint.has(record.fingerprint)) {
      problems.push(`the ${record.severity} finding ${record.fingerprint} has no denial test; add one to denial-tests.json, or lower its severity with the evidence that justifies it`)
    }
  }
  for (const fingerprint of byFingerprint.keys()) {
    if (!known.has(fingerprint)) {
      problems.push(`denial-tests.json names ${fingerprint}, which no final record carries; remove it or restore the record`)
    }
  }
  return problems
}
