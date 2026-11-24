/**
 * Delorun's additions to the skill's briefs, composed after the verbatim blocks and never replacing them.
 *
 * The vendored skill is generic: it knows nothing about Delorun's threat model, its contracts, its own test suites or
 * the limits it has already accepted. These four layers point a role at that knowledge, so a finding is judged against
 * what Delorun claims to enforce rather than against a generic checklist, and so a deliberate decision is not reported
 * as a defect.
 * @module @delorun/plugin-security-audit/prompts/additions
 */

/** What a role can be told about the target beyond the skill's own text. */
export interface TargetContext {
  /** The threat model's boundary headings, when the target has one. */
  readonly boundaries?: readonly string[]
  /** Paths of the target's own specs that are meant to prove a boundary, when known. */
  readonly specs?: readonly string[]
  /** The target's coding and review rules, when they could be read. */
  readonly rules?: string
  /** Limits the project has already accepted, one line each. */
  readonly accepted?: readonly string[]
}

/**
 * The claims-versus-enforcement layer: a candidate is real only where the code fails to enforce what the project says
 * it enforces.
 * @returns the section.
 */
export function claimsSection(): string {
  return [
    '## What counts as a finding here',
    '',
    'This project states what it enforces: a threat model, contracts, READMEs and a trust page. A candidate is real only',
    'where the code fails to enforce a claim the project makes, or enforces something weaker than it states. A missing',
    'best practice that the project never claimed is not a finding; say so under hardening instead.',
    '',
    'For each candidate, name the claim it breaks and where that claim is written. A candidate whose claim you cannot',
    'locate is a hardening note, not a finding.',
  ].join('\n')
}

/**
 * The tests-as-evidence layer: the spec that should prove a boundary is itself in scope.
 * @param specs - the spec paths known to prove boundaries, when any.
 * @returns the section.
 */
export function testsSection(specs: readonly string[] | undefined): string {
  const lines = [
    '## The project\'s own tests are evidence',
    '',
    'Each boundary names the spec that is supposed to prove it. Read that spec. A spec that is missing, skipped,',
    'asserts the wrong thing, or asserts only the happy path is itself reportable: the boundary is then unproven,',
    'whatever the code appears to do.',
  ]
  if (specs !== undefined && specs.length > 0) {
    lines.push('', 'Specs known to prove boundaries in this target:', ...specs.map(spec => '- ' + spec))
  }
  return lines.join('\n')
}

/**
 * The project-rules layer, so a proposed fix lands in house style and a deliberate decision is not flagged.
 * @param rules - the target's rules, when they could be read.
 * @returns the section, or an empty string when there are no rules to state.
 */
export function rulesSection(rules: string | undefined): string {
  if (rules === undefined || rules.trim() === '') return ''
  return [
    '## How this project wants changes made',
    '',
    'Propose fixes in this style. Where a rule below explains why something is the way it is, that is a deliberate',
    'decision, not a defect.',
    '',
    rules.trim(),
  ].join('\n')
}

/**
 * The suppression layer: limits the project has already accepted, so they are not reported again as new findings.
 * @param accepted - the accepted limits, one line each.
 * @returns the section, or an empty string when nothing has been accepted.
 */
export function acceptedSection(accepted: readonly string[] | undefined): string {
  if (accepted === undefined || accepted.length === 0) return ''
  return [
    '## Already accepted',
    '',
    'These limits are known and accepted. Do not report them as findings. If one has changed in a way that makes it',
    'worse than stated, report that difference and cite the line that states it.',
    '',
    ...accepted.map(entry => '- ' + entry),
  ].join('\n')
}

/**
 * Every addition that applies to a target, in the order a brief carries them.
 * @param context - what is known about the target.
 * @returns the sections, each separated by a blank line, with the empty ones dropped.
 */
export function targetSections(context: TargetContext): string {
  return [
    claimsSection(),
    testsSection(context.specs),
    rulesSection(context.rules),
    acceptedSection(context.accepted),
  ].filter(section => section !== '').join('\n\n')
}
