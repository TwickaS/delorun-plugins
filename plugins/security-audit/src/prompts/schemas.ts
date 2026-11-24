/**
 * The `outputSchema` of each delegated role, in the harness's enforced JSON
 * Schema subset. The schema fixes each result's fields and enums; the skill's
 * full record rules, which that subset cannot express, run in the validation
 * gate before a result reaches shared state. The prompt carries the same
 * contract verbatim, so a child sees the rules and the tool enforces them.
 * @module @delorun/plugin-security-audit/prompts/schemas
 */
import type { JsonSchemaNode, ObjectJsonSchema } from '@deepseek-ai/dsh-tools'

const strings: JsonSchemaNode = { type: 'array', items: { type: 'string' } }
const anyObject: JsonSchemaNode = { type: 'object' }

/** A recon agent's source facts. */
export const RECON_RESULT: ObjectJsonSchema = {
  type: 'object',
  additionalProperties: false,
  required: ['facts', 'gaps'],
  properties: {
    facts: {
      type: 'array',
      description: 'One entry per fact, grouped by the numbered item of the brief it answers.',
      items: {
        type: 'object',
        additionalProperties: false,
        required: ['item', 'fact', 'refs'],
        properties: {
          item: { type: 'string', description: 'The brief item it answers, such as "1" or "Entry surfaces".' },
          fact: { type: 'string' },
          refs: { ...strings, description: 'Repository-relative file:line references that establish the fact.' },
        },
      },
    },
    gaps: { ...strings, description: 'What the source could not establish, and why.' },
  },
} satisfies ObjectJsonSchema

const check: ObjectJsonSchema = {
  type: 'object',
  additionalProperties: false,
  required: ['agent_id', 'reviewed_paths', 'invariant', 'method', 'result', 'artifact'],
  properties: {
    agent_id: { type: 'string' },
    reviewed_paths: strings,
    invariant: { type: 'string' },
    method: { type: 'string', enum: ['source', 'local'] },
    result: { type: 'string' },
    artifact: { oneOf: [{ type: 'string' }, { type: 'null' }] },
  },
}

const proposedUnit: ObjectJsonSchema = {
  type: 'object',
  additionalProperties: false,
  required: ['surface', 'boundary', 'subsystem', 'attack_class', 'starting_paths', 'reason'],
  properties: {
    surface: { type: 'string' },
    boundary: { type: 'string' },
    subsystem: { type: 'string' },
    attack_class: { type: 'string' },
    starting_paths: strings,
    reason: { type: 'string' },
  },
}

/** A hunter's structured result (HUNTING.md, Structured hunter result). */
export const HUNTER_RESULT: ObjectJsonSchema = {
  type: 'object',
  additionalProperties: false,
  required: ['units', 'candidates', 'hardening', 'uncovered'],
  properties: {
    units: {
      type: 'array',
      items: {
        type: 'object',
        additionalProperties: false,
        required: ['coverage_id', 'disposition', 'reviewed_paths', 'checks', 'candidate_fingerprints', 'unresolved'],
        properties: {
          coverage_id: { type: 'string' },
          disposition: { type: 'string', enum: ['covered', 'candidate', 'blocked'] },
          reviewed_paths: strings,
          checks: { type: 'array', items: check },
          candidate_fingerprints: strings,
          unresolved: strings,
        },
      },
    },
    candidates: {
      type: 'array',
      description: 'Schema-shaped records with proposed_verdict in place of verdict; the gate checks them against report-schema.json.',
      items: anyObject,
    },
    hardening: strings,
    uncovered: { type: 'array', items: proposedUnit },
  },
} satisfies ObjectJsonSchema

/** A candidate verifier's decision (VALIDATION-AND-REPORTING.md, Phase 3). */
export const VERIFIER_RESULT: ObjectJsonSchema = {
  type: 'object',
  additionalProperties: false,
  required: ['decision', 'record', 'checks'],
  properties: {
    decision: { type: 'string', enum: ['confirmed', 'needs_validation', 'rejected'] },
    record: { ...anyObject, description: 'Exactly the report-schema.json branch of the decision.' },
    checks: {
      type: 'array',
      description: 'The verifier-owned checks that establish this decision. May be empty only when the record has no local evidence.',
      items: check,
    },
  },
} satisfies ObjectJsonSchema

/** A final record verifier's decision (VALIDATION-AND-REPORTING.md, Phase 5). */
export const FINAL_VERIFIER_RESULT: ObjectJsonSchema = {
  type: 'object',
  additionalProperties: false,
  required: ['decision', 'fingerprint'],
  properties: {
    decision: { type: 'string', enum: ['verified', 'replace'] },
    fingerprint: { type: 'string' },
    reason: { type: 'string', description: 'Required with replace.' },
    record: { ...anyObject, description: 'Required with replace: the full replacement record.' },
  },
} satisfies ObjectJsonSchema

/** A coverage critic's result (HUNTING.md, Coverage-critic waves). */
export const CRITIC_RESULT: ObjectJsonSchema = {
  type: 'object',
  additionalProperties: false,
  required: ['missing_units', 'reassign_ids', 'resolved_prior_leads', 'stop'],
  properties: {
    missing_units: {
      type: 'array',
      items: {
        ...proposedUnit,
        required: [...(proposedUnit.required ?? []), 'selected_companion_blocks', 'excluded_blocks'],
        properties: {
          ...(proposedUnit.properties ?? {}),
          selected_companion_blocks: strings,
          excluded_blocks: {
            type: 'array',
            items: {
              type: 'object',
              additionalProperties: false,
              required: ['block', 'reason'],
              properties: { block: { type: 'string' }, reason: { type: 'string' } },
            },
          },
        },
      },
    },
    reassign_ids: strings,
    resolved_prior_leads: strings,
    stop: { type: 'boolean' },
  },
} satisfies ObjectJsonSchema
