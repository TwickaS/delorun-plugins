/**
 * The roles whose model and reasoning effort a run can choose separately, and the
 * brief kinds each one covers.
 *
 * This module imports nothing at runtime, so the host half (the configuration,
 * intake and delegation) and the studio half (the composer strip and the start
 * message) read one list. A role the strip offers is therefore a role intake
 * accepts: the two halves cannot drift apart, and adding a role is one edit that
 * the compiler then demands copy and a route for.
 * @module delorun-plugin-security-audit/roles
 */
import type { BriefKind } from './types.ts'

/** The roles whose model can be chosen separately; the coordinator uses the chat's. */
export const MODELED_ROLES = ['recon', 'hunter', 'verifier', 'critic'] as const

/** One role with its own model choice. */
export type ModeledRole = typeof MODELED_ROLES[number]

/** The reasoning efforts a role can be given; an unset effort inherits the chat's. */
export const REASONING_EFFORTS = ['off', 'low', 'high', 'max'] as const

/** One reasoning effort a role can be given. */
export type ReasoningEffort = typeof REASONING_EFFORTS[number]

/**
 * Which modeled role each brief kind runs as. The record is exhaustive over
 * {@link BriefKind}, so a new brief kind fails to compile until it names its role.
 */
export const MODELED_ROLE_OF: Readonly<Record<BriefKind, ModeledRole>> = {
  recon: 'recon',
  hunt: 'hunter',
  verify: 'verifier',
  'final-verify': 'verifier',
  critique: 'critic',
  'final-critique': 'critic',
}

/**
 * The role whose route a delegated brief uses.
 * @param kind - the brief kind.
 * @returns the modeled role.
 */
export function modeledRoleOf(kind: BriefKind): ModeledRole {
  return MODELED_ROLE_OF[kind]
}
