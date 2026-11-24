/**
 * The start message the composer strip writes, and the same message the pane's
 * empty state offers. One builder keeps the two surfaces saying the same thing.
 *
 * The message states every role's effective route, so the person sees what the
 * run will spend before sending it: a role with its own model names its provider,
 * model and reasoning effort, a role with only an effort names that, and a role
 * with neither says it uses this chat's model. The roles come from `../roles.ts`,
 * the one list the strip, this builder, intake's validator and the delegation
 * layer all read.
 * @module delorun-plugin-security-audit/client/start-message
 */
import type { TranslateNS } from '@deepseek-ai/dsh-client-locale/client'
import { MODELED_ROLES, type ModeledRole, type ReasoningEffort } from '../roles.ts'
import { RUNS_DIRECTORY } from './runs.ts'
import type { NS } from './locales.ts'

export { MODELED_ROLES, type ModeledRole, type ReasoningEffort } from '../roles.ts'

/** The audit profiles the skill defines. */
export type AuditProfile = 'quick' | 'standard' | 'deep'

/** When the coordinator may interrupt an unattended run. */
export type CheckIn = 'straight_through' | 'after_recon' | 'every_stage'

/**
 * A model route one role runs on. Every field is optional because a role can be
 * given a model, an effort, or both: a field left out inherits the chat's, so a
 * role with only an effort runs this chat's model at that effort.
 */
export interface RoleModel {
  /** The provider id. */
  readonly provider?: string
  /** The model id within that provider. */
  readonly model?: string
  /** The model's display name, for the strip and the start message. */
  readonly label?: string
  /** The reasoning effort this role runs at, or absent for this chat's effort. */
  readonly effort?: ReasoningEffort
}

/** Every choice the start message states. */
export interface StartMessageInput {
  /** The workspace the audit targets, when the chat reports one. */
  readonly target: string | undefined
  /** The chosen profile. */
  readonly profile: AuditProfile
  /** Whether the RC profile is on, which seeds coverage from the threat model's boundaries. */
  readonly rc?: boolean
  /** The maximum agent invocations, or `null` for no limit. */
  readonly budget: number | null
  /** The chosen check-in timing. */
  readonly checkIn: CheckIn
  /** The role routes chosen; a missing role inherits the chat's model. */
  readonly models: Partial<Record<ModeledRole, RoleModel>>
}

/** The translate seat, bound to this plugin's namespace. */
type Translate = TranslateNS<typeof NS>

/**
 * The name the person reads for one role.
 * @param t - the namespace-bound translate seat.
 * @param role - the role.
 * @returns its name.
 */
export function roleName(t: Translate, role: ModeledRole): string {
  return {
    recon: t('strip.role.recon'),
    hunter: t('strip.role.hunter'),
    verifier: t('strip.role.verifier'),
    critic: t('strip.role.critic'),
  }[role]
}

/**
 * The name the person reads for one reasoning effort.
 * @param t - the namespace-bound translate seat.
 * @param effort - the effort.
 * @returns its name.
 */
export function effortName(t: Translate, effort: ReasoningEffort): string {
  return {
    off: t('strip.models.effort.off'),
    low: t('strip.models.effort.low'),
    high: t('strip.models.effort.high'),
    max: t('strip.models.effort.max'),
  }[effort]
}

/**
 * State one role's effective route: its own model and effort, its own effort on
 * this chat's model, or this chat's model when it has no choice of its own.
 * @param t - the namespace-bound translate seat.
 * @param route - the role's choice, when it has one.
 * @returns the route as one line of the message.
 */
export function routeText(t: Translate, route: RoleModel | undefined): string {
  const effort = route?.effort === undefined ? t('strip.models.effort.chat') : effortName(t, route.effort)
  if (route?.provider === undefined || route.model === undefined) {
    return route?.effort === undefined
      ? t('strip.models.chat')
      : t('strip.models.routeChat', { effort })
  }
  return t('strip.models.route', { model: route.provider + '/' + route.model, effort })
}

/**
 * The role choices in the shape `audit_init` reads, so the coordinator passes
 * exactly what the person chose.
 * @param models - the role routes chosen.
 * @returns the JSON object, or `null` when no role has a choice of its own.
 */
export function modelsJson(models: Partial<Record<ModeledRole, RoleModel>>): string | null {
  const value: Record<string, Record<string, string>> = {}
  for (const role of MODELED_ROLES) {
    const route = models[role]
    if (route === undefined) continue
    const fields: Record<string, string> = {}
    if (route.provider !== undefined && route.model !== undefined) {
      fields.provider = route.provider
      fields.model = route.model
    }
    if (route.effort !== undefined) fields.reasoningEffort = route.effort
    if (Object.keys(fields).length > 0) value[role] = fields
  }
  return Object.keys(value).length === 0 ? null : JSON.stringify(value)
}

/**
 * Build the start message.
 * @param t - the namespace-bound translate seat.
 * @param input - the person's choices.
 * @returns the message, ready for the message box.
 */
export function buildStartMessage(t: Translate, input: StartMessageInput): string {
  const budget = input.budget === null ? t('strip.budget.none') : t('strip.budget.value', { n: input.budget })
  const checkIn = {
    straight_through: t('strip.checkIn.straight_through'),
    after_recon: t('strip.checkIn.after_recon'),
    every_stage: t('strip.checkIn.every_stage'),
  }[input.checkIn]
  const rc = input.rc === true
  const profile = rc
    ? t('strip.profile.rc')
    : {
      quick: t('strip.profile.quick'),
      standard: t('strip.profile.standard'),
      deep: t('strip.profile.deep'),
    }[input.profile]
  const seed = rc ? t('strip.seed.rc') : t('strip.seed.reconnaissance')
  const lines = MODELED_ROLES
    .map(role => t('strip.models.line', { role: roleName(t, role), route: routeText(t, input.models[role]) }))
  // The same choices in the shape audit_init reads, so the coordinator passes
  // exactly what the person chose rather than re-deriving it from the prose.
  const json = modelsJson(input.models)
  const models = json === null ? lines.join('\n') : [...lines, t('strip.models.json', { json })].join('\n')
  return t('strip.message', {
    target: input.target ?? '.',
    profile,
    seed,
    budget,
    checkIn,
    models,
    runs: RUNS_DIRECTORY,
  })
}
