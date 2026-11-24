/**
 * The start message the composer strip writes, and the same message the pane's
 * empty state offers. One builder keeps the two surfaces saying the same thing.
 * @module @delorun/plugin-security-audit/client/start-message
 */
import type { TranslateNS } from '@deepseek-ai/dsh-client-locale/client'
import { RUNS_DIRECTORY } from './runs.ts'
import type { NS } from './locales.ts'

/** The audit profiles the skill defines. */
export type AuditProfile = 'quick' | 'standard' | 'deep'

/** When the coordinator may interrupt an unattended run. */
export type CheckIn = 'straight_through' | 'after_recon' | 'every_stage'

/** The roles whose model can be chosen separately, as the skill's budget counts them. */
export const MODELED_ROLES = ['recon', 'hunter', 'verifier', 'critic'] as const

/** One role with its own model choice. */
export type ModeledRole = typeof MODELED_ROLES[number]

/** A model route one role runs on, with the name the person sees. */
export interface RoleModel {
  /** The provider id. */
  readonly provider: string
  /** The model id within that provider. */
  readonly model: string
  /** The model's display name. */
  readonly label: string
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
  const roles = {
    recon: t('strip.role.recon'),
    hunter: t('strip.role.hunter'),
    verifier: t('strip.role.verifier'),
    critic: t('strip.role.critic'),
  }
  const chosen = MODELED_ROLES.flatMap(role => {
    const route = input.models[role]
    return route === undefined ? [] : [`${roles[role]} — ${route.label}`]
  })
  const models = chosen.length === 0 ? t('strip.models.chat') : chosen.join('; ')
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