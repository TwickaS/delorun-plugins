/**
 * The skill's cost budget, applied as a strict gate before work is assigned.
 * One unit is roughly one hunter assignment, and one surviving candidate is one
 * or two verifier assignments (SKILL.md, Cost budget). Every function here is
 * pure, so the intake, the delegation gate and the pane share one accounting and
 * a set budget is never exceeded silently.
 * @module @delorun/plugin-security-audit/budget
 */
import type { AuditProfile } from './types.ts'

/** The four baseline reconnaissance calls RECONNAISSANCE.md defines. */
export const BASELINE_RECONNAISSANCE = 4

/**
 * A run's reason for stopping short, spelled exactly as the skill spells it, so
 * `run-metadata.json` carries the skill's own words.
 */
export type BudgetReason =
  | 'budget_cannot_fund_reconnaissance_and_reserves'
  | 'budget_cannot_reserve_critics_and_validation'
  | 'critic_budget_exhausted'
  | 'validation_budget_exhausted'
  | 'quick_profile_final_critic'

/**
 * How many critic calls one hunter wave requires.
 * @param profile - the run's profile.
 * @returns the immediate post-wave critic calls and the distinct final-clean calls.
 */
export function criticCalls(profile: AuditProfile): { readonly wave: number; readonly finalClean: number } {
  return profile === 'quick' ? { wave: 1, finalClean: 0 } : { wave: 1, finalClean: 1 }
}

/** Agent calls held back before hunting starts. */
export interface Reservation {
  /** The reconnaissance calls the gate funds, baseline and focused together. */
  readonly reconnaissance: number
  /** The immediate post-wave critic calls held back for the coming wave. */
  readonly waveCritic: number
  /** The distinct final-clean critic calls, which a quick run does not have. */
  readonly finalClean: number
  /** The verifier calls held back for candidate validation and record verification. */
  readonly validation: number
  /** The sum held back, which a hunter assignment may never touch. */
  readonly total: number
}

/**
 * The verifier reserve: about one or two agents per expected candidate, and 30
 * per cent of the remaining balance when the candidate count is unknown.
 * @param profile - the run's profile; `deep` keeps two verifiers per candidate.
 * @param candidates - the expected candidate count, or `undefined` before hunting.
 * @param balance - the agent calls left after the critic reserve.
 * @returns the verifier calls to hold back, at least one.
 */
export function validationReserve(profile: AuditProfile, candidates: number | undefined, balance: number): number {
  if (candidates !== undefined && candidates > 0) {
    return Math.max(1, candidates * (profile === 'deep' ? 2 : 1))
  }
  return Math.max(1, Math.ceil(Math.max(0, balance) * 0.3))
}

/**
 * The calls a run holds back before it assigns any hunter.
 * @param profile - the run's profile.
 * @param validation - the verifier reserve.
 * @param reconnaissance - the reconnaissance calls the gate funds.
 * @returns the reservation.
 */
export function reservationFor(profile: AuditProfile, validation: number, reconnaissance = BASELINE_RECONNAISSANCE): Reservation {
  const critics = criticCalls(profile)
  const total = reconnaissance + critics.wave + critics.finalClean + validation
  return { reconnaissance, waveCritic: critics.wave, finalClean: critics.finalClean, validation, total }
}

/** The pre-reconnaissance gate's verdict. */
export interface ReconnaissanceGate {
  /** Whether the budget funds reconnaissance, the critics and one verifier. */
  readonly ok: boolean
  /** Why the gate refuses, when it does. */
  readonly reason?: BudgetReason
  /** What the run holds back. */
  readonly reservation: Reservation
  /** The agent calls left after spending. */
  readonly remaining: number
  /** What hunting may spend, or `null` when no budget is set. */
  readonly huntingAllowance: number | null
}

/**
 * The strict pre-reconnaissance gate (SKILL.md, Cost budget). Reserve the four
 * baseline reconnaissance calls, the post-wave critics, the final-clean critic
 * and at least one verifier before launching any reconnaissance agent.
 * @param input - the profile, the set budget, what the run already spent, any focused reconnaissance calls, and the expected candidates.
 * @returns the verdict, the reservation and the hunting allowance.
 */
export function reconnaissanceGate(input: {
  readonly profile: AuditProfile
  readonly budget: number | null
  readonly spent: number
  readonly focusedCalls?: number
  readonly candidates?: number
}): ReconnaissanceGate {
  const reconnaissance = BASELINE_RECONNAISSANCE + Math.max(0, input.focusedCalls ?? 0)
  const remaining = input.budget === null ? Number.POSITIVE_INFINITY : input.budget - input.spent
  const validation = validationReserve(input.profile, input.candidates, remaining - reconnaissance)
  const reservation = reservationFor(input.profile, validation, reconnaissance)
  if (input.budget === null) return { ok: true, reservation, remaining, huntingAllowance: null }
  if (remaining < reservation.total) {
    return { ok: false, reason: 'budget_cannot_fund_reconnaissance_and_reserves', reservation, remaining, huntingAllowance: 0 }
  }
  return { ok: true, reservation, remaining, huntingAllowance: remaining - reservation.total }
}

/** The verdict before one hunter wave. */
export interface WaveGate {
  /** The hunter assignments this wave can fund. */
  readonly hunters: number
  /** The hunter assignments the coordinator asked for. */
  readonly requested: number
  /** What the wave holds back. */
  readonly reservation: Reservation
  /** The agent calls left after spending. */
  readonly remaining: number
  /** Why no hunter may start, when none may. */
  readonly stop?: BudgetReason
}

/**
 * The gate before one hunter wave: reserve the wave's own post-wave critic, the
 * retained final-clean critic and the verifier reserve, then spend what is left
 * on hunters (SKILL.md, Cost budget, steps 2 and 4).
 * @param input - the profile, the set budget, what the run spent, the hunters wanted, and the expected candidates.
 * @returns the affordable hunter count and, when none fits, the reason to defer.
 */
export function waveGate(input: {
  readonly profile: AuditProfile
  readonly budget: number | null
  readonly spent: number
  readonly requested: number
  readonly candidates?: number
}): WaveGate {
  const critics = criticCalls(input.profile)
  const remaining = input.budget === null ? Number.POSITIVE_INFINITY : input.budget - input.spent
  const afterCritics = remaining - critics.wave - critics.finalClean
  if (afterCritics < 1) {
    const reason: BudgetReason = remaining < critics.wave + critics.finalClean ? 'critic_budget_exhausted' : 'budget_cannot_reserve_critics_and_validation'
    return { hunters: 0, requested: input.requested, reservation: reservationFor(input.profile, 0), remaining, stop: reason }
  }
  const validation = validationReserve(input.profile, input.candidates, afterCritics)
  const reservation = reservationFor(input.profile, validation, 0)
  const allowance = afterCritics - validation
  if (allowance < 1) {
    return { hunters: 0, requested: input.requested, reservation, remaining, stop: 'budget_cannot_reserve_critics_and_validation' }
  }
  return { hunters: Math.min(input.requested, Math.floor(allowance)), requested: input.requested, reservation, remaining }
}

/** The verdict for candidate validation. */
export interface ValidationGate {
  /** The candidates that may be validated now. */
  readonly canValidate: number
  /** The candidates left without a verifier, in fingerprint order. */
  readonly unvalidated: number
  /** Why validation stops short, when it does. */
  readonly stop?: BudgetReason
}

/**
 * The gate for validation: a set budget never grows to fit an unexpectedly
 * large candidate set, so the remainder is validated in fingerprint order and
 * the rest stay unresolved ledger candidates (SKILL.md, Cost budget).
 * @param input - the set budget, what the run spent, and how many candidates await validation.
 * @returns how many may be validated and how many remain.
 */
export function validationGate(input: { readonly budget: number | null; readonly spent: number; readonly candidates: number }): ValidationGate {
  if (input.budget === null) return { canValidate: input.candidates, unvalidated: 0 }
  const remaining = Math.max(0, input.budget - input.spent)
  const canValidate = Math.min(input.candidates, remaining)
  const unvalidated = input.candidates - canValidate
  return { canValidate, unvalidated, ...unvalidated > 0 ? { stop: 'validation_budget_exhausted' as const } : {} }
}

/**
 * Propose a budget from the target's size when the person set none. A hunter
 * owns closely related units, one wave holds about four hunters, and each
 * candidate needs a verifier and usually a record verifier.
 * @param input - the profile, the seeded unit count and the candidates already known.
 * @returns the proposed maximum agent calls.
 */
export function proposeBudget(input: { readonly profile: AuditProfile; readonly units: number; readonly candidates?: number }): number {
  const hunters = Math.max(1, Math.ceil(input.units / 3))
  const waves = Math.max(1, Math.ceil(hunters / 4))
  const critics = waves * (input.profile === 'quick' ? 1 : 2)
  const validation = Math.max(2, Math.ceil((input.candidates ?? hunters * 0.6) * 1.5))
  return BASELINE_RECONNAISSANCE + hunters + critics + validation
}

/**
 * State a budget in plain words for the intake summary.
 * @param input - the set or proposed budget, what it funds and whether it covers the plan.
 * @returns one sentence, or `undefined` when no budget applies.
 */
export function budgetSummary(input: {
  readonly budget: number | null
  readonly gateway: ReconnaissanceGate
  readonly proposed: boolean
}): string | undefined {
  if (input.budget === null) return undefined
  const { reservation, huntingAllowance } = input.gateway
  const source = input.proposed ? 'proposed from the target\u2019s size' : 'set by the person'
  if (!input.gateway.ok) {
    return `The budget of ${input.budget} agent calls, ${source}, cannot fund the four reconnaissance calls, ${reservation.waveCritic + reservation.finalClean} critic calls and one verifier (${reservation.total} in all). Raise the budget, narrow the scope or choose a coarser profile.`
  }
  const hunting = huntingAllowance === null ? 'an unlimited number of hunters' : `${huntingAllowance} hunter assignments`
  return `The budget of ${input.budget} agent calls, ${source}, funds ${reservation.reconnaissance} reconnaissance calls, ${reservation.waveCritic + reservation.finalClean} critic calls, ${reservation.validation} verifier calls and ${hunting}.`
}
