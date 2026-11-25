/**
 * `audit_ledger`: the deterministic coverage ledger as the coordinator operates
 * it. Every action writes through the skill's own ledger validator, so a
 * malformed or non-canonical ledger never reaches disk.
 * @module delorun-plugin-security-audit/tools/ledger
 */
import type { Context } from '@deepseek-ai/cordis'
import type { Agent } from '@deepseek-ai/dsh-agent'
import { defineTool } from '@deepseek-ai/dsh-tools'
import type { ToolRunContext } from '@deepseek-ai/dsh-tools'
import type { Config } from '../config.ts'
import { closeUnits, patchUnit, reassignUnits, seedUnits, statusCounts, validateLedger, type LedgerUnit, type UnitSeed } from '../ledger.ts'
import { readCandidates } from '../candidates.ts'
import { writeLedger, writeRunMetadata } from '../report.ts'
import { requireMutable, runContext, type RunContext } from '../run-context.ts'
import { updateState } from '../store.ts'
import type { PriorStatus, UnitStatus } from '../types.ts'
import { jsonArray, jsonObject, type Json } from './json.ts'

const UNIT_STATUS = ['covered', 'candidate', 'blocked', 'deferred', 'out_of_scope', 'not_applicable'] as const
const PRIOR_STATUS = ['new', 'prior_confirmed_same_source', 'prior_confirmed_changed_source', 'prior_needs_validation', 'prior_deferred', 'prior_blocked', 'prior_out_of_scope', 'prior_covered_same_source', 'prior_covered_changed_source', 'prior_rejected_claim_changed', 'none'] as const

/** One block a seed considered and left out. */
interface ExcludedBlockArg {
  readonly block: string
  readonly reason: string
}

/** One unit seed as the tool receives it. */
interface SeedArg {
  readonly surface: string
  readonly boundary: string
  readonly subsystem: string
  readonly attack_class: string
  readonly lifecycle?: string
  readonly starting_paths: readonly string[]
  readonly ordinary_attack_class_block?: string
  readonly selected_companion_blocks: readonly string[]
  readonly excluded_blocks: readonly ExcludedBlockArg[]
  readonly prior_status?: PriorStatus
}

const seedUnit = {
  type: 'object',
  additionalProperties: false,
  properties: {
    surface: { type: 'string', required: true, description: 'The entry surface, as a person reads it.' },
    boundary: { type: 'string', required: true, description: 'The trust boundary, as a person reads it.' },
    subsystem: { type: 'string', required: true, description: 'The subsystem, as a person reads it.' },
    attack_class: { type: 'string', required: true, description: 'The attack class, as a person reads it.' },
    lifecycle: { type: 'string', description: 'The lifecycle mode, when the profile makes one material.' },
    starting_paths: { type: 'array', required: true, items: { type: 'string' }, description: 'Repository-relative paths a hunter starts from.' },
    ordinary_attack_class_block: { type: 'string', description: 'The ordinary attack-class block reference, or omitted when none applies.' },
    selected_companion_blocks: { type: 'array', required: true, items: { type: 'string' }, description: 'The companion blocks this unit selects.' },
    excluded_blocks: { type: 'array', required: true, items: { type: 'object', additionalProperties: false, properties: { block: { type: 'string', required: true }, reason: { type: 'string', required: true } } }, description: 'Every block considered and not selected, with the source fact that excludes it.' },
    prior_status: { type: 'string', enum: [...PRIOR_STATUS], description: 'The prior-run state this unit descends from.' },
  },
} as const

/**
 * Write the ledger, mark the run hunting and refresh the pane's metadata.
 * @param context - the run context.
 * @param ledger - the ledger to write.
 * @returns the counts, the added ids and any validator problems.
 */
async function writeApplied(context: RunContext, ledger: readonly LedgerUnit[], added: readonly string[] = []): Promise<{ counts: Record<string, Json>; added: string[]; problems: string[] }> {
  await writeLedger(context.files, context.run, ledger)
  const state = await updateState(context.files, context.run, current => {
    if (current.stage === 'reconnaissance') current.stage = 'hunting'
    return current
  })
  await writeRunMetadata(context.files, context.run, state, ledger, await readCandidates(context.files, context.run))
  return { counts: statusCounts(ledger), added: [...added], problems: validateLedger(ledger) }
}

/**
 * Register `audit_ledger`.
 * @param ctx - the plugin context.
 * @param config - the mounted row's configuration.
 */
export function registerLedgerTool(ctx: Context, config: Config): void {
  ctx.tools.register(defineTool({
    name: 'audit_ledger',
    presentCall: args => ({ card: 'generic', title: 'Audit ledger: ' + args.action, kind: 'other', rawInput: args }),
    description: 'Operate the deterministic coverage ledger: status, list, seed planned units, close units without evidence, reassign evidence-bearing units a critic reopened, or validate. Only planned units can be delegated.',
    parameters: {
      action: { type: 'string', required: true, enum: ['status', 'list', 'seed', 'close', 'reassign', 'patch', 'validate'], description: 'The ledger operation.' },
      units: { type: 'array', items: seedUnit, description: 'Unit seeds for action=seed.' },
      ids: { type: 'array', items: { type: 'string' }, description: 'Coverage ids for close or reassign.' },
      status: { type: 'string', enum: [...UNIT_STATUS], description: 'Closing status for action=close.' },
      reason: { type: 'string', description: 'The reason for close or reassign.' },
      next: { type: 'string', enum: ['planned', 'deferred'], description: 'Live state after reassign; default planned.' },
      filter: { type: 'string', enum: [...UNIT_STATUS, 'all'], description: 'Filter for action=list.' },
      fields: { type: 'object', additionalProperties: true, description: 'Field replacements for action=patch, such as a verifier check or a carried owner.' },
      id: { type: 'string', description: 'The coverage id for action=patch.' },
    },
    output: {
      schema: {
        type: 'object', additionalProperties: false,
        properties: {
          action: { type: 'string', required: true },
          counts: { type: 'object', additionalProperties: true, required: true },
          added: { type: 'array', required: true, items: { type: 'string' } },
          units: { type: 'array', required: true, items: { type: 'object', additionalProperties: true } },
          problems: { type: 'array', required: true, items: { type: 'string' } },
          content: { type: 'string', required: true },
        },
      },
      render: (_args, value) => [{ type: 'text', text: value.content }],
    },
    async execute(args, exec: ToolRunContext) {
      if (exec.agent === undefined) throw new Error('the audit tools need an owning agent session')
      const agent: Agent = exec.agent
      const context = await runContext(ctx, agent, exec.signal, config.runsDir)
      if (args.action !== 'status' && args.action !== 'list' && args.action !== 'validate') requireMutable(context.state)
      const answer = (counts: Record<string, Json>, added: string[], units: readonly Record<string, Json>[], problems: readonly string[]): { action: string; counts: Record<string, Json>; added: string[]; units: Record<string, Json>[]; problems: string[]; content: string } => {
        const lines = [args.action + ': ' + JSON.stringify(counts)]
        if (added.length > 0) lines.push('Added: ' + added.join(', '))
        if (problems.length > 0) lines.push('Problems:\n' + problems.map(problem => '- ' + problem).join('\n'))
        if (units.length > 0) lines.push(JSON.stringify(units, undefined, 2))
        return { action: args.action, counts, added, units: [...units], problems: [...problems], content: lines.join('\n') }
      }
      switch (args.action) {
        case 'status':
          return answer(statusCounts(context.ledger), [], [], validateLedger(context.ledger))
        case 'list': {
          const units = args.filter === undefined || args.filter === 'all' ? context.ledger : context.ledger.filter(unit => unit.status === args.filter)
          return answer(statusCounts(context.ledger), [], jsonArray(units.slice(0, 100)), validateLedger(context.ledger))
        }
        case 'seed': {
          if (args.units === undefined || (args.units as readonly SeedArg[]).length === 0) throw new Error('action=seed needs a non-empty units array')
          const seeds: UnitSeed[] = (args.units as readonly SeedArg[]).map(unit => ({
            canonical_refs: { surface: unit.surface, boundary: unit.boundary, subsystem: unit.subsystem, attack_class: unit.attack_class, ...unit.lifecycle === undefined ? {} : { lifecycle: unit.lifecycle } },
            surface: unit.surface,
            boundary: unit.boundary,
            subsystem: unit.subsystem,
            attack_class: unit.attack_class,
            ...unit.lifecycle === undefined ? {} : { lifecycle: unit.lifecycle },
            starting_paths: unit.starting_paths,
            ordinary_attack_class_block: unit.ordinary_attack_class_block ?? null,
            selected_companion_blocks: unit.selected_companion_blocks,
            excluded_blocks: unit.excluded_blocks,
            ...unit.prior_status === undefined ? {} : { prior_status: unit.prior_status },
          }))
          const result = seedUnits(context.ledger, seeds)
          const applied = await writeApplied(context, result.ledger, result.added)
          return answer(applied.counts, applied.added, [], applied.problems)
        }
        case 'close': {
          if (args.ids === undefined || args.status === undefined || args.reason === undefined) throw new Error('action=close needs ids, status and reason')
          const ledger = closeUnits(context.ledger, args.ids, args.status as 'deferred' | 'out_of_scope' | 'not_applicable', args.reason)
          const applied = await writeApplied(context, ledger)
          return answer(applied.counts, [], [], applied.problems)
        }
        case 'reassign': {
          if (args.ids === undefined || args.reason === undefined) throw new Error('action=reassign needs ids and reason')
          const ledger = reassignUnits(context.ledger, args.ids, args.reason, args.next ?? 'planned')
          const applied = await writeApplied(context, ledger)
          return answer(applied.counts, [], [], applied.problems)
        }
        case 'patch': {
          if (args.id === undefined || args.fields === undefined) throw new Error('action=patch needs id and fields')
          const ledger = patchUnit(context.ledger, args.id, args.fields as Record<string, unknown>)
          const applied = await writeApplied(context, ledger)
          return answer(applied.counts, [], [], applied.problems)
        }
        case 'validate': {
          const problems = validateLedger(context.ledger)
          return answer(statusCounts(context.ledger), [], [], problems)
        }
      }
    },
  }))
}

/**
 * The statuses a unit can hold, for callers that build a ledger filter.
 * @returns the statuses.
 */
export function unitStatuses(): readonly UnitStatus[] {
  return ['planned', 'in_progress', 'covered', 'candidate', 'blocked', 'deferred', 'out_of_scope', 'not_applicable']
}
