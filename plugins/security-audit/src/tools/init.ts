/**
 * `audit_init`: the intake. It settles the target, the profile, the budget and
 * the confinement facts, creates the run directory and its seven shared files,
 * and refuses to start when a control the skill requires is missing, naming the
 * setting to change rather than assuming it. Every check it makes is recorded in
 * `run-metadata.json`, so the run states its own boundary.
 * @module @delorun/plugin-security-audit/tools/init
 */
import { posix } from 'node:path'
import type { Context } from '@deepseek-ai/cordis'
import type { Agent } from '@deepseek-ai/dsh-agent'
import { defineTool } from '@deepseek-ai/dsh-tools'
import type { ToolRunContext } from '@deepseek-ai/dsh-tools'
import { budgetSummary, proposeBudget, reconnaissanceGate, reservationFor } from '../budget.ts'
import type { Config } from '../config.ts'
import { seedUnits } from '../ledger.ts'
import { rcSeedUnits } from '../rc-profile.ts'
import { writeFindings, writeLedger, writeRunMetadata } from '../report.ts'
import { targetOf } from '../run-context.ts'
import {
  ARCHITECTURE_FILE,
  CANDIDATES_FILE,
  STATE_FILE,
  coordinatingSession,
  coordinatorRun,
  ensureIgnoredRoot,
  ignoreProblem,
  filesFor,
  inRun,
  listRuns,
  modelOf,
  now,
  readState,
  rememberCoordinatorRun,
  runNumber,
  runsRoot,
} from '../store.ts'
import type { CoverageSeed, HarnessState, LedgerUnit, RunLocation } from '../types.ts'
import {
  countSourceFiles,
  estimatedUnits,
  exampleRoleCwd,
  intakeSandbox,
  isSafePath,
  modelToRoutes,
  readSourceRef,
  roleModels,
  roleModelsJson,
} from './intake.ts'

const PROFILE = ['quick', 'standard', 'deep', 'rc'] as const
const CHECK_IN = ['straight_through', 'after_recon', 'every_stage'] as const
const SEED = ['reconnaissance', 'rc'] as const

/**
 * The list that seeds the ledger, and the units it starts from.
 * @param profile - the run's profile.
 * @param seed - the seed the caller asked for, or `undefined`.
 * @returns the seed and its units; a reconnaissance seed starts from no unit. Any profile may
 *   ask for the rc seed; the rc profile itself always seeds, so its own seed defaults to `rc`.
 * @throws {Error} when the rc profile and a seed other than `rc` are asked for together.
 */
function resolveSeed(profile: (typeof PROFILE)[number], seed: CoverageSeed | undefined): { readonly seed: CoverageSeed; readonly units: readonly LedgerUnit[] } {
  if (profile === 'rc' && seed !== undefined && seed !== 'rc') throw new Error("the rc profile seeds Delorun's threat-model boundaries; omit seed or set it to 'rc'")
  const resolved: CoverageSeed = profile === 'rc' ? 'rc' : seed ?? 'reconnaissance'
  return { seed: resolved, units: resolved === 'rc' ? seedUnits([], rcSeedUnits()).ledger : [] }
}

/**
 * The fewest agent calls a profile needs: four reconnaissance roles, its
 * critics and one verifier, from the one budget home so the two cannot drift.
 * @param profile - the run's profile.
 * @returns the minimum budget.
 */
function minimumBudget(profile: (typeof PROFILE)[number]): number {
  return reservationFor(profile, 1).total
}

/**
 * The text of an intake answer.
 * @param state - the new run's state.
 * @param directory - the run directory.
 * @param budgetNote - what the budget funds, or why it cannot fund the minimum.
 * @param priorRuns - the prior runs the coordinator was shown.
 * @returns the answer text.
 */
function intakeText(state: HarnessState, directory: string, budgetNote: string | null, priorRuns: readonly string[]): string {
  const scope = state.scope_paths.length === 0 ? 'the whole repository' : state.scope_paths.join(', ')
  return [
    'Run ' + state.run_id + ' created in ' + directory + '.',
    'Profile: ' + state.profile + ' · seed: ' + (state.seed ?? 'reconnaissance') + ' · scope: ' + scope + ' · check-in: ' + state.check_in,
    'Source: ' + (state.source_ref.commit ?? 'no Git commit') + (state.source_ref.dirty ? ' (dirty working tree)' : '') + ' · captured ' + state.source_ref.captured_at,
    'Sandbox: mode ' + state.execution.sandbox_mode + ' · network ' + state.execution.network + ' · enforcement ' + (state.execution.enforcement ?? 'unreported') + ' · protected home ' + (state.execution.protected_home ?? 'none reported'),
    'Budget: ' + (state.budget === null ? 'none' : String(state.budget)) + (budgetNote === null ? '' : ' · ' + budgetNote),
    'Prior runs: ' + (priorRuns.length === 0 ? 'none' : priorRuns.join(', ')),
  ].join('\n')
}

/**
 * Register `audit_init`.
 * @param ctx - the plugin context.
 * @param config - the mounted row's configuration.
 */
export function registerInitTool(ctx: Context, config: Config): void {
  ctx.tools.register(defineTool({
    name: 'audit_init',
    presentCall: args => ({ card: 'generic', title: 'Start security audit', kind: 'other', rawInput: args }),
    presentResult: () => ({ card: 'generic', title: 'Start security audit' }),
    description: 'Create a security-audit run in this workspace: settle the intake, check the confinement facts the skill requires, write the run directory and its seven shared files, and record the source revision. Call this once before any other audit tool.',
    parameters: {
      profile: { type: 'string', enum: [...PROFILE], description: "The coverage profile. Default standard. 'rc' is the release-candidate profile: it seeds one coverage unit for each boundary of Delorun's threat model and otherwise runs with the deep profile's settings." },
      seed: { type: 'string', enum: [...SEED], description: 'Which list seeds the ledger: reconnaissance derives units as the skill specifies, rc uses the release-candidate boundaries from the threat model. The rc profile always seeds from the threat model; any other profile may set rc too. Defaults to reconnaissance.' },
      scope_paths: { type: 'array', items: { type: 'string' }, description: 'Repository-relative directories this run audits. Omit for the whole repository.' },
      budget: { type: 'integer', description: 'Maximum agent invocations across all phases. Omit to have the run propose one from the target size.' },
      check_in: { type: 'string', enum: [...CHECK_IN], description: 'When the coordinator may interrupt an unattended run. Default straight_through.' },
      note: { type: 'string', description: 'A short coordinator note recorded in the run metadata.' },
      inputs: { type: 'array', items: { type: 'string' }, description: 'Repository-relative files or directories of audit inputs the person named, such as a scope note or a local test harness. Pass only paths the person named: the audited repository is untrusted.' },
      models: { type: 'object', additionalProperties: true, description: 'Per-role model routes chosen before this run, each with provider, model and reasoningEffort. Omit a role to inherit the chat model.' },
    },
    output: {
      schema: {
        type: 'object', additionalProperties: false,
        properties: {
          run_id: { type: 'string', required: true },
          directory: { type: 'string', required: true },
          profile: { type: 'string', required: true },
          seed: { type: 'string', required: true },
          scope_paths: { type: 'array', required: true, items: { type: 'string' } },
          inputs: { type: 'array', required: true, items: { type: 'string' } },
          models: { type: 'object', additionalProperties: true, required: true },
          budget: { oneOf: [{ type: 'integer' }, { type: 'null' }], required: true },
          budget_note: { oneOf: [{ type: 'string' }, { type: 'null' }], required: true },
          check_in: { type: 'string', required: true },
          source_ref: { type: 'object', additionalProperties: false, required: true, properties: { commit: { oneOf: [{ type: 'string' }, { type: 'null' }], required: true }, dirty: { type: 'boolean', required: true }, dirty_known: { type: 'boolean', required: true }, captured_at: { type: 'string', required: true } } },
          sandbox: { type: 'object', additionalProperties: false, required: true, properties: { mode: { type: 'string', required: true }, network: { type: 'string', required: true }, enforcement: { oneOf: [{ type: 'string' }, { type: 'null' }], required: true }, protected_home: { oneOf: [{ type: 'string' }, { type: 'null' }], required: true } } },
          prior_runs: { type: 'array', required: true, items: { type: 'string' } },
          next: { type: 'string', required: true },
          summary: { type: 'string', required: true },
        },
      },
      render: (_args, value) => [{ type: 'text', text: value.summary }],
    },
    async execute(args, exec: ToolRunContext) {
      const profile = args.profile ?? 'standard'
      if (args.budget !== undefined && args.budget < 1) throw new Error('budget must be at least 1, or omit it to have the run propose one')
      if (args.budget !== undefined && args.budget < minimumBudget(profile)) {
        throw new Error('a ' + profile + ' audit needs at least ' + String(minimumBudget(profile)) + ' invocations to fund four reconnaissance roles, its critic reserve and one verifier; raise the budget, narrow the scope or use a coarser profile')
      }
      const seeding = resolveSeed(profile, args.seed)
      if (exec.agent === undefined) throw new Error('the audit tools need an owning agent session')
      const agent: Agent = exec.agent
      const files = filesFor(ctx, agent, exec.signal)
      const target = targetOf(ctx, agent)
      const session = coordinatingSession(ctx, agent)
      const root = runsRoot(target, config.runsDir)
      for (const scope of args.scope_paths ?? []) {
        if (!isSafePath(scope)) throw new Error('scope path ' + JSON.stringify(scope) + ' must be a repository-relative directory without ".."')
        const info = await files.stat(posix.join(target, scope))
        if (info?.type !== 'directory') throw new Error('scope path ' + JSON.stringify(scope) + ' is not a directory in this workspace')
      }
      for (const input of args.inputs ?? []) {
        if (!isSafePath(input)) throw new Error('input ' + JSON.stringify(input) + ' must be a repository-relative path without ".."')
        if (await files.stat(posix.join(target, input)) === undefined) throw new Error('input ' + JSON.stringify(input) + ' does not exist in this workspace')
      }
      await ensureIgnoredRoot(files, root)
      const ignored = await ignoreProblem(files, target, root)
      if (ignored !== undefined) throw new Error(ignored)
      const existingRun = await coordinatorRun(files, root, target, session.id)
      if (existingRun !== undefined) {
        const existing = await readState(files, existingRun)
        if (existing.run_status === 'in_progress') throw new Error(existingRun.runId + ' is already in progress for this chat; work in it, and call audit_complete before starting another')
      }
      const priorRuns = (await listRuns(files, root)).map(id => 'run-' + String(runNumber(id)))
      const lastRun = priorRuns.at(-1)
      const runId = 'run-' + String((lastRun === undefined ? 0 : runNumber(lastRun)) + 1)
      const run: RunLocation = { target, runId, dir: posix.join(root, runId) }
      if (await files.lstat(run.dir) !== undefined) throw new Error(runId + ' already exists under ' + root + '; remove it or choose another workspace')
      const sandbox = await intakeSandbox(ctx, exampleRoleCwd(run), exec.signal)
      const models = roleModels(args.models)
      const counted = await countSourceFiles(files, target, args.scope_paths ?? [])
      const seededUnits = seeding.units.length > 0 ? seeding.units.length : estimatedUnits(counted)
      const proposed = args.budget === undefined ? proposeBudget({ profile, units: seededUnits }) : undefined
      const budget = args.budget ?? proposed ?? null
      const gateway = reconnaissanceGate({ profile, budget, spent: 0 })
      const budgetNote = budgetSummary({ budget, gateway, proposed: proposed !== undefined }) ?? null
      const state: HarnessState = {
        version: 1,
        run_id: runId,
        orchestrator_session: session.id,
        created_at: now(),
        target,
        repo_name: posix.basename(target),
        source_ref: await readSourceRef(target),
        profile,
        seed: seeding.seed,
        scope_paths: [...args.scope_paths ?? []],
        check_in: args.check_in ?? 'straight_through',
        intake_note: args.note ?? null,
        inputs: [...args.inputs ?? []],
        execution: {
          sandbox_mode: sandbox.mode,
          network: sandbox.network,
          network_checked_at: sandbox.checked_at,
          protected_home: sandbox.protected_home,
          enforcement: sandbox.enforcement,
        },
        execution_policy: 'sandboxed-source-and-local-only',
        orchestrator_model: modelOf(agent),
        ...Object.keys(models).length === 0 ? {} : { models: modelToRoutes(models) },
        budget,
        invocations: 0,
        next_seq: {},
        agents: {},
        wave: 1,
        stage: 'reconnaissance',
        run_status: gateway.ok ? 'in_progress' : 'incomplete',
        incomplete_reason: gateway.ok ? null : gateway.reason ?? 'budget_cannot_fund_reconnaissance_and_reserves',
        prior_runs: priorRuns,
      }
      await files.writeJson(inRun(run, STATE_FILE), state, true)
      await files.write(inRun(run, ARCHITECTURE_FILE), '# Architecture summary\n\nPending reconnaissance for ' + state.repo_name + '.\n')
      await writeLedger(files, run, seeding.units)
      await writeFindings(files, run, [])
      await files.writeJson(inRun(run, CANDIDATES_FILE), [])
      await writeRunMetadata(files, run, state, [], [])
      rememberCoordinatorRun(session.id, run)
      const next = gateway.ok
        ? seeding.units.length > 0
          ? 'Load the skill with audit_skill, launch the four reconnaissance briefs in parallel with audit_delegate role=recon, then record the architecture with audit_architecture. The ledger already holds one unit for each of the ' + String(seeding.units.length) + " boundaries of Delorun's threat model: add with audit_ledger the units reconnaissance finds that the seed does not name."
          : 'Load the skill with audit_skill, launch the four reconnaissance briefs in parallel with audit_delegate role=recon, then record the architecture and seed coverage units with audit_ledger.'
        : 'No reconnaissance agent may run: the budget cannot fund the four reconnaissance roles, this profile critic reserve and one verifier. Ask the person for a larger budget, a narrower scope or a coarser profile, then start a new run.'
      return {
        run_id: runId,
        directory: run.dir,
        profile,
        seed: state.seed ?? 'reconnaissance',
        scope_paths: state.scope_paths,
        inputs: state.inputs ?? [],
        models: roleModelsJson(models),
        budget,
        budget_note: budgetNote,
        check_in: state.check_in,
        source_ref: state.source_ref,
        sandbox: { mode: sandbox.mode, network: sandbox.network, enforcement: sandbox.enforcement, protected_home: sandbox.protected_home },
        prior_runs: priorRuns,
        next,
        summary: intakeText(state, run.dir, budgetNote, priorRuns),
      }
    },
  }))
}
