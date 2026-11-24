/**
 * Shared lookup for the coordinator tools and the delegation tool: the calling
 * chat's target, run, file accessor, ledger, architecture and state. Every tool
 * resolves these the same way, so a chat that resumes finds the run its log
 * names.
 * @module delorun-plugin-security-audit/run-context
 */
import type { Context } from '@deepseek-ai/cordis'
import type { Agent } from '@deepseek-ai/dsh-agent'
import type {} from '@deepseek-ai/dsh-working-directory'
import { parseLedger, type LedgerUnit } from './ledger.ts'
import {
  type AuditFiles,
  type HarnessState,
  type RunLocation,
  ARCHITECTURE_FILE,
  COVERAGE_LEDGER_FILE,
  coordinatingSession,
  coordinatorRun,
  filesFor,
  inRun,
  readState,
  runsRoot,
} from './store.ts'

/** Everything a coordinator tool needs about its current run. */
export interface RunContext {
  readonly sessionId: string
  readonly target: string
  readonly root: string
  readonly files: AuditFiles
  readonly run: RunLocation
  readonly state: HarnessState
  readonly ledger: LedgerUnit[]
  readonly architecture: string | undefined
}

/**
 * The current target directory of a chat.
 * @param ctx - a plugin context.
 * @param agent - the calling agent.
 * @returns the absolute working directory.
 * @throws {Error} when the chat has none.
 */
export function targetOf(ctx: Context, agent: Agent): string {
  const session = coordinatingSession(ctx, agent)
  const directory = ctx.get('workingDirectory')?.get(session) ?? session.header.cwd
  if (directory === undefined || directory.length === 0) throw new Error('the audit has no working directory; start the chat in the repository to audit')
  return directory
}

/**
 * Resolve the coordinator's current run and its state files.
 * @param ctx - a plugin context.
 * @param agent - the calling agent.
 * @param signal - the call's signal.
 * @param runsDir - the target-relative runs directory.
 * @returns the context.
 * @throws {Error} when the chat has no run.
 */
export async function runContext(ctx: Context, agent: Agent, signal: AbortSignal, runsDir: string): Promise<RunContext> {
  const sessionId = coordinatingSession(ctx, agent).id
  const target = targetOf(ctx, agent)
  const root = runsRoot(target, runsDir)
  const files = filesFor(ctx, agent, signal)
  const run = await coordinatorRun(files, root, target, sessionId)
  if (run === undefined) throw new Error('this chat has no security-audit run; call audit_init first')
  const state = await readState(files, run)
  const ledger = parseLedger(await files.readJson(inRun(run, COVERAGE_LEDGER_FILE)))
  const architecture = await files.read(inRun(run, ARCHITECTURE_FILE))
  return { sessionId, target, root, files, run, state, ledger, architecture }
}

/**
 * Refuse work on a finished run. A completed report must not be silently
 * extended afterwards.
 * @param state - the run's state.
 * @throws {Error} when the run is done.
 */
export function requireMutable(state: HarnessState): void {
  if (state.stage === 'done' || state.run_status === 'complete') throw new Error('this audit run is complete; start a new run for more coverage or a new report')
}
