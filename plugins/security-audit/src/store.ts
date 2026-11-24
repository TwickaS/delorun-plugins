/**
 * The run store: where an audit run lives, how its files are read and written, and the bookkeeping the coordinator
 * keeps beside them.
 *
 * A run lives at `<workspace>/.security-audit/run-N/`, whose own `.gitignore` keeps it out of version control: a run
 * holds reports of unfixed vulnerabilities, so none of it may be committed by accident. Every read is tolerant, because
 * the studio pane and a restarted coordinator both read a run while it is being written: a missing file is `undefined`
 * and a malformed one names the file, never a crash.
 *
 * Every file goes through `ctx.fs`, so a write carries the coordinating session's standing sandbox policy where the
 * filesystem confines. One lock per run serialises every read-modify-write of the run's bookkeeping, which is enough
 * because every session of one account runs in one harness process.
 * @module delorun-plugin-security-audit/store
 */
import { posix } from 'node:path'
import type { Context } from '@deepseek-ai/cordis'
import type { Agent } from '@deepseek-ai/dsh-agent'
import type {} from '@deepseek-ai/dsh-fs'
import type { SandboxExecutionPolicy } from '@deepseek-ai/dsh-sandbox'
import type {} from '@deepseek-ai/dsh-sandbox-policy'
import type { Session } from '@deepseek-ai/dsh-session'
import type {
  AgentEntry,
  CoordinatorRunFile,
  HarnessState,
  ModelRoute,
  RunLocation,
  SharedRunFile,
} from './types.ts'

/**
 * The domain types a caller of this module reads: a run's location and state, and its files. They live in `types.ts`
 * and are re-exported here because every function below speaks them.
 */
export type {
  AgentEntry,
  CoordinatorRunFile,
  HarnessState,
  ModelRoute,
  RunLocation,
  SharedRunFile,
} from './types.ts'

/** The target-relative directory every run of a workspace lives under. */
export const RUNS_DIRECTORY = '.security-audit'

/** The run's own record of its setup, state and cost. */
export const RUN_METADATA_FILE = 'run-metadata.json'

/** The architecture summary reconnaissance synthesises, capped at about 1,000 words. */
export const ARCHITECTURE_FILE = 'architecture.md'

/** The coverage ledger: one unit per planned assignment. */
export const COVERAGE_LEDGER_FILE = 'coverage-ledger.json'

/** The structured records that passed verification. */
export const FINDINGS_FILE = 'findings.json'

/** The candidate store between hunting and final verification; the coordinator's bookkeeping, not a report file. */
export const CANDIDATES_FILE = 'candidates.json'

/** The coordinator's private bookkeeping: agents, budget, stage and the confinement facts. */
export const STATE_FILE = 'state.json'

/** The report of what the run found, for a person who reads no code. */
export const REPORT_FILE = 'REPORT.md'

/** The detail behind each confirmed finding of medium severity or above. */
export const FINDINGS_DETAIL_FILE = 'FINDINGS-DETAIL.md'

/** The findings that need a check the audit could not make. */
export const NEEDS_VALIDATION_FILE = 'NEEDS-VALIDATION.md'

/** The seven files a run's report is built from, in the order a reader takes them. */
export const SHARED_RUN_FILES: readonly SharedRunFile[] = [
  RUN_METADATA_FILE,
  ARCHITECTURE_FILE,
  COVERAGE_LEDGER_FILE,
  FINDINGS_FILE,
  REPORT_FILE,
  FINDINGS_DETAIL_FILE,
  NEEDS_VALIDATION_FILE,
]

/** The report document each report file holds, keyed by the document `audit_report` writes. */
export const REPORT_FILES: Readonly<Record<'REPORT' | 'FINDINGS_DETAIL' | 'NEEDS_VALIDATION', string>> = {
  REPORT: REPORT_FILE,
  FINDINGS_DETAIL: FINDINGS_DETAIL_FILE,
  NEEDS_VALIDATION: NEEDS_VALIDATION_FILE,
}

/** Every file at a run's root that only the coordinator writes. */
export const COORDINATOR_RUN_FILES: readonly CoordinatorRunFile[] = [...SHARED_RUN_FILES, CANDIDATES_FILE]

/** The text a runs root's `.gitignore` carries, so a report of an unfixed vulnerability never reaches a commit. */
export const RUNS_IGNORE_TEXT = '# Security audit runs hold reports of unfixed vulnerabilities; never commit them.\n*\n'

/** A run id's form: `run-` and a number without leading zeros. */
const RUN_ID = /^run-([1-9][0-9]{0,5})$/

/** Raised for a run-store rule the caller broke, with a message that names what is wrong and what to do. */
export class AuditStoreError extends Error {
  /** The problems the operation found, one per line, when it found several. */
  readonly problems: readonly string[]

  /**
   * @param message - what is wrong and what to do, or the problems joined by newlines.
   * @param problems - the individual problems, when the message collects several.
   */
  constructor(message: string, problems: readonly string[] = []) {
    super(message)
    this.name = 'AuditStoreError'
    this.problems = problems
  }
}

/**
 * The directory every run of a workspace lives under.
 * @param target - the workspace directory the audit targets, absolute.
 * @param runsDir - the configured target-relative runs directory, `RUNS_DIRECTORY` by default.
 * @returns its absolute path.
 */
export function runsRoot(target: string, runsDir: string = RUNS_DIRECTORY): string {
  return posix.join(target, runsDir)
}

/**
 * Resolve a run-relative path, refusing one that leaves the run.
 * @param run - the run.
 * @param relative - a path relative to the run directory.
 * @returns the absolute path.
 * @throws {AuditStoreError} for an absolute path or one with an empty or `..` segment.
 */
export function inRun(run: RunLocation, relative: string): string {
  if (relative.startsWith('/') || relative.split('/').some(part => part === '..' || part === '')) {
    throw new AuditStoreError(`${JSON.stringify(relative)} is not a run-relative path`)
  }
  return posix.join(run.dir, relative)
}

/**
 * @param runId - a run id.
 * @returns its number, or 0 for a name that is not a run id.
 */
export function runNumber(runId: string): number {
  return Number(RUN_ID.exec(runId)?.[1] ?? 0)
}

/**
 * The run ids under a runs root, in ascending order.
 * @param files - file access.
 * @param root - the runs root, absolute.
 * @returns the run ids.
 */
export async function listRuns(files: Pick<AuditFiles, 'list'>, root: string): Promise<string[]> {
  const runs = (await files.list(root)).filter(entry => entry.type === 'directory' && RUN_ID.test(entry.name))
  return runs.map(entry => entry.name).sort((left, right) => runNumber(left) - runNumber(right))
}

/**
 * Create the runs root's `.gitignore` when it is missing or does not ignore everything below it, so version control
 * ignores the run files the skill requires it to ignore.
 * @param files - file access.
 * @param root - the runs root, absolute.
 * @throws {AuditStoreError} when the root exists and is not a real directory.
 */
export async function ensureIgnoredRoot(files: AuditFiles, root: string): Promise<void> {
  const rootEntry = await files.lstat(root)
  if (rootEntry !== undefined && rootEntry.type !== 'directory') {
    throw new AuditStoreError(`${root} must be a real directory, not a symbolic link or a special file`)
  }
  const ignore = posix.join(root, '.gitignore')
  const current = await files.read(ignore)
  if (current !== RUNS_IGNORE_TEXT) await files.write(ignore, RUNS_IGNORE_TEXT)
}

/**
 * The repository rules that would keep a run out of version control, or the reason they would not.
 *
 * The skill requires the run directory to be ignored before any file is written into it, and a run holds reports of
 * unfixed vulnerabilities. The runs root's own `.gitignore` is not enough on its own: a repository can re-include a
 * path below an ignored directory with a later negation, and a nested repository can ignore nothing at all. So this
 * reads the rules that apply to the runs root and refuses when any of them would let a run file be committed.
 * @param files - file access.
 * @param workspace - the workspace root, absolute.
 * @param root - the runs root, absolute.
 * @returns the problem to report, or `undefined` when version control ignores the runs root.
 */
export async function ignoreProblem(files: AuditFiles, workspace: string, root: string): Promise<string | undefined> {
  const relative = posix.relative(workspace, root)
  if (relative === '' || relative.startsWith('..') || posix.isAbsolute(relative)) {
    return `the runs root ${root} is not inside the workspace ${workspace}, so this plugin cannot establish that version control ignores it`
  }
  const segments = relative.split('/')
  const rules: { readonly file: string, readonly text: string }[] = []
  for (let depth = 0; depth <= segments.length; depth += 1) {
    const directory = depth === 0 ? workspace : posix.join(workspace, ...segments.slice(0, depth))
    const text = await files.read(posix.join(directory, '.gitignore'))
    if (text !== undefined) rules.push({ file: posix.join(directory, '.gitignore'), text })
  }
  const problem = reincludeProblem(rules, segments)
  if (problem !== undefined) return problem
  return undefined
}

/**
 * Whether any rule re-includes a path inside the runs root, which would let a run file be committed.
 * @param rules - the `.gitignore` files that apply, outermost first.
 * @param segments - the runs root's path below the workspace, one entry per directory.
 * @returns the problem to report, or `undefined` when nothing re-includes a run file.
 */
function reincludeProblem(rules: readonly { readonly file: string, readonly text: string }[], segments: readonly string[]): string | undefined {
  for (const rule of rules) {
    for (const line of rule.text.split('\n')) {
      const trimmed = line.trim()
      if (trimmed === '' || trimmed.startsWith('#')) continue
      if (!trimmed.startsWith('!')) continue
      const target = trimmed.slice(1).replace(/^\/+/, '').replace(/\/+$/, '')
      if (target === '') continue
      const first = target.split('/')[0] ?? ''
      if (segments.includes(first) || target.startsWith(segments.join('/'))) {
        return `${rule.file} re-includes "${trimmed}" below the runs root, so a run file could be committed. Remove that rule, or move the run outside the repository.`
      }
    }
  }
  return undefined
}

const locks = new Map<string, Promise<void>>()

/**
 * Run `op` while holding the run's lock, so every read-modify-write of the run's bookkeeping is serial.
 * @param run - the run.
 * @param op - the operation.
 * @returns its result.
 */
export async function withRunLock<T>(run: RunLocation, op: () => Promise<T>): Promise<T> {
  const prior = locks.get(run.dir) ?? Promise.resolve()
  const result = prior.then(op, op)
  const tail = result.then(() => undefined, () => undefined)
  locks.set(run.dir, tail)
  try {
    return await result
  } finally {
    if (locks.get(run.dir) === tail) locks.delete(run.dir)
  }
}

/**
 * Read a run's bookkeeping.
 * @param files - file access.
 * @param run - the run.
 * @returns the state.
 * @throws {AuditStoreError} when the run has no state, or when another tool wrote it.
 */
export async function readState(files: AuditFiles, run: RunLocation): Promise<HarnessState> {
  const state = await files.readJson(inRun(run, STATE_FILE))
  if (typeof state !== 'object' || state === null || (state as { version?: unknown }).version !== 1) {
    throw new AuditStoreError(`${run.runId} has no readable ${STATE_FILE}; it was not created by audit_init`)
  }
  return state as HarnessState
}

/**
 * Write a run's bookkeeping as it stands.
 * @param files - file access.
 * @param run - the run.
 * @param state - the state.
 */
export async function writeState(files: AuditFiles, run: RunLocation, state: HarnessState): Promise<void> {
  await files.writeJson(inRun(run, STATE_FILE), state)
}

/**
 * Read, change and write a run's bookkeeping under its lock.
 * @param files - file access.
 * @param run - the run.
 * @param change - mutates the state and returns the operation's result.
 * @returns the result.
 * @throws {AuditStoreError} when the run has no state.
 */
export async function updateState<T>(files: AuditFiles, run: RunLocation, change: (state: HarnessState) => T | Promise<T>): Promise<T> {
  return await withRunLock(run, async () => {
    const state = await readState(files, run)
    const result = await change(state)
    await files.writeJson(inRun(run, STATE_FILE), state)
    return result
  })
}

/** Runs the coordinators of this process opened, by coordinating session id. */
const coordinatorRuns = new Map<string, RunLocation>()

/** Claimed agents of this process, by child session id. */
const claims = new Map<string, { readonly run: RunLocation; readonly agentId: string }>()

/**
 * Remember the run a coordinating session works on.
 * @param sessionId - the coordinating session.
 * @param run - its run.
 */
export function rememberCoordinatorRun(sessionId: string, run: RunLocation): void {
  coordinatorRuns.set(sessionId, run)
}

/**
 * Remember a child's claimed brief.
 * @param sessionId - the child session.
 * @param run - the run.
 * @param agentId - the agent id it claimed.
 */
export function rememberClaim(sessionId: string, run: RunLocation, agentId: string): void {
  claims.set(sessionId, { run, agentId })
}

/**
 * Forget a child's claim after its run ends.
 * @param sessionId - the child session.
 */
export function forgetClaim(sessionId: string): void {
  claims.delete(sessionId)
}

/**
 * Find the agent entry a child session owns in one run.
 * @param state - the run's state.
 * @param child - the child session id.
 * @returns the agent id and its entry, or `undefined` when the child claimed nothing.
 */
export function agentClaimedBy(state: HarnessState, child: string): { readonly agentId: string; readonly entry: AgentEntry } | undefined {
  for (const [agentId, entry] of Object.entries(state.agents)) {
    if (entry.claimed_by === child) return { agentId, entry }
  }
  return undefined
}

/**
 * The run a coordinating session works on: remembered in this process, else the newest run whose state names the
 * session, which survives a harness restart.
 * @param files - file access.
 * @param root - the runs root, absolute.
 * @param target - the workspace directory the audit targets.
 * @param sessionId - the coordinating session.
 * @returns the run, or `undefined` when the session has none.
 */
export async function coordinatorRun(files: AuditFiles, root: string, target: string, sessionId: string): Promise<RunLocation | undefined> {
  const known = coordinatorRuns.get(sessionId)
  if (known !== undefined) {
    if (known.target === target && (await files.lstat(inRun(known, STATE_FILE)))?.type === 'file') return known
    coordinatorRuns.delete(sessionId)
  }
  for (const runId of (await listRuns(files, root)).reverse()) {
    const run = { target, runId, dir: posix.join(root, runId) }
    const state = await files.readJson(inRun(run, STATE_FILE)) as Partial<HarnessState> | undefined
    if (state?.orchestrator_session === sessionId) {
      coordinatorRuns.set(sessionId, run)
      return run
    }
  }
  return undefined
}

/**
 * The brief a child session claimed: remembered in this process, else found in the state of a run its coordinator
 * owns.
 * @param files - file access.
 * @param root - the runs root, absolute.
 * @param target - the workspace directory the audit targets.
 * @param child - the child session id.
 * @param coordinator - the child's coordinating session id.
 * @returns the claim, or `undefined` when the child claimed nothing.
 */
export async function claimOf(
  files: AuditFiles,
  root: string,
  target: string,
  child: string,
  coordinator: string,
): Promise<{ readonly run: RunLocation; readonly agentId: string } | undefined> {
  const known = claims.get(child)
  if (known !== undefined) return known
  const run = await coordinatorRun(files, root, target, coordinator)
  if (run === undefined) return undefined
  const found = agentClaimedBy(await readState(files, run), child)
  if (found === undefined) return undefined
  const claim = { run, agentId: found.agentId }
  claims.set(child, claim)
  return claim
}

/**
 * The session that owns a run: the agent's own for the coordinator, its delegating parent for a child.
 * @param ctx - a plugin context.
 * @param agent - the calling agent.
 * @returns the coordinating session, or the agent's own when the parent is not live.
 */
export function coordinatingSession(ctx: Context, agent: Agent): Session {
  const parent = agent.session.header.parentSession
  if (agent.session.header.origin !== 'subagent' || parent === undefined) return agent.session
  return ctx.get('sessions')?.get(parent) ?? agent.session
}

/** File access for one calling agent, with the coordinating session's standing sandbox policy. */
export class AuditFiles {
  /** The plugin context every operation goes through. */
  private readonly ctx: Context

  /** The calling session's signal. */
  private readonly signal: AbortSignal

  /** The standing policy every write runs under, when the backend confines. */
  private readonly policy: SandboxExecutionPolicy | undefined

  /**
   * @param ctx - a plugin context.
   * @param signal - the call's signal.
   * @param policy - the standing policy every write runs under, when the backend confines.
   */
  constructor(ctx: Context, signal: AbortSignal, policy: SandboxExecutionPolicy | undefined) {
    this.ctx = ctx
    this.signal = signal
    this.policy = policy
  }

  /**
   * Read a file.
   * @param path - an absolute path.
   * @returns its text, or `undefined` when it does not exist.
   * @throws {AuditStoreError} when the path is not a regular file.
   */
  async read(path: string): Promise<string | undefined> {
    const entry = await this.ctx.fs.lstat(path, undefined, this.signal)
    if (entry === undefined) return undefined
    if (entry.type !== 'file') throw new AuditStoreError(`${path} is not a regular file`)
    const target = await this.ctx.fs.resolve(path, { signal: this.signal })
    const info = await this.ctx.fs.stat(target, this.signal)
    if (info === undefined) return undefined
    if (info.type !== 'file') throw new AuditStoreError(`${path} is not a regular file`)
    return await this.ctx.fs.readText(target, this.signal)
  }

  /**
   * Read and parse a JSON file.
   * @param path - an absolute path.
   * @returns the value, or `undefined` when the file does not exist.
   * @throws {AuditStoreError} when the file is not JSON.
   */
  async readJson(path: string): Promise<unknown> {
    const text = await this.read(path)
    if (text === undefined) return undefined
    try {
      return JSON.parse(text) as unknown
    } catch (error: unknown) {
      throw new AuditStoreError(`${path} is not valid JSON: ${(error as Error).message}`)
    }
  }

  /**
   * Write a file, creating its missing parent directories.
   * @param path - an absolute path.
   * @param content - the text.
   * @param exclusive - refuse to replace an existing file.
   * @throws {AuditStoreError} when the path holds something other than a regular file.
   */
  async write(path: string, content: string, exclusive = false): Promise<void> {
    const entry = await this.ctx.fs.lstat(path, undefined, this.signal)
    if (entry?.type === 'symlink' || entry?.type === 'other' || entry?.type === 'directory') {
      throw new AuditStoreError(`${path} is not a replaceable regular file`)
    }
    const target = await this.ctx.fs.resolve(path, { signal: this.signal })
    await this.ctx.fs.writeText(target, content, exclusive ? { kind: 'createIfAbsent' } : undefined, this.signal, this.policy)
  }

  /**
   * Write JSON with two-space indentation and a trailing newline.
   * @param path - an absolute path.
   * @param value - the value.
   * @param exclusive - refuse to replace an existing file.
   */
  async writeJson(path: string, value: unknown, exclusive = false): Promise<void> {
    await this.write(path, `${JSON.stringify(value, undefined, 2)}\n`, exclusive)
  }

  /**
   * Stat a path without following its final symbolic-link component.
   * @param path - an absolute path.
   * @returns its path-entry type, or `undefined` when it is absent.
   */
  async lstat(path: string): Promise<{ readonly type: string } | undefined> {
    const entry = await this.ctx.fs.lstat(path, undefined, this.signal)
    return entry === undefined ? undefined : { type: entry.type }
  }

  /**
   * Stat a file.
   * @param path - an absolute path.
   * @returns its type and size, or `undefined` when it does not exist.
   */
  async stat(path: string): Promise<{ readonly type: string; readonly size: number | undefined } | undefined> {
    const target = await this.ctx.fs.resolve(path, { signal: this.signal })
    const info = await this.ctx.fs.stat(target, this.signal)
    return info === undefined ? undefined : { type: info.type, size: info.size }
  }

  /**
   * List a directory.
   * @param path - an absolute path.
   * @returns its entries, or an empty list when it does not exist or is not a directory.
   */
  async list(path: string): Promise<{ readonly name: string; readonly type: string }[]> {
    const target = await this.ctx.fs.resolve(path, { signal: this.signal })
    const info = await this.ctx.fs.stat(target, this.signal)
    if (info?.type !== 'directory') return []
    return (await this.ctx.fs.listDir(target, this.signal)).map(entry => ({ name: entry.name, type: entry.type }))
  }
}

/**
 * File access for one tool call, with the coordinating session's standing sandbox policy.
 * @param ctx - a plugin context.
 * @param agent - the calling agent.
 * @param signal - the call's signal.
 * @returns the accessor.
 * @throws {AuditStoreError} when the filesystem confines but no sandbox policy can resolve.
 */
export function filesFor(ctx: Context, agent: Agent, signal: AbortSignal): AuditFiles {
  const policy = ctx.fs.sandboxMode === undefined
    ? undefined
    : ctx.get('sandboxPolicy')?.resolve({ session: coordinatingSession(ctx, agent) })
  if (ctx.fs.sandboxMode !== undefined && policy === undefined) {
    throw new AuditStoreError('the filesystem confines writes but no sandbox policy resolves, so the run files cannot be written safely; mount @deepseek-ai/dsh-sandbox-policy')
  }
  return new AuditFiles(ctx, signal, policy)
}

/**
 * The model route an agent runs on.
 * @param agent - the agent.
 * @returns the route, with `null` for a field the agent leaves to its adapter.
 */
export function modelOf(agent: Agent): ModelRoute {
  const options = agent.options
  return { provider: options.provider ?? null, model: options.model ?? null, reasoning_effort: options.reasoningEffort ?? null }
}

/**
 * The current time as an ISO 8601 UTC timestamp; one place so tests can pin it.
 * @returns the timestamp.
 */
export function now(): string {
  return new Date().toISOString()
}
