/**
 * Validated delegation for every Cloudflare role: reconnaissance, hunter,
 * candidate verifier, coverage critic, the distinct final-clean critic and the
 * Phase 5 record verifier. One call assigns coverage, composes the deterministic
 * brief, starts one child in its own scratch directory with its structured-result
 * schema, waits for the result, promotes the artifacts it named, runs the
 * validation gate and only then changes shared state. A refused result never
 * reaches the ledger, the candidate store or `findings.json`.
 *
 * The isolation is the harness's: a child's working directory is its
 * workspace-write boundary, so a role writes only inside its own working copy
 * and reads the target freely. Every role gets one disposable copy of the
 * reviewed tree at `<run>/agents/<id>/work/` (A644), made with
 * `git archive | tar`, which it may edit and build in; the copy is removed when
 * the role finishes and its artifacts are kept. A role may also start the
 * target harness inside that copy, at most twice per run, under bwrap and its
 * own scratch HOME (`audit_harness`). The audit workspace's network setting
 * must be off; the gate refuses to start a role without it.
 * @module @delorun/plugin-security-audit/delegate
 */
import { spawn, type ChildProcess } from 'node:child_process'
import { constants, existsSync } from 'node:fs'
import { chmod, lstat, mkdir, open, writeFile as writeFileAsync } from 'node:fs/promises'
import { createServer } from 'node:net'
import { dirname, join } from 'node:path'
import type { Context } from '@deepseek-ai/cordis'
import type { Agent, AgentOptions } from '@deepseek-ai/dsh-agent'
import type { SandboxMode, SandboxNetwork } from '@deepseek-ai/dsh-sandbox'
import type {} from '@deepseek-ai/dsh-sandbox-policy'
import type {} from '@deepseek-ai/dsh-working-directory'
import { defineTool } from '@deepseek-ai/dsh-tools'
import type { ObjectJsonSchema } from '@deepseek-ai/dsh-tools'
import { modeledRoleOf, routeFor, type Config, type ModeledRole, type RoleModelOverride, type RoleModelOverrides } from './config.ts'
import { requireMutable, runContext, type RunContext } from './run-context.ts'
import {
  claimOf,
  coordinatingSession,
  forgetClaim,
  inRun,
  modelOf,
  now,
  readState,
  rememberClaim,
  withRunLock,
  STATE_FILE,
  type AgentEntry,
  type HarnessState,
  type RunLocation,
} from './store.ts'
import type { BriefKind, CheckIn, ModelRoute, NestedStart, RoleModels, WorkCopy } from './types.ts'
import {
  applyHunterResult,
  assignUnits,
  closeUnits,
  parseLedger,
  patchUnit,
  reassignUnits,
  seedUnits,
  type HunterUnitResult,
  type LedgerCheck,
  type LedgerUnit,
  type UnitSeed,
} from './ledger.ts'
import {
  applyFinalVerification,
  readCandidates,
  recordVerification,
  upsertCandidate,
  writeCandidates,
  type CandidateEntry,
} from './candidates.ts'
import { proposedRecord, resultProblems, type GateContext } from './gate.ts'
import {
  bytesText,
  copyGateProblem,
  createWorkCopy,
  freeDiskBytes,
  NESTED_HARNESS_CAP,
  NESTED_PORT_RANGE,
  removeWorkCopy,
  type CopyMeasurement,
} from './scripts-copy.ts'
import { ledgerValidator } from './skill.ts'
import { writeLedger, writeRunMetadata } from './report.ts'
import {
  CRITIC_RESULT,
  FINAL_VERIFIER_RESULT,
  HUNTER_RESULT,
  MAX_ARTIFACT_BYTES,
  MAX_PROMOTED_BYTES,
  RECON_RESULT,
  VERIFIER_RESULT,
  criticBrief,
  finalVerifierBrief,
  hunterBrief,
  reconBrief,
  verifierBrief,
  type BriefContext,
  type BriefRun,
  type CandidateSummary,
  type CarriedRecord,
} from './prompts/index.ts'
import {
  budgetSummary,
  criticCalls,
  reconnaissanceGate,
  validationGate,
  waveGate,
  type BudgetReason,
} from './budget.ts'

/** A value that is lossless JSON, as a tool answer carries it. */
type Json = null | boolean | number | string | Json[] | { [key: string]: Json }

/** The bytes limits a promotion applies, from the skill's write isolation. */
export interface PromotionLimits {
  /** The most bytes one artifact may hold. */
  readonly perFile: number
  /** The most bytes all artifacts of one agent may hold together. */
  readonly total: number
}

/** One artifact's promotion outcome. */
export interface PromotionOutcome {
  /** The run-relative references that were promoted, in request order. */
  readonly promoted: string[]
  /** Why each refused reference was refused. */
  readonly refused: { readonly reference: string; readonly reason: string }[]
}

/**
 * Whether one path segment is safe to walk: a plain name, never empty, `.` or `..`.
 * @param segment - the segment.
 * @returns whether it is safe.
 */
function safeSegment(segment: string): boolean {
  return segment.length > 0 && segment !== '.' && segment !== '..' && !segment.includes('\\0') && !segment.includes('\\')
}

/**
 * Walk a directory-relative path's parent components, requiring each to be a
 * real directory rather than a symbolic link.
 * @param root - the absolute root the walk starts from.
 * @param segments - the parent segments, in order.
 * @returns the absolute parent directory.
 * @throws {Error} naming the component that is missing or not a real directory.
 */
async function realDirectory(root: string, segments: readonly string[]): Promise<string> {
  let current = root
  for (const segment of segments) {
    current = join(current, segment)
    const entry = await lstat(current).catch(() => undefined)
    if (entry === undefined) throw new Error(current + ' does not exist')
    if (entry.isSymbolicLink()) throw new Error(current + ' is a symbolic link, not a directory')
    if (!entry.isDirectory()) throw new Error(current + ' is not a directory')
  }
  return current
}

/**
 * The bytes of one promoted artifact, read from a verified descriptor.
 * @param handle - the open source descriptor.
 * @param bound - the most bytes the artifact may hold.
 * @returns the bytes.
 * @throws {Error} when the file holds more than its bound.
 */
async function readBounded(handle: Awaited<ReturnType<typeof open>>, bound: number): Promise<Buffer> {
  const chunks: Buffer[] = []
  let total = 0
  for (;;) {
    const chunk = Buffer.alloc(Math.min(65536, bound + 1 - total))
    const { bytesRead } = await handle.read(chunk, 0, chunk.length, total)
    if (bytesRead === 0) break
    total += bytesRead
    if (total > bound) throw new Error('the file holds more than ' + String(bound) + ' bytes')
    chunks.push(chunk.subarray(0, bytesRead))
  }
  return Buffer.concat(chunks)
}

/**
 * Promote the artifacts a result named, following the skill's promotion
 * procedure: no-follow path-confined traversal, a regular file with one link,
 * explicit per-file and cumulative byte bounds, an exclusive destination and no
 * reopening of either path after verification.
 * @param input - the role's scratch and artifacts roots, its agent id, the references its checks named, and the limits.
 * @returns what was promoted and why each refusal was refused.
 */
export async function promoteArtifacts(input: {
  readonly scratch: string
  readonly artifacts: string
  readonly agentId: string
  readonly references: readonly string[]
  readonly limits: PromotionLimits
}): Promise<PromotionOutcome> {
  const promoted: string[] = []
  const refused: { reference: string; reason: string }[] = []
  let used = 0
  const prefix = 'agents/' + input.agentId + '/artifacts/'
  for (const reference of input.references) {
    if (!reference.startsWith(prefix)) {
      refused.push({ reference, reason: 'an artifact reference is ' + prefix + '<relative>' });
      continue;
    }
    const relative = reference.slice(prefix.length);
    const segments = relative.split('/');
    if (relative.startsWith('/') || segments.some(segment => !safeSegment(segment))) {
      refused.push({ reference, reason: 'the relative path is absolute, empty, or holds . or ..' });
      continue;
    }
    const name = segments[segments.length - 1] as string
    const parents = segments.slice(0, -1);
    let handle: Awaited<ReturnType<typeof open>> | undefined
    try {
      const sourceDirectory = await realDirectory(input.scratch, parents);
      const source = join(sourceDirectory, name)
      const before = await lstat(source)
      if (before.isSymbolicLink()) throw new Error(source + ' is a symbolic link');
      if (!before.isFile()) throw new Error(source + ' is not a regular file');
      if (before.nlink !== 1) throw new Error(source + ' has ' + String(before.nlink) + ' links; a promoted artifact has exactly one');
      if (before.size > input.limits.perFile) throw new Error(source + ' holds more than ' + String(input.limits.perFile) + ' bytes');
      if (used + before.size > input.limits.total) throw new Error('the promoted artifacts would exceed ' + String(input.limits.total) + ' bytes together');
      handle = await open(source, constants.O_RDONLY | constants.O_NOFOLLOW | (constants.O_NONBLOCK ?? 0));
      const opened = await handle.stat()
      if (!opened.isFile() || opened.nlink !== 1) throw new Error(source + ' changed type or link count while it was opened');
      const bytes = await readBounded(handle, input.limits.perFile);
      const after = await handle.stat()
      if (after.ino !== opened.ino || after.dev !== opened.dev || after.size !== opened.size || after.nlink !== 1) {
        throw new Error(source + ' changed while it was read');
      }
      if (bytes.length !== after.size) throw new Error(source + ' changed size while it was read');
      const destinationDirectory = await ensureDirectories(input.artifacts, parents);
      const destination = join(destinationDirectory, name)
      const created = await open(destination, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
      try {
        const createdStat = await created.stat()
        if (!createdStat.isFile() || createdStat.nlink !== 1) throw new Error(destination + ' is not a new regular file');
        await created.write(bytes, 0, bytes.length, 0);
      } finally {
        await created.close();
      }
      used += bytes.length;
      promoted.push(reference);
    } catch (error: unknown) {
      refused.push({ reference, reason: error instanceof Error ? error.message : String(error) });
    } finally {
      await handle?.close().catch(() => undefined);
    }
  }
  return { promoted, refused };
}

/**
 * Create each missing destination directory, verifying every component stays a
 * real directory and is never reached through a symbolic link.
 * @param root - the absolute artifacts root.
 * @param segments - the parent segments, in order.
 * @returns the absolute parent directory.
 * @throws {Error} naming a component that is not a real directory.
 */
async function ensureDirectories(root: string, segments: readonly string[]): Promise<string> {
  let current = root
  for (const segment of segments) {
    current = join(current, segment)
    const entry = await lstat(current).catch(() => undefined)
    if (entry === undefined) {
      await mkdir(current).catch((error: unknown) => {
        const code = typeof error === 'object' && error !== null && 'code' in error ? String(error.code) : ''
        if (code !== 'EEXIST') throw error;
      });
      const created = await lstat(current);
      if (created.isSymbolicLink() || !created.isDirectory()) throw new Error(current + ' is not a real directory');
      continue;
    }
    if (entry.isSymbolicLink() || !entry.isDirectory()) throw new Error(current + ' is not a real directory');
  }
  return current
}

/** The roles one delegation call may start. */
export const ROLE = ['recon', 'hunt', 'verify', 'final-verify', 'critique', 'final-clean'] as const

/** One delegated role. */
export type Role = typeof ROLE[number]

/** The canonical agent-id prefix of each role, which names its directory. */
const PREFIX: Readonly<Record<Role, string>> = {
  recon: 'recon',
  hunt: 'hunter',
  verify: 'verifier',
  'final-verify': 'final-verifier',
  critique: 'critic',
  'final-clean': 'final-clean',
}

/** The Windows device names the skill refuses as agent ids. */
const DEVICE_NAMES = new Set(['con', 'prn', 'aux', 'nul', 'com1', 'com2', 'com3', 'com4', 'com5', 'com6', 'com7', 'com8', 'com9', 'lpt1', 'lpt2', 'lpt3', 'lpt4', 'lpt5', 'lpt6', 'lpt7', 'lpt8', 'lpt9'])

/**
 * Whether an id is a canonical agent id: lowercase, at most 64 characters,
 * a letter or digit first, and never a Windows device name.
 * @param id - the candidate id.
 * @returns whether the skill accepts it.
 */
export function isCanonicalAgentId(id: string): boolean {
  return /^[a-z0-9][a-z0-9_-]{0,63}$/u.test(id) && !DEVICE_NAMES.has(id)
}

/**
 * The role's brief kind, which its gate and its model route both key off.
 * @param role - the delegated role.
 * @returns the brief kind.
 */
function kindOf(role: Role): BriefKind {
  switch (role) {
    case 'recon': return 'recon'
    case 'hunt': return 'hunt'
    case 'verify': return 'verify'
    case 'final-verify': return 'final-verify'
    case 'critique': return 'critique'
    case 'final-clean': return 'final-critique'
  }
}

/**
 * The `outputSchema` a role's child is held to, when the provider supports one.
 * @param role - the delegated role.
 * @returns the schema.
 */
function schemaOf(role: Role): ObjectJsonSchema {
  switch (role) {
    case 'recon': return RECON_RESULT
    case 'hunt': return HUNTER_RESULT
    case 'verify': return VERIFIER_RESULT
    case 'final-verify': return FINAL_VERIFIER_RESULT
    case 'critique':
    case 'final-clean': return CRITIC_RESULT
  }
}

/**
 * The network a role's scratch directory resolves to, asked of the same
 * resolver the sandbox policy asks (owner ruling A641: a subdirectory inherits
 * its workspace's setting).
 * @param ctx - the plugin context.
 * @param workspaceRoot - the role's scratch directory.
 * @returns the network, or `undefined` when no resolver decides one.
 */
function networkAt(ctx: Context, workspaceRoot: string): SandboxNetwork | undefined {
  return ctx.get('sandboxNetwork')?.({ workspaceRoot })
}

/**
 * Why a role may not start in this workspace, if it may not.
 * @param ctx - the plugin context.
 * @param scratch - the role's scratch directory.
 * @returns the reason, or `undefined` when the role may start.
 */
export function isolationProblem(ctx: Context, scratch: string): string | undefined {
  const network = networkAt(ctx, scratch);
  if (network === undefined) {
    return 'this install decides no sandbox network for ' + scratch + ', so the audit cannot prove the off network the skill requires. Turn on the sandbox network setting for this workspace (Settings, Network) and retry.';
  }
  if (network.mode !== 'off') {
    return 'the audit workspace\u2019s network is ' + network.mode + ' at ' + scratch + '. Set this workspace\u2019s network to off (Settings, Network) before starting a role.';
  }
  return undefined;
}

/**
 * The composed sandbox mode a role's subdirectory cwd resolves to: a session
 * cwd takes the composed default rather than a full-access consent granted for
 * the workspace root, whose consent is keyed by the exact directory.
 * @param ctx - the plugin context.
 * @returns the mode, or `workspace-write` when no policy service is mounted.
 */
function sandboxModeAt(ctx: Context): SandboxMode {
  return ctx.get('sandboxPolicy')?.resolve({}).mode ?? 'workspace-write';
}

/** One role's prepared work: its working copy, its artifacts root, and what the copy holds. */
interface RoleWork {
  /** The absolute working copy, the role's cwd and only writable root. */
  readonly work: string
  /** The run-owned directory its named artifacts are promoted into. */
  readonly artifacts: string
  /** The copy's record, as the run metadata states it. */
  readonly copy: WorkCopy
}

/**
 * How many working copies the run holds now: a reserved copy counts, and a
 * removed one does not.
 * @param state - the run's state.
 * @returns the count.
 */
function liveCopies(state: HarnessState): number {
  return Object.values(state.agents).filter(entry => entry.work !== undefined && entry.work.removed_at === null).length
}

/**
 * Make a role's working copy and its artifacts root, refusing a symbolic link
 * or a special file where a directory belongs and refusing to copy when the
 * run holds its cap of copies or the disk is below its floor.
 * @param input - the run, its target, its state, the role's agent id and the call's signal.
 * @returns the copy and the artifacts root.
 * @throws {Error} naming the cap or the floor and what a copy measures, or the target's missing revision.
 */
async function prepareRoleWork(input: {
  readonly run: RunLocation
  readonly target: string
  readonly state: HarnessState
  readonly agentId: string
  readonly signal: AbortSignal
}): Promise<RoleWork> {
  if (!isCanonicalAgentId(input.agentId)) throw new Error('agent id ' + JSON.stringify(input.agentId) + ' is not canonical')
  if (input.state.source_ref.commit === null) {
    throw new Error('this target has no Git commit, so there is no reviewed revision to copy: the audit copies the target with git archive, so commit the target and start the run again')
  }
  const artifacts = inRun(input.run, 'agents/' + input.agentId + '/artifacts')
  await ensureDirectory(artifacts)
  // The role's own slot is reserved before its copy is made, so it does not count against the cap here.
  const own = input.state.agents[input.agentId]?.work
  const problem = copyGateProblem({
    live: liveCopies(input.state) - (own !== undefined && own.removed_at === null ? 1 : 0),
    freeBytes: await freeDiskBytes(input.run.dir),
    measured: input.state.copy_measurement,
  })
  if (problem !== undefined) throw new Error(problem)
  const work = inRun(input.run, 'agents/' + input.agentId + '/work')
  const copy = await createWorkCopy({
    target: input.target,
    revision: input.state.source_ref.commit,
    destination: work,
    reviewed: !input.state.source_ref.dirty,
    signal: input.signal,
  })
  return { work, artifacts, copy: { ...copy, path: 'agents/' + input.agentId + '/work' } }
}

/**
 * Record what a role's copy measured, once it has been made, so the run's
 * metadata states the cost and the next role's gate can state it too.
 * @param files - the run's file access.
 * @param run - the run.
 * @param agentId - the role's agent id.
 * @param copy - the copy's record.
 */
async function recordRoleWork(files: RunContext['files'], run: RunLocation, agentId: string, copy: WorkCopy): Promise<void> {
  await mutate(files, run, async (state) => {
    const entry = state.agents[agentId]
    if (entry !== undefined) entry.work = copy
    state.copy_measurement = { bytes: copy.bytes, files: copy.files }
    return { value: undefined }
  })
}

/**
 * Remove a role's working copy when it finishes, keeping its artifacts, and
 * record that it is gone.
 * @param ctx - the plugin context, for a removal that failed.
 * @param context - the run context.
 * @param agentId - the role's agent id.
 */
async function releaseRoleWork(ctx: Context, context: RunContext, agentId: string): Promise<void> {
  try {
    await stopNestedHarnesses({ ctx, context, agentId })
  } catch (error: unknown) {
    ctx.logger.warn('security-audit: stopping the nested harness of %s failed: %s', agentId, error instanceof Error ? error.message : String(error))
  }
  const work = inRun(context.run, 'agents/' + agentId + '/work')
  try {
    await removeWorkCopy(work)
  } catch (error: unknown) {
    ctx.logger.warn('security-audit: removing the working copy of %s failed: %s', agentId, error instanceof Error ? error.message : String(error))
  }
  await mutate(context.files, context.run, async (state) => {
    const entry = state.agents[agentId]
    if (entry?.work !== undefined && entry.work.removed_at === null) entry.work = { ...entry.work, removed_at: now() }
    return { value: undefined }
  })
}

/**
 * Create one directory and every missing parent, never through a symbolic link.
 * @param directory - the absolute directory.
 */
async function ensureDirectory(directory: string): Promise<void> {
  const entry = await lstat(directory).catch(() => undefined);
  if (entry !== undefined) {
    if (entry.isSymbolicLink() || !entry.isDirectory()) throw new Error(directory + ' is not a real directory');
    return;
  }
  await mkdir(directory, { recursive: true });
  const created = await lstat(directory);
  if (created.isSymbolicLink() || !created.isDirectory()) throw new Error(directory + ' is not a real directory');
}

/** The facts one brief states about its run. */
function briefRunOf(input: {
  readonly context: RunContext;
  readonly agentId: string;
  readonly scratch: string;
  readonly artifacts: string;
  readonly ctx: Context;
  readonly config: Config;
}): BriefRun {
  const state = input.context.state;
  const provider = input.ctx.get('subagents')?.getProvider(input.config.provider);
  return {
    runId: input.context.run.runId,
    target: input.context.target,
    repoName: state.repo_name,
    profile: state.profile,
    scopePaths: state.scope_paths,
    source: { commit: state.source_ref.commit, dirty: state.source_ref.dirty, capturedAt: state.source_ref.captured_at },
    priorRuns: state.prior_runs,
    scratch: input.scratch,
    artifacts: input.artifacts,
    agentId: input.agentId,
    sandboxMode: sandboxModeAt(input.ctx),
    schemaEnforced: provider?.capabilities.outputSchema === true,
  };
}

/**
 * Allocate a canonical agent id, honouring a requested one and never repeating
 * an id this run already used.
 * @param state - the run's state.
 * @param role - the delegated role.
 * @param requested - the id the coordinator asked for, if any.
 * @returns the id.
 * @throws {Error} when a requested id is not canonical or is already used.
 */
function allocateAgentId(state: HarnessState, role: Role, requested: string | undefined): string {
  if (requested !== undefined) {
    if (!isCanonicalAgentId(requested)) throw new Error('agent id ' + JSON.stringify(requested) + ' is not a canonical lowercase id such as recon-1');
    if (state.agents[requested] !== undefined) throw new Error('agent id ' + requested + ' is already used in this run');
    return requested;
  }
  const prefix = PREFIX[role];
  for (let sequence = (state.next_seq[prefix] ?? 0) + 1; sequence < 1000; sequence++) {
    const candidate = prefix + '-' + String(sequence);
    if (state.agents[candidate] !== undefined) continue;
    state.next_seq[prefix] = sequence;
    return candidate;
  }
  throw new Error('this run cannot allocate another ' + prefix + ' agent id');
}

/**
 * A retry's id, derived from the refused one.
 * @param state - the run's state.
 * @param base - the first attempt's id.
 * @param attempt - the attempt number.
 * @returns a fresh canonical id.
 */
function retryAgentId(state: HarnessState, base: string, attempt: number): string {
  for (let suffix = 0; suffix < 100; suffix++) {
    const candidate = (base.slice(0, 50) + '-r' + String(attempt + 1) + (suffix === 0 ? '' : '-' + String(suffix)));
    if (state.agents[candidate] === undefined && isCanonicalAgentId(candidate)) return candidate;
  }
  throw new Error('this run cannot allocate a retry id for ' + base);
}

/**
 * The model route one role runs on: the run's choice, the deployment default, then
 * inheritance from the chat.
 * @param config - the plugin configuration.
 * @param state - the run's state.
 * @param role - the delegated role.
 * @returns the agent options to request, empty when the role inherits the chat's route.
 */
function modelOptions(config: Config, state: HarnessState, role: Role): AgentOptions {
  const kind = kindOf(role);
  const route = routeFor(config.models, runModelChoices(state.models), modeledRoleOf(kind === 'final-critique' ? 'critique' : kind));
  const options: AgentOptions = {};
  if (route.provider !== undefined) options.provider = route.provider;
  if (route.model !== undefined) options.model = route.model;
  if (route.reasoningEffort !== undefined) options.reasoningEffort = route.reasoningEffort as NonNullable<AgentOptions['reasoningEffort']>;
  return options;
}

/** What one refused or accepted attempt yields. */
interface AttemptResult {
  /** The structured result, when one arrived. */
  readonly value: Record<string, unknown>;
  /** Why the result was refused; empty when it was accepted. */
  readonly problems: string[];
  /** The promoted artifacts. */
  readonly promoted: readonly string[];
  /** The child Session id, for the claim record. */
  readonly childId?: string | undefined;
  /** The route the child actually ran on. */
  readonly model: ModelRoute | undefined;
}

/**
 * The artifact references a result names, which promotion must consider.
 * @param role - the delegated role.
 * @param value - the result.
 * @returns the references, deduplicated.
 */
function artifactRefs(role: Role, value: Record<string, unknown>): string[] {
  const refs: string[] = [];
  const collect = (checks: unknown): void => {
    if (!Array.isArray(checks)) return;
    for (const check of checks) {
      if (typeof check !== 'object' || check === null) continue;
      const artifact = (check as { artifact?: unknown }).artifact;
      if (typeof artifact === 'string' && artifact.length > 0) refs.push(artifact);
    }
  };
  if (role === 'hunt') {
    const units = value.units;
    if (Array.isArray(units)) for (const unit of units) collect((unit as { checks?: unknown }).checks);
  }
  if (role === 'verify') collect(value.checks);
  return [...new Set(refs)];
}

/**
 * The structured value a settled child returned: its enforced structured result,
 * else the single JSON object its text output holds.
 * @param structured - `SubagentResult.structured`.
 * @param output - `SubagentResult.output`.
 * @returns the value, or `undefined` when the child returned none.
 */
function structuredValue(structured: unknown, output: readonly unknown[]): Record<string, unknown> | undefined {
  if (typeof structured === 'object' && structured !== null && !Array.isArray(structured)) return structured as Record<string, unknown>;
  const text = output
    .map(block => (typeof block === 'object' && block !== null && 'text' in block && typeof block.text === 'string' ? block.text : ''))
    .join('\n')
    .trim();
  const start = text.indexOf('{');
  const end = text.lastIndexOf('}');
  if (start < 0 || end <= start) return undefined;
  try {
    const value = JSON.parse(text.slice(start, end + 1)) as unknown;
    return typeof value === 'object' && value !== null && !Array.isArray(value) ? value as Record<string, unknown> : undefined;
  } catch {
    return undefined;
  }
}

/**
 * Start one child, wait for its result, promote what it named and gate it.
 * @param input - the plugin context, configuration, run context, parent agent and the attempt's facts.
 * @returns the attempt's outcome.
 */
async function runAttempt(input: {
  readonly ctx: Context;
  readonly config: Config;
  readonly context: RunContext;
  readonly parent: Agent;
  readonly role: Role;
  readonly agentId: string;
  readonly assigned: readonly string[];
  readonly ownedUnits: readonly LedgerUnit[];
  readonly brief: string;
  /** The role's working copy: its cwd, and the root its named artifacts are promoted from. */
  readonly work: string;
  readonly artifacts: string;
  readonly signal: AbortSignal;
}): Promise<AttemptResult> {
  const subagents = input.ctx.get('subagents');
  if (subagents === undefined) throw new Error('the audit needs the subagent service to start a role');
  const provider = subagents.getProvider(input.config.provider);
  if (provider === undefined) throw new Error('the subagent provider ' + JSON.stringify(input.config.provider) + ' is not registered; check the plugin configuration');
  const depth = subagents.resolveMaxDepth();
  if (depth !== undefined && depth < 1) throw new Error('subagent delegation is disabled by this installation\u2019s maxDepth setting');
  const schema = schemaOf(input.role);
  const options = modelOptions(input.config, input.context.state, input.role);
  const started = await subagents.startActivation({
    provider: input.config.provider,
    label: input.role + ' ' + input.agentId,
    prompt: [{ type: 'text', text: input.brief }],
    parent: input.parent,
    cwd: input.work,
    maxDepth: depth === undefined ? 1 : Math.min(depth, 1),
    ...provider.capabilities.outputSchema ? { outputSchema: schema } : {},
    ...Object.keys(options).length === 0 ? {} : { agentOptions: options },
    signal: input.signal,
    delivery: 'caller',
  });
  rememberClaim(started.childId, input.context.run, input.agentId);
  const childAgent = input.ctx.get('agents')?.get(started.childId);
  const model = childAgent === undefined ? undefined : modelOf(childAgent);
  let result: Awaited<typeof started.result>;
  try {
    result = await started.result;
  } finally {
    forgetClaim(started.childId);
    await started.dispose().catch((error: unknown) => {
      input.ctx.logger.warn('security-audit: disposing %s failed: %s', input.agentId, error instanceof Error ? error.message : String(error));
    });
  }
  if (result.stopReason !== 'completed') {
    const detail = result.diagnostic === undefined ? '' : ': ' + result.diagnostic;
    return { value: {}, problems: ['the ' + input.role + ' ended with ' + result.stopReason + detail], promoted: [], childId: started.childId, model };
  }
  const value = structuredValue(result.structured, result.output);
  if (value === undefined) return { value: {}, problems: ['the ' + input.role + ' returned no structured result object'], promoted: [], childId: started.childId, model };
  const outcome = await promoteArtifacts({
    scratch: input.work,
    artifacts: input.artifacts,
    agentId: input.agentId,
    references: artifactRefs(input.role, value),
    limits: { perFile: MAX_ARTIFACT_BYTES, total: MAX_PROMOTED_BYTES },
  });
  const problems = outcome.refused.map(refusal => 'artifact ' + refusal.reference + ' was not promoted: ' + refusal.reason);
  const gate: GateContext = {
    agentId: input.agentId,
    assigned: input.assigned,
    promoted: new Set(outcome.promoted),
    ownedUnits: input.ownedUnits,
    scopePaths: input.context.state.scope_paths,
  };
  const kind = kindOf(input.role);
  const gateKind = kind === 'final-critique' ? 'critique' : kind;
  problems.push(...resultProblems(gateKind, value, gate));
  return { value, problems, promoted: outcome.promoted, childId: started.childId, model };
}

/** A check-in boundary the run can pause at. */
type CheckInStage = 'after_recon' | 'after_wave' | 'after_validation' | 'after_final_verification'

/** What the recorded critics of a run said. */
interface CritiqueOutcomes {
  /** How many post-wave critic passes are recorded. */
  readonly postWave: number;
  /** Whether a distinct final-clean pass is recorded. */
  readonly finalCleanDone: boolean;
  /** Whether the newest post-wave pass accepted no work. */
  readonly lastPostWaveClean: boolean;
}

/**
 * Whether a critic result accepted no work.
 * @param value - the critic's structured result.
 * @returns whether it proposed no unit and reopened none.
 */
function cleanCritique(value: unknown): boolean {
  if (typeof value !== 'object' || value === null) return false;
  const missing = (value as { missing_units?: unknown }).missing_units;
  const reassign = (value as { reassign_ids?: unknown }).reassign_ids;
  return Array.isArray(missing) && Array.isArray(reassign) && missing.length === 0 && reassign.length === 0;
}

/**
 * Read what the run's recorded critic passes said, from their durable results.
 * @param context - the run context.
 * @returns the outcomes.
 */
async function critiqueOutcomes(context: RunContext): Promise<CritiqueOutcomes> {
  let postWave = 0;
  let finalCleanDone = false;
  let lastPostWaveClean = false;
  for (const entry of Object.values(context.state.agents)) {
    if ((entry.kind !== 'critique' && entry.kind !== 'final-critique') || entry.status !== 'recorded' || entry.result === undefined) continue;
    const value = await context.files.readJson(inRun(context.run, entry.result));
    if (entry.kind === 'final-critique') finalCleanDone = true;
    else {
      postWave += 1;
      lastPostWaveClean = cleanCritique(value);
    }
  }
  return { postWave, finalCleanDone, lastPostWaveClean };
}

/**
 * The stages one check-in mode pauses at.
 * @param mode - the mode agreed at intake.
 * @returns the stages, in run order.
 */
function stagesOf(mode: CheckIn): CheckInStage[] {
  switch (mode) {
    case 'straight_through': return [];
    case 'after_recon': return ['after_recon'];
    case 'every_stage': return ['after_recon', 'after_wave', 'after_validation', 'after_final_verification'];
  }
}

/** The check-in boundary a finished role reaches, if any. */
function stageAfter(input: {
  readonly role: Role;
  readonly state: HarnessState;
  readonly ledger: readonly LedgerUnit[];
  readonly candidates: readonly CandidateEntry[];
  readonly outcomes: CritiqueOutcomes;
}): CheckInStage | undefined {
  const recorded = Object.values(input.state.agents).filter(entry => entry.status === 'recorded');
  if (input.role === 'recon') {
    const recon = recorded.filter(entry => entry.kind === 'recon').length;
    return recon >= 4 ? 'after_recon' : undefined;
  }
  if (input.role === 'critique') return 'after_wave';
  if (input.role === 'verify') {
    const unvalidated = input.candidates.filter(candidate => candidate.verifications.length === 0 && candidate.status !== 'rejected').length;
    return unvalidated === 0 && input.candidates.length > 0 ? 'after_validation' : undefined;
  }
  if (input.role === 'final-verify') {
    const records = input.candidates.filter(candidate => candidate.status !== 'rejected');
    return records.length > 0 && records.every(candidate => candidate.final_verified) ? 'after_final_verification' : undefined;
  }
  return undefined;
}

/** What the coordinator must do at a due check-in. */
const CHECK_IN_INSTRUCTION: Readonly<Record<CheckInStage, string>> = {
  after_recon: 'Report the architecture summary, the seeded coverage count by surface and the budget so far to the person, then wait for their reply before hunting.',
  after_wave: 'Report this wave\u2019s units closed, candidates raised and budget spent to the person, then wait for their reply before the next wave.',
  after_validation: 'Report every candidate with its verdict and the remaining validation plan to the person, then wait for their reply before final verification.',
  after_final_verification: 'Report the verified records and what the report will claim to the person, then wait for their reply before writing it.',
};

/** A check-in that is due. */
export interface CheckInDue {
  /** The stage the run reached. */
  readonly stage: CheckInStage;
  /** What the coordinator must report and wait for. */
  readonly instruction: string;
}

/**
 * Decide whether a finished role reached a check-in the run has not paused at
 * yet, and record it as reached.
 * @param context - the run context.
 * @param stage - the boundary the role reached, if any.
 * @returns the check-in, when one is due now.
 */
async function checkInFrom(context: RunContext, stage: CheckInStage | undefined): Promise<CheckInDue | undefined> {
  if (stage === undefined) return undefined;
  if (!stagesOf(context.state.check_in).includes(stage)) return undefined;
  const path = inRun(context.run, 'harness/check-ins.json');
  const recorded = await context.files.readJson(path);
  const done: string[] = [];
  if (typeof recorded === 'object' && recorded !== null && 'done' in recorded && Array.isArray(recorded.done)) {
    for (const entry of recorded.done) if (typeof entry === 'string') done.push(entry);
  }
  if (done.includes(stage)) return undefined;
  await context.files.writeJson(path, { done: [...done, stage] });
  return { stage, instruction: CHECK_IN_INSTRUCTION[stage] };
}

/** The run's state, ledger and candidates, read together under the run lock. */
interface RunFiles {
  /** The run's bookkeeping state. */
  readonly state: HarnessState;
  /** Its coverage ledger. */
  readonly ledger: LedgerUnit[];
  /** Its candidate store. */
  readonly candidates: CandidateEntry[];
}

/**
 * Read the run's three mutable stores.
 * @param files - the run's file access.
 * @param run - the run.
 * @returns the stores.
 */
async function readRun(files: RunContext['files'], run: RunLocation): Promise<RunFiles> {
  return {
    state: await readState(files, run),
    ledger: parseLedger(await files.readJson(inRun(run, 'coverage-ledger.json'))),
    candidates: await readCandidates(files, run),
  };
}

/** The changes one mutation returns. */
interface Mutation<T> {
  /** What the caller receives. */
  readonly value: T;
  /** The ledger to write, when the operation changed it. */
  readonly ledger?: LedgerUnit[] | undefined;
  /** The candidate store to write, when the operation changed it. */
  readonly candidates?: CandidateEntry[] | undefined;
}

/**
 * Apply one change to the run's stores under the run lock, then rewrite the
 * derived `run-metadata.json` when a store changed.
 * @param files - the run's file access.
 * @param run - the run.
 * @param op - the change, given the current stores.
 * @returns the change's value.
 */
async function mutate<T>(
  files: RunContext['files'],
  run: RunLocation,
  op: (state: HarnessState, ledger: LedgerUnit[], candidates: CandidateEntry[]) => Promise<Mutation<T>>,
): Promise<T> {
  return await withRunLock(run, async () => {
    const snapshot = await readRun(files, run);
    const result = await op(snapshot.state, snapshot.ledger, snapshot.candidates);
    if (result.ledger !== undefined) await writeLedger(files, run, result.ledger);
    if (result.candidates !== undefined) await writeCandidates(files, run, result.candidates);
    await files.writeJson(inRun(run, STATE_FILE), snapshot.state);
    if (result.ledger !== undefined || result.candidates !== undefined) {
      await writeRunMetadata(files, run, snapshot.state, result.ledger ?? snapshot.ledger, result.candidates ?? snapshot.candidates);
    }
    return result.value;
  });
}

/** The budget gate's verdict for one role. */
interface BudgetVerdict {
  /** Whether the role may start. */
  readonly ok: boolean;
  /** What refuse the role, when it may not start. */
  readonly problems: readonly string[];
  /** The hunter assignments a wave may start. */
  readonly hunters?: number | undefined;
  /** Why a wave's units are deferred instead of hunted. */
  readonly defer?: BudgetReason | undefined;
  /** Why the run records itself incomplete, when it must. */
  readonly incomplete?: BudgetReason | undefined;
}

/**
 * Apply the skill's cost budget before a role starts (SKILL.md, Cost budget):
 * the strict pre-reconnaissance gate, the reserve before every hunter wave, the
 * critic reserve and the validation reserve.
 * @param input - the run's accounting and the role about to start.
 * @returns the verdict.
 */
function budgetVerdict(input: {
  readonly state: HarnessState;
  readonly role: Role;
  readonly requested: number;
  readonly candidates: number;
  readonly outcomes: CritiqueOutcomes;
}): BudgetVerdict {
  const { budget, profile, invocations } = input.state;
  if (budget === null) return { ok: true, problems: [], ...input.role === 'hunt' ? { hunters: input.requested } : {} };
  const remaining = budget - invocations;
  switch (input.role) {
    case 'recon': {
      const gate = reconnaissanceGate({ profile, budget, spent: invocations });
      if (!gate.ok) {
        return {
          ok: false,
          problems: [budgetSummary({ budget, gateway: gate, proposed: false }) ?? 'the budget cannot fund the reconnaissance pass'],
          incomplete: 'budget_cannot_fund_reconnaissance_and_reserves',
        };
      }
      return { ok: true, problems: [] };
    }
    case 'hunt': {
      const gate = waveGate({ profile, budget, spent: invocations, requested: input.requested, candidates: input.candidates });
      if (gate.stop !== undefined) {
        return {
          ok: true,
          problems: [],
          hunters: 0,
          defer: gate.stop,
          ...gate.stop === 'critic_budget_exhausted' ? { incomplete: gate.stop } : {},
        };
      }
      return { ok: true, problems: [], hunters: gate.hunters };
    }
    case 'critique': {
      const critics = criticCalls(profile);
      const needed = 1 + (input.outcomes.finalCleanDone ? 0 : critics.finalClean);
      if (remaining < needed) {
        return {
          ok: false,
          problems: ['the budget has ' + String(Math.max(0, remaining)) + ' agent call(s) left, and a post-wave critic needs one while the final-clean critic keeps its own reserve'],
          incomplete: 'critic_budget_exhausted',
        };
      }
      return { ok: true, problems: [] };
    }
    case 'final-clean': {
      if (remaining < 1) {
        return { ok: false, problems: ['the budget has no agent call left for the final-clean critic'], incomplete: 'critic_budget_exhausted' };
      }
      return { ok: true, problems: [] };
    }
    case 'verify':
    case 'final-verify': {
      const gate = validationGate({ budget, spent: invocations, candidates: 1 });
      if (gate.canValidate < 1) {
        return {
          ok: false,
          problems: ['the budget has no agent call left to validate this candidate; the run stops hunting and reports itself incomplete'],
          incomplete: 'validation_budget_exhausted',
        };
      }
      return { ok: true, problems: [] };
    }
  }
}

/**
 * Record a refused attempt: release an unclaimed invocation, fail the agent
 * entry, return its units to `planned`, and keep the refused result for the
 * next attempt and for the person reading the run.
 * @param files - the run's file access.
 * @param run - the run.
 * @param input - the agent, its assignment, why it was refused and what it returned.
 */
async function failDelegation(input: {
  readonly files: RunContext['files'];
  readonly run: RunLocation;
  readonly agentId: string;
  readonly reason: string;
  readonly assigned: readonly string[];
  readonly value?: Record<string, unknown> | undefined;
}): Promise<void> {
  await mutate(input.files, input.run, async (state, ledger) => {
    const entry = state.agents[input.agentId];
    if (entry !== undefined) {
      if (entry.status === 'briefed' && entry.claimed_by === undefined) {
        state.invocations = Math.max(0, state.invocations - 1);
      }
      entry.status = 'failed';
      entry.refused_results += 1;
    }
    const nextLedger = ledger.map(unit => unit.status === 'in_progress' && unit.agent_id === input.agentId
      ? { ...unit, status: 'planned' as const, agent_id: null }
      : unit);
    await input.files.write(inRun(input.run, 'agents/' + input.agentId + '/refused.md'), input.reason + '\n');
    if (input.value !== undefined) await input.files.writeJson(inRun(input.run, 'agents/' + input.agentId + '/refused.json'), input.value);
    return { value: undefined, ledger: nextLedger };
  });
}

/**
 * The units a critic's proposed gaps become, with their canonical references.
 * @param missing - the critic's `missing_units`.
 * @returns the seeds.
 * @throws {Error} when a proposed unit's starting paths are not strings.
 */
function unitSeeds(missing: readonly Record<string, unknown>[]): UnitSeed[] {
  const seeds: UnitSeed[] = [];
  for (const entry of missing) {
    const startingPaths = entry.starting_paths;
    if (!Array.isArray(startingPaths) || startingPaths.some(path => typeof path !== 'string')) throw new Error('a critic unit names string starting_paths');
    const strings = (value: unknown): string[] => Array.isArray(value) ? value.filter((item): item is string => typeof item === 'string') : [];
    const excluded = Array.isArray(entry.excluded_blocks)
      ? entry.excluded_blocks.filter((item): item is { block: string; reason: string } => typeof item === 'object' && item !== null && typeof (item as { block?: unknown }).block === 'string' && typeof (item as { reason?: unknown }).reason === 'string')
      : [];
    seeds.push({
      canonical_refs: {
        surface: String(entry.surface),
        boundary: String(entry.boundary),
        subsystem: String(entry.subsystem),
        attack_class: String(entry.attack_class),
      },
      surface: String(entry.surface),
      boundary: String(entry.boundary),
      subsystem: String(entry.subsystem),
      attack_class: String(entry.attack_class),
      starting_paths: startingPaths as string[],
      ordinary_attack_class_block: null,
      selected_companion_blocks: strings(entry.selected_companion_blocks),
      excluded_blocks: excluded,
    });
  }
  return seeds;
}

/**
 * Apply one accepted result to the ledger, the candidate store and the run state.
 * @param context - the run context.
 * @param role - the role that returned it.
 * @param agentId - its agent id.
 * @param value - its structured result.
 * @param model - the route it ran on.
 * @returns a short summary for the tool answer.
 */
async function applyResult(input: {
  readonly context: RunContext;
  readonly role: Role;
  readonly agentId: string;
  readonly value: Record<string, unknown>;
  readonly model: ModelRoute | undefined;
  readonly promoted: readonly string[];
}): Promise<Record<string, Json>> {
  const { context, role, agentId, value } = input;
  const resultPath = 'agents/' + agentId + '/result.json';
  return await mutate<Record<string, Json>>(context.files, context.run, async (state, ledger, candidates) => {
    await context.files.writeJson(inRun(context.run, resultPath), value);
    const entry = state.agents[agentId];
    if (entry !== undefined) {
      entry.status = 'recorded';
      entry.result = resultPath;
      entry.recorded_at = now();
      if (input.model !== undefined) entry.model = input.model;
      entry.promoted = [...input.promoted];
    }
    if (role === 'recon') {
      await context.files.writeJson(inRun(context.run, 'harness/recon/' + agentId + '.json'), value);
      state.stage = 'reconnaissance';
      const answer: Record<string, Json> = { facts: jsonOf(value.facts), gaps: jsonOf(value.gaps) };
      return { value: answer, ledger };
    }
    if (role === 'hunt') {
      const units = value.units as HunterUnitResult[];
      const hardening = (value.hardening ?? []) as string[];
      const nextLedger = applyHunterResult(ledger, agentId, units, hardening);
      let nextCandidates = candidates;
      for (const raw of (value.candidates ?? []) as Record<string, unknown>[]) {
        const record = proposedRecord(raw);
        const fingerprint = String(record.fingerprint);
        const linked = units.filter(unit => unit.candidate_fingerprints.includes(fingerprint)).map(unit => unit.coverage_id);
        nextCandidates = upsertCandidate(nextCandidates, record, agentId, linked).candidates;
      }
      const dispositions = Object.fromEntries(units.map(unit => [unit.coverage_id, unit.disposition]));
      state.stage = 'hunting';
      const answer: Record<string, Json> = { units: jsonOf(dispositions), candidates: jsonOf(Array.isArray(value.candidates) ? value.candidates.length : 0), hardening: jsonOf(hardening.length) };
      return { value: answer, ledger: nextLedger, candidates: nextCandidates };
    }
    if (role === 'verify') {
      const decision = value.decision as 'confirmed' | 'needs_validation' | 'rejected';
      const record = value.record as Record<string, unknown>;
      const checks = (value.checks ?? []) as LedgerCheck[];
      const fingerprint = String(record.fingerprint);
      const existing = candidates.find(candidate => candidate.fingerprint === fingerprint);
      const nextCandidates = recordVerification(candidates, fingerprint, { agent_id: agentId, decision, record, checks, at: now() });
      let nextLedger = ledger;
      for (const unit of ledger) {
        const linked = unit.result_fingerprints.includes(fingerprint) || existing?.proposed_units.includes(unit.coverage_id) === true;
        if (!linked) continue;
        const carried = unit.status === 'in_progress' && unit.agent_id === agentId && !unit.result_fingerprints.includes(fingerprint);
        nextLedger = patchUnit(nextLedger, unit.coverage_id, {
          ...carried ? { status: 'candidate', agent_id: agentId, result_fingerprints: [fingerprint] } : {},
          local_checks: [...unit.local_checks, ...checks],
          reviewed_paths: [...new Set([...unit.reviewed_paths, ...checks.flatMap(check => check.reviewed_paths)])],
          ...decision === 'needs_validation' ? { unresolved: Array.isArray(record.blockers) ? record.blockers : unit.unresolved } : {},
          harness_decision: decision,
        });
      }
      state.stage = 'validation';
      const answer: Record<string, Json> = { decision: jsonOf(decision), fingerprint: jsonOf(fingerprint), checks: jsonOf(checks.length) };
      return { value: answer, ledger: nextLedger, candidates: nextCandidates };
    }
    if (role === 'final-verify') {
      const decision = value.decision as 'verified' | 'replace';
      const fingerprint = String(value.fingerprint);
      const replacement = value.record as Record<string, unknown> | undefined;
      const applied = applyFinalVerification(candidates, fingerprint, decision, agentId, replacement, value.reason as string | undefined);
      state.stage = 'final_verification';
      const answer: Record<string, Json> = { decision: jsonOf(decision), fingerprint: jsonOf(fingerprint), requires_another_verifier: jsonOf(applied.requiresVerifier), material: jsonOf(applied.material) };
      return { value: answer, candidates: applied.candidates, ledger };
    }
    const missing = (value.missing_units ?? []) as Record<string, unknown>[];
    const reassign = (value.reassign_ids ?? []) as string[];
    const seeds = unitSeeds(missing);
    let nextLedger = ledger;
    const added: string[] = [];
    const skipped: string[] = [];
    for (const seed of seeds) {
      try {
        const seeded = seedUnits(nextLedger, [seed]);
        nextLedger = seeded.ledger;
        added.push(...seeded.added);
      } catch (error: unknown) {
        const message = error instanceof Error ? error.message : String(error);
        if (!message.includes('already in the ledger')) throw error;
        skipped.push(ledgerValidator.canonicalCoverageId(seed.canonical_refs));
      }
    }
    if (reassign.length > 0) {
      const next = state.profile === 'quick' ? 'deferred' : 'planned';
      nextLedger = reassignUnits(nextLedger, reassign, 'coverage critic reopened the unit', next);
    }
    // HUNTING.md: a quick run's critic pass ends the coverage loop, so the units it
    // proposes are deferred with the skill's own reason rather than hunted.
    if (state.profile === 'quick' && added.length > 0) {
      nextLedger = closeUnits(nextLedger, added, 'deferred', 'quick_profile_final_critic');
    }
    await context.files.writeJson(inRun(context.run, 'harness/critic-resolved.json'), value.resolved_prior_leads ?? []);
    state.stage = nextLedger.some(unit => unit.status === 'planned') || reassign.length > 0 ? 'hunting' : 'validation';
    const answer: Record<string, Json> = { missing: jsonOf(missing.length), added: jsonOf(added), skipped: jsonOf(skipped), reassigned: jsonOf(reassign.length), stop: jsonOf(value.stop === true) };
    return { value: answer, ledger: nextLedger };
  });
}

/** A value as plain JSON for a tool answer. */
function jsonOf(value: unknown): Json {
  return JSON.parse(JSON.stringify(value)) as Json;
}

/** The calling agent, which owns the run. */
function requireAgent(exec: { readonly agent?: Agent | undefined }): Agent {
  if (exec.agent === undefined) throw new Error('security-audit delegation needs an owning chat session');
  return exec.agent;
}

/** A prompt or rendered answer made of text. */
function text(value: string): { readonly type: 'text'; readonly text: string }[] {
  return [{ type: 'text', text: value }];
}

/** The role an agent entry records. */
function roleOf(role: Role): AgentEntry['role'] {
  switch (role) {
    case 'recon': return 'recon'
    case 'hunt': return 'hunter'
    case 'verify':
    case 'final-verify': return 'verifier'
    case 'critique':
    case 'final-clean': return 'critic'
  }
}

/**
 * The run's own model choices, in the shape the route helper reads.
 * @param models - the routes the run recorded, when it recorded any.
 * @returns the choices, or `undefined`.
 */
function runModelChoices(models: RoleModels | undefined): RoleModelOverrides | undefined {
  if (models === undefined) return undefined;
  const choices: RoleModelOverrides = {};
  for (const [role, route] of Object.entries(models)) {
    if (route === undefined) continue;
    choices[role as ModeledRole] = {
      ...route.provider === null ? {} : { provider: route.provider },
      ...route.model === null ? {} : { model: route.model },
      ...route.reasoning_effort === null ? {} : { reasoningEffort: route.reasoning_effort },
    };
  }
  return choices;
}

/** The answer one delegation call returns. */
export interface DelegateAnswer {
  /** The role that ran. */
  readonly role: Role;
  /** Its canonical agent id. */
  readonly agent_id: string;
  /** `recorded`, or `deferred` when the budget could not fund the work. */
  readonly status: string;
  /** A short account of what changed. */
  readonly summary: Record<string, Json>;
  /** Refusals the coordinator must act on, empty when the result was recorded. */
  readonly problems: readonly string[];
  /** The budget as it now stands. */
  readonly budget: Record<string, Json>;
  /** A check-in due now, which the coordinator reports and waits on. */
  readonly check_in: Record<string, Json> | null;
}

/**
 * Register the delegation tool. The coordinator calls it once per role; four
 * reconnaissance calls or a wave's hunters in one message run in parallel.
 * @param ctx - the plugin context.
 * @param config - the agent row's configuration.
 */
export function registerDelegationTool(ctx: Context, config: Config): void {
  ctx.tools.register(defineTool({
    name: 'audit_delegate',
    presentCall: args => ({ card: 'generic', title: 'Audit ' + args.role, kind: 'other', rawInput: args }),
    description: 'Assign coverage and delegate one audit role: recon, hunt, verify, final-verify, critique or final-clean. The call composes the deterministic brief from the vendored skill, starts one fresh child in its own working copy of the reviewed tree under its structured-result schema, waits for the result, promotes the files it names, runs the validation gate and records only accepted evidence. Start the four reconnaissance calls, or a wave\u2019s hunters, in one message so they run in parallel; a check-in the answer reports must be given to the person before the next stage.',
    parameters: {
      role: { type: 'string', required: true, enum: [...ROLE], description: 'recon, hunt, verify, final-verify, critique or final-clean.' },
      coverage_ids: { type: 'array', items: { type: 'string' }, description: 'For role=hunt: the planned coverage ids, in priority order.' },
      fingerprint: { type: 'string', description: 'For role=verify or final-verify: the candidate fingerprint.' },
      focus: { type: 'string', description: 'For role=recon: 1a, 1b, 1c or 1d to run one focused reconnaissance prompt.' },
      agent_id: { type: 'string', description: 'Optional canonical lowercase agent id; omit to allocate one.' },
      note: { type: 'string', description: 'A short coordinator note appended to the brief.' },
    },
    output: {
      schema: {
        type: 'object',
        additionalProperties: false,
        properties: {
          role: { type: 'string', required: true },
          agent_id: { type: 'string', required: true },
          status: { type: 'string', required: true },
          summary: { type: 'object', required: true, additionalProperties: true },
          problems: { type: 'array', required: true, items: { type: 'string' } },
          budget: { type: 'object', required: true, additionalProperties: true },
          check_in: { oneOf: [{ type: 'object', additionalProperties: true }, { type: 'null' }], required: true },
        },
      },
      render: (_args, value) => text([
        value.role + ' ' + value.agent_id + ': ' + value.status,
        ...value.problems.length === 0 ? [] : ['', 'Problems:', ...value.problems.map(problem => '- ' + problem)],
        '',
        'Result:',
        JSON.stringify(value.summary, undefined, 2),
        ...value.check_in === null ? [] : ['', 'Check-in due at ' + value.check_in.stage + ': ' + value.check_in.instruction],
      ].join('\n')),
    },
    isConcurrencySafe: args => args.role !== 'critique' && args.role !== 'final-clean',
    async execute(args, exec) {
      const agent = requireAgent(exec);
      const context = await runContext(ctx, agent, exec.signal, config.runsDir);
      requireMutable(context.state);
      const outcomes = await critiqueOutcomes(context);
      const candidates = await readCandidates(context.files, context.run);
      await checkPreconditions(args, context, outcomes);
      const requested = args.role === 'hunt' ? args.coverage_ids?.length ?? 0 : 1;
      const verdict = budgetVerdict({ state: context.state, role: args.role, requested, candidates: candidates.filter(candidate => candidate.verifications.length === 0).length, outcomes });
      if (!verdict.ok) {
        if (verdict.incomplete !== undefined) {
          await mutate(context.files, context.run, async (state) => {
            state.run_status = 'incomplete';
            state.incomplete_reason = verdict.incomplete ?? null;
            return { value: undefined };
          });
        }
        throw new Error(verdict.problems.join('\n'));
      }
      let baseId: string | undefined;
      let lastProblems: string[] = [];
      for (let attempt = 0; attempt <= config.resultRetries; attempt++) {
        const assigned = args.role === 'hunt'
          ? [...args.coverage_ids ?? []]
          : args.role === 'verify' || args.role === 'final-verify' ? [String(args.fingerprint)] : [];
        const plan = await mutate(context.files, context.run, async (state, ledger, stored) => {
          const agentId = attempt === 0
            ? allocateAgentId(state, args.role, args.agent_id)
            : retryAgentId(state, baseId as string, attempt);
          if (attempt === 0) baseId = agentId;
          const allowed = args.role === 'hunt' ? Math.max(0, Math.min(verdict.hunters ?? assigned.length, assigned.length)) : 0;
          const hunting = args.role === 'hunt' ? assigned.slice(0, allowed) : [];
          let nextLedger = ledger;
          if (hunting.length > 0) nextLedger = assignUnits(nextLedger, hunting, agentId);
          if (args.role === 'hunt' && allowed === 0 && verdict.defer !== undefined) {
            nextLedger = closeUnits(nextLedger, assigned, 'deferred', verdict.defer);
            if (verdict.incomplete !== undefined) {
              state.run_status = 'incomplete';
              state.incomplete_reason = verdict.incomplete;
            }
            return { value: { agentId, units: [], deferred: assigned.length, assigned }, ledger: nextLedger };
          }
          if (args.role === 'verify') {
            const candidate = stored.find(entry => entry.fingerprint === String(args.fingerprint));
            const linked = ledger.filter(unit => unit.status === 'planned' && candidate?.proposed_units.includes(unit.coverage_id) === true).map(unit => unit.coverage_id);
            if (linked.length > 0) nextLedger = assignUnits(nextLedger, linked, agentId);
          }
          const units = args.role === 'hunt'
            ? nextLedger.filter(unit => hunting.includes(unit.coverage_id))
            : args.role === 'verify'
              ? nextLedger.filter(unit => unit.result_fingerprints.includes(String(args.fingerprint)) || unit.agent_id === agentId)
              : [];
          const copyProblem = copyGateProblem({
            live: liveCopies(state),
            freeBytes: await freeDiskBytes(context.run.dir),
            measured: state.copy_measurement,
          });
          if (copyProblem !== undefined) throw new Error(copyProblem);
          const entry: AgentEntry = {
            role: roleOf(args.role),
            kind: kindOf(args.role),
            brief: 'agents/' + agentId + '/brief.md',
            assigned: args.role === 'hunt' ? hunting : assigned,
            created_at: now(),
            status: 'briefed',
            refused_results: attempt,
            exec: { runs: 0, seconds: 0 },
            promoted: [],
            wave: units[0]?.wave ?? state.wave,
          };
          entry.work = {
            path: 'agents/' + agentId + '/work',
            revision: state.source_ref.commit,
            reviewed: !state.source_ref.dirty,
            bytes: 0,
            files: 0,
            seconds: 0,
            created_at: now(),
            removed_at: null,
          };
          state.agents[agentId] = entry;
          state.invocations += 1;
          return { value: { agentId, units, deferred: 0, assigned }, ledger: nextLedger };
        });
        if (plan.units.length === 0 && plan.deferred > 0) {
          const finalState = await readState(context.files, context.run);
          return {
            role: args.role,
            agent_id: plan.agentId,
            status: 'deferred',
            summary: { deferred_units: plan.deferred, reason: verdict.defer ?? '' },
            problems: [],
            budget: budgetJson(finalState),
            check_in: null,
          };
        }
        const agentId = plan.agentId;
        const prepared = await prepareRoleWork({
          run: context.run,
          target: context.target,
          state: await readState(context.files, context.run),
          agentId,
          signal: exec.signal,
        }).catch(async (error: unknown) => {
          const reason = error instanceof Error ? error.message : String(error);
          await failDelegation({ files: context.files, run: context.run, agentId, reason, assigned });
          throw error;
        });
        await recordRoleWork(context.files, context.run, agentId, prepared.copy);
        let attemptResult: AttemptResult;
        try {
          const isolation = isolationProblem(ctx, prepared.work);
          if (isolation !== undefined) {
            await failDelegation({ files: context.files, run: context.run, agentId, reason: isolation, assigned });
            throw new Error(isolation);
          }
          let brief: string;
          try {
            const snapshot = await readRun(context.files, context.run);
            brief = composeBrief({
              ctx, config, context, snapshot, agentId,
              directories: { scratch: prepared.work, artifacts: prepared.artifacts },
              role: args.role,
              candidates: snapshot.candidates,
              units: plan.units,
              note: [args.note, attempt === 0 ? undefined : 'A previous result was refused:\n' + lastProblems.join('\n')].filter(Boolean).join('\n\n') || undefined,
              focus: args.focus,
              fingerprint: args.fingerprint,
            });
            await context.files.write(inRun(context.run, 'agents/' + agentId + '/brief.md'), brief);
          } catch (error: unknown) {
            const reason = error instanceof Error ? error.message : String(error);
            await failDelegation({ files: context.files, run: context.run, agentId, reason, assigned });
            throw error;
          }
          attemptResult = await runAttempt({
            ctx, config, context, parent: agent, role: args.role, agentId,
            assigned, ownedUnits: plan.units, brief,
            work: prepared.work, artifacts: prepared.artifacts, signal: exec.signal,
          }).catch(async (error: unknown) => {
            const reason = error instanceof Error ? error.message : String(error);
            await failDelegation({ files: context.files, run: context.run, agentId, reason, assigned });
            throw error;
          });
        } finally {
          await releaseRoleWork(ctx, context, agentId);
        }
        if (attemptResult.problems.length > 0) {
          lastProblems = [...attemptResult.problems];
          await failDelegation({ files: context.files, run: context.run, agentId, reason: lastProblems.join('\n'), assigned, value: attemptResult.value });
          continue;
        }
        const summary = await applyResult({
          context, role: args.role, agentId, value: attemptResult.value, model: attemptResult.model, promoted: attemptResult.promoted,
        });
        const finalState = await readState(context.files, context.run);
        const finalLedger = parseLedger(await context.files.readJson(inRun(context.run, 'coverage-ledger.json')));
        const finalCandidates = await readCandidates(context.files, context.run);
        const stage = stageAfter({ role: args.role, state: finalState, ledger: finalLedger, candidates: finalCandidates, outcomes });
        const checkIn = await checkInFrom({ ...context, state: finalState }, stage);
        return {
          role: args.role,
          agent_id: agentId,
          status: 'recorded',
          summary,
          problems: [],
          budget: budgetJson(finalState),
          check_in: checkIn === undefined ? null : { stage: checkIn.stage, instruction: checkIn.instruction },
        };
      }
      throw new Error('the ' + args.role + ' result was refused after ' + String(config.resultRetries + 1) + ' attempt(s):\n' + lastProblems.join('\n'));
    },
  }));
  registerHarnessTool(ctx, config);
}


/** The nested harnesses this process started, by run and agent, so a stop can wait for the exit. */
const nestedHarnesses = new Map<string, { readonly child: ChildProcess; readonly port: number; readonly startedAt: string }>()

/**
 * The key one role's nested harness is held under.
 * @param run - the role's run.
 * @param agentId - the role's agent id.
 * @returns the key.
 */
function nestedKey(run: RunLocation, agentId: string): string {
  return run.dir + '\u0000' + agentId
}

/**
 * Find bubblewrap, the only runner this host offers: Landlock is absent, so a
 * nested harness is confined by bwrap alone (verified on this host, with
 * `--unshare-net` working inside the existing sandbox).
 * @returns the path of the executable, or `undefined` when it is not installed.
 */
function bwrapPath(): string | undefined {
  for (const path of ['/usr/bin/bwrap', '/bin/bwrap', '/usr/local/bin/bwrap']) {
    if (existsSync(path)) return path
  }
  return undefined
}

/**
 * The first spare port of the nested harness range that this run has not
 * already given to a nested start.
 * @param used - the ports the run's starts hold.
 * @returns the port, proved free to bind on the loopback address.
 * @throws {Error} naming the range when every one is taken.
 */
async function availablePort(used: readonly number[]): Promise<number> {
  for (const port of NESTED_PORT_RANGE) {
    if (used.includes(port)) continue
    const free = await new Promise<boolean>(resolve => {
      const server = createServer()
      server.once('error', () => { resolve(false) })
      server.listen(port, '127.0.0.1', () => { server.close(() => { resolve(true) }) })
    })
    if (free) return port
  }
  throw new Error('every port from ' + String(NESTED_PORT_RANGE[0]) + ' to ' + String(NESTED_PORT_RANGE[NESTED_PORT_RANGE.length - 1]) + ' is in use, so a nested harness cannot take a spare one; stop the process holding one and retry')
}

/** What a nested start runs: the command, its arguments and the environment of its stub provider. */
interface NestedCommand {
  /** The executable. */
  readonly command: string
  /** Its arguments. */
  readonly args: readonly string[]
  /** The environment it starts with. */
  readonly env: Readonly<Record<string, string>>
}

/**
 * The command a nested start runs and the environment that keeps it off the
 * network: a stub provider and a dummy key (see the profile patch the caller
 * writes), its own scratch HOME, and its spare port.
 * @param input - the role's working copy, its scratch HOME and its port.
 * @returns the command and its environment.
 */
function nestedCommand(input: { readonly work: string; readonly home: string; readonly port: number }): NestedCommand {
  const env: Record<string, string> = {
    PATH: '/usr/local/bin:/usr/bin:/bin',
    HOME: input.home,
    TMPDIR: input.home + '/tmp',
    DSH_HOME: input.home,
    DELORUN_HOME: input.home,
    DELORUN_PROFILE: 'nested',
    PORT: String(input.port),
    DELORUN_PORT: String(input.port),
    DEEPSEEK_API_KEY: 'dummy',
    DELORUN_MODEL_PROVIDER: 'stub',
  }
  const command = process.env['DELORUN_SECURITY_AUDIT_HARNESS'] ?? 'delorun'
  return { command, args: ['headless', 'Check that this working copy boots and exit.'], env }
}

/**
 * The bwrap argument list that confines one nested harness: its own network
 * namespace, its copy and scratch HOME writable, and the host's own files read
 * only.
 * @param input - the working copy, the scratch HOME, the port and the command.
 * @returns the executable and its arguments.
 * @throws {Error} when bwrap is not installed.
 */
function bwrapArguments(input: { readonly work: string; readonly home: string; readonly port: number; readonly run: NestedCommand }): { readonly command: string; readonly args: string[] } {
  const bwrap = bwrapPath()
  if (bwrap === undefined) {
    throw new Error('the nested harness runs under bwrap, the only confinement this host offers (it has no Landlock); install bubblewrap and retry')
  }
  const args: string[] = ['--unshare-net', '--die-with-parent', '--new-session', '--clearenv']
  for (const directory of ['/usr', '/bin', '/lib', '/lib64', '/etc', '/opt']) {
    if (existsSync(directory)) args.push('--ro-bind', directory, directory)
  }
  const nodeDirectory = dirname(process.execPath)
  if (!['/usr', '/bin', '/usr/local'].some(root => nodeDirectory === root || nodeDirectory.startsWith(root + '/'))) {
    args.push('--ro-bind', nodeDirectory, nodeDirectory)
  }
  args.push('--proc', '/proc', '--dev', '/dev', '--tmpfs', '/tmp')
  args.push('--bind', input.work, input.work, '--bind', input.home, input.home)
  args.push('--chdir', input.work)
  for (const [name, value] of Object.entries(input.run.env)) args.push('--setenv', name, value)
  args.push('--', input.run.command, ...input.run.args)
  return { command: bwrap, args }
}

/**
 * Write the stub provider a nested start uses, so it needs no network and no
 * real key: a pi-ai route named `stub` on a closed loopback port, and the
 * default-model row that selects it. The profile patch is a best effort: a
 * nested Delorun that refuses it reports its own exit, which the run records.
 * @param home - the scratch HOME, absolute.
 */
async function writeStubProfile(home: string): Promise<void> {
  const profile = join(home, 'profiles', 'nested')
  await mkdir(profile, { recursive: true, mode: 0o700 })
  const patch = [
    '# The stub provider a security-audit nested harness runs on: no network, no real key.',
    '- id: llm-pi-ai',
    '  config:',
    '    providers:',
    '      stub:',
    '        apiKeyEnv: DEEPSEEK_API_KEY',
    '        baseURL: http://127.0.0.1:9/v1',
    '        models: [stub]',
    '- id: agent-default-model',
    '  config:',
    '    provider: stub',
    '    model: stub',
    '',
  ].join('\n')
  await writeFileAsync(join(profile, 'cordis.patch.yml'), patch, { mode: 0o600 })
  const credentials = ['version: 1', 'refs:', '  DEEPSEEK_API_KEY: dummy', ''].join('\n')
  await writeFileAsync(join(home, '.credentials.yaml'), credentials, { mode: 0o600 })
}

/**
 * Start one nested Delorun from a role's working copy.
 * @param input - the plugin context, the run context, the role's agent id and its copy.
 * @returns the start, as the tool answer states it.
 * @throws {Error} naming the cap when the run has spent it, or why the start could not be made.
 */
async function startNestedHarness(input: {
  readonly ctx: Context
  readonly context: RunContext
  readonly agentId: string
  readonly copy: WorkCopy
}): Promise<Record<string, Json>> {
  const starts = input.context.state.nested_harness?.starts ?? []
  if (starts.length >= NESTED_HARNESS_CAP) {
    throw new Error('this run has already started ' + String(starts.length) + ' nested harnesses, its cap of ' + String(NESTED_HARNESS_CAP) + '; record what the last one showed and stop it before starting another')
  }
  const port = await availablePort(starts.map(start => start.port))
  const home = inRun(input.context.run, 'agents/' + input.agentId + '/nested/start-' + String(starts.length + 1) + '/home')
  await mkdir(join(home, 'tmp'), { recursive: true, mode: 0o700 })
  await chmod(home, 0o700)
  await writeStubProfile(home)
  const work = inRun(input.context.run, input.copy.path)
  const command = nestedCommand({ work, home, port })
  const wrapped = bwrapArguments({ work, home, port, run: command })
  const child = spawn(wrapped.command, wrapped.args, { cwd: work, detached: true, stdio: 'ignore' })
  const startedAt = now()
  let failure: { readonly code: number | null; readonly signal: string } | undefined
  child.on('error', (error: Error) => { failure = { code: null, signal: 'spawn error: ' + error.message } })
  const exited = new Promise<void>(resolve => {
    child.once('exit', () => { resolve() })
    child.once('error', () => { resolve() })
  })
  const raced = await Promise.race([exited.then(() => 'exited' as const), new Promise<'running'>(resolve => setTimeout(() => { resolve('running') }, 1500))])
  const start: NestedStart = {
    agent_id: input.agentId,
    port,
    home: 'agents/' + input.agentId + '/nested/start-' + String(starts.length + 1) + '/home',
    pid: child.pid ?? null,
    started_at: startedAt,
    stopped_at: raced === 'exited' ? now() : null,
    exit: raced === 'exited' ? { code: child.exitCode, signal: failure?.signal ?? child.signalCode } : null,
  }
  await mutate(input.context.files, input.context.run, async (state) => {
    state.nested_harness = { cap: NESTED_HARNESS_CAP, starts: [...state.nested_harness?.starts ?? [], start] }
    return { value: undefined }
  })
  if (start.stopped_at === null) nestedHarnesses.set(nestedKey(input.context.run, input.agentId), { child, port, startedAt })
  return {
    status: raced === 'exited' ? 'exited' : 'running',
    port,
    home: start.home,
    pid: start.pid,
    exit: start.exit === null ? null : { ...start.exit },
    starts: starts.length + 1,
    cap: NESTED_HARNESS_CAP,
    provider: 'stub',
    key: 'dummy',
    runner: bwrapPath() ?? 'none',
  }
}

/**
 * Stop one nested harness and record its exit.
 * @param input - the plugin context, the run context, the role's agent id and the port, or every running start of the role.
 * @returns how many it stopped.
 */
async function stopNestedHarnesses(input: { readonly ctx: Context; readonly context: RunContext; readonly agentId: string }): Promise<number> {
  const running = (input.context.state.nested_harness?.starts ?? []).filter(start => start.agent_id === input.agentId && start.stopped_at === null)
  if (running.length === 0) return 0
  const exits = new Map<number, { readonly code: number | null; readonly signal: string | null }>()
  for (const start of running) {
    const held = nestedHarnesses.get(nestedKey(input.context.run, input.agentId))
    const child = held?.port === start.port ? held.child : undefined
    if (child === undefined) {
      if (start.pid !== null) {
        try { process.kill(-start.pid, 'SIGTERM') } catch { /* already gone */ }
      }
      exits.set(start.port, { code: null, signal: 'not ours to wait for' })
      continue
    }
    const ended = new Promise<void>(resolve => { child.once('exit', () => { resolve() }) })
    try { process.kill(-(child.pid ?? start.pid ?? 0), 'SIGTERM') } catch { /* already gone */ }
    const timedOut = await Promise.race([ended.then(() => false), new Promise<boolean>(resolve => setTimeout(() => { resolve(true) }, 10_000))])
    if (timedOut) {
      try { process.kill(-(child.pid ?? start.pid ?? 0), 'SIGKILL') } catch { /* already gone */ }
      await Promise.race([ended, new Promise<void>(resolve => setTimeout(resolve, 2_000))])
    }
    exits.set(start.port, { code: child.exitCode, signal: child.signalCode })
    nestedHarnesses.delete(nestedKey(input.context.run, input.agentId))
  }
  await mutate(input.context.files, input.context.run, async (state) => {
    const starts = state.nested_harness?.starts
    if (starts === undefined) return { value: undefined }
    state.nested_harness = {
      cap: state.nested_harness?.cap ?? NESTED_HARNESS_CAP,
      starts: starts.map(start => start.stopped_at !== null || start.agent_id !== input.agentId
        ? start
        : { ...start, stopped_at: now(), exit: exits.get(start.port) ?? null }),
    }
    return { value: undefined }
  })
  return exits.size
}

/**
 * Register `audit_harness`: a role's bounded way to start the target harness
 * inside its own working copy. Two starts per run, each with its own scratch
 * HOME, a spare port and bwrap's network namespace, and a stop that records the
 * exit.
 * @param ctx - the plugin context.
 * @param config - the agent row's configuration.
 */
export function registerHarnessTool(ctx: Context, config: Config): void {
  ctx.tools.register(defineTool({
    name: 'audit_harness',
    presentCall: args => ({ card: 'generic', title: 'Nested harness ' + args.action, kind: 'other', rawInput: args }),
    description: 'Start or stop one nested Delorun inside your working copy, at most two starts per run. A start runs the target harness under bwrap with its own network namespace, its own scratch HOME (mode 0700), a spare port from 19988 to 19997 and a stub provider with a dummy key, so it needs no network and no real model. Use it to prove a behaviour you can only observe by running the harness; stop it afterwards, and the answer records its exit.',
    parameters: {
      action: { type: 'string', required: true, enum: ['start', 'stop'], description: 'start one nested harness from your working copy, or stop the ones you started.' },
    },
    output: {
      schema: {
        type: 'object',
        additionalProperties: false,
        properties: {
          action: { type: 'string', required: true },
          status: { type: 'string', required: true },
          port: { oneOf: [{ type: 'integer' }, { type: 'null' }], required: true },
          home: { oneOf: [{ type: 'string' }, { type: 'null' }], required: true },
          pid: { oneOf: [{ type: 'integer' }, { type: 'null' }], required: true },
          exit: { oneOf: [{ type: 'object', additionalProperties: true }, { type: 'null' }], required: true },
          stops: { type: 'integer', required: true },
          starts: { type: 'integer', required: true },
          cap: { type: 'integer', required: true },
          runner: { type: 'string', required: true },
          summary: { type: 'string', required: true },
        },
      },
      render: (_args, value) => text(value.summary),
    },
    isConcurrencySafe: () => false,
    async execute(args, exec) {
      const agent = requireAgent(exec)
      const context = await runContext(ctx, agent, exec.signal, config.runsDir)
      requireMutable(context.state)
      const claim = await claimOf(context.files, context.root, context.target, agent.session.id, coordinatingSession(ctx, agent).id)
      if (claim === undefined) throw new Error('audit_harness runs from a delegated role: this chat claimed no brief of the run')
      const entry = (await readState(context.files, claim.run)).agents[claim.agentId]
      if (entry?.work === undefined || entry.work.removed_at !== null) {
        throw new Error('your working copy is not live, so there is no tree to start the harness from; audit_harness runs only while the role that owns a copy is working')
      }
      if (args.action === 'start') {
        const answer = await startNestedHarness({ ctx, context, agentId: claim.agentId, copy: entry.work })
        return {
          action: 'start',
          status: String(answer.status),
          port: answer.port as number,
          home: String(answer.home),
          pid: answer.pid as number | null,
          exit: (answer.exit ?? null) as Record<string, Json> | null,
          stops: 0,
          starts: answer.starts as number,
          cap: answer.cap as number,
          runner: String(answer.runner),
          summary: 'nested harness ' + String(answer.status) + ' on port ' + String(answer.port) + ' with HOME ' + String(answer.home) + (answer.exit === null ? '; stop it when you are done' : '; it exited before the check could see it running'),
        }
      }
      const stopped = await stopNestedHarnesses({ ctx, context, agentId: claim.agentId })
      const after = await readState(context.files, claim.run)
      const starts = after.nested_harness?.starts ?? []
      const last = starts.filter(start => start.agent_id === claim.agentId).at(-1)
      return {
        action: 'stop',
        status: stopped === 0 ? 'nothing-running' : 'stopped',
        port: last?.port ?? null,
        home: last?.home ?? null,
        pid: last?.pid ?? null,
        exit: (last?.exit ?? null) as Record<string, Json> | null,
        stops: stopped,
        starts: starts.length,
        cap: after.nested_harness?.cap ?? NESTED_HARNESS_CAP,
        runner: bwrapPath() ?? 'none',
        summary: stopped === 0 ? 'no nested harness of yours was running' : 'stopped ' + String(stopped) + ' nested harness(es); last exit ' + JSON.stringify(last?.exit ?? null),
      }
    },
  }))
}

/** The arguments one delegation call carries. */
interface DelegationArgs {
  /** The role to start. */
  readonly role: Role;
  /** The planned coverage ids a hunt assigns. */
  readonly coverage_ids?: string[] | undefined;
  /** The candidate a verifier reviews. */
  readonly fingerprint?: string | undefined;
  /** The reconnaissance item a focused call runs. */
  readonly focus?: string | undefined;
  /** The id the coordinator asks for. */
  readonly agent_id?: string | undefined;
  /** A note appended to the brief. */
  readonly note?: string | undefined;
}

/**
 * The budget as a tool answer states it.
 * @param state - the run's state.
 * @returns the budget, what it spent and what is left.
 */
function budgetJson(state: HarnessState): Record<string, Json> {
  return {
    budget: state.budget,
    spent: state.invocations,
    remaining: state.budget === null ? null : Math.max(0, state.budget - state.invocations),
  };
}

/**
 * Refuse a role the run's current state cannot start, before it spends a call.
 * @param args - the call's arguments.
 * @param context - the run context.
 * @param outcomes - what the recorded critic passes said.
 * @throws {Error} naming what to do instead.
 */
async function checkPreconditions(args: DelegationArgs, context: RunContext, outcomes: CritiqueOutcomes): Promise<void> {
  const ledger = context.ledger;
  const candidates = await readCandidates(context.files, context.run);
  const candidate = args.fingerprint === undefined ? undefined : candidates.find(entry => entry.fingerprint === args.fingerprint);
  switch (args.role) {
    case 'recon':
      return;
    case 'hunt': {
      if (args.coverage_ids === undefined || args.coverage_ids.length === 0) throw new Error('role=hunt needs coverage_ids');
      for (const id of args.coverage_ids) {
        const unit = ledger.find(entry => entry.coverage_id === id);
        if (unit === undefined) throw new Error('coverage id ' + id + ' is not in the ledger');
        if (unit.status !== 'planned') throw new Error('coverage id ' + id + ' is ' + unit.status + '; only planned units can be delegated');
      }
      return;
    }
    case 'verify': {
      if (args.fingerprint === undefined) throw new Error('role=verify needs fingerprint');
      if (candidate === undefined) throw new Error('candidate ' + args.fingerprint + ' is not in the candidate store');
      if (candidate.verifications.length > 0) throw new Error('candidate ' + args.fingerprint + ' already has a candidate validation; use role=final-verify for its record verification');
      return;
    }
    case 'final-verify': {
      if (args.fingerprint === undefined) throw new Error('role=final-verify needs fingerprint');
      if (candidate === undefined) throw new Error('candidate ' + args.fingerprint + ' is not in the candidate store');
      if (candidate.status === 'rejected') throw new Error('candidate ' + args.fingerprint + ' was rejected; a rejected record needs no record verification');
      if (candidate.verifications.length === 0) throw new Error('candidate ' + args.fingerprint + ' has no candidate validation yet; run role=verify first');
      if (candidate.final_verified) throw new Error('candidate ' + args.fingerprint + ' already has an independent record verification');
      return;
    }
    case 'critique': {
      if (ledger.some(unit => unit.status === 'in_progress')) {
        throw new Error('a post-wave critic runs after its wave: units are still in progress, so collect every hunter result before critiquing');
      }
      if (context.state.profile === 'quick' && outcomes.postWave >= 1) {
        throw new Error('the quick profile runs exactly one hunter wave and one critic pass; record its accepted work as deferred instead');
      }
      return;
    }
    case 'final-clean': {
      if (context.state.profile === 'quick') throw new Error('the quick profile has no distinct final-clean critic');
      if (outcomes.finalCleanDone) throw new Error('this run already had its final-clean critic');
      if (outcomes.postWave === 0) throw new Error('run a post-wave critic before the final-clean pass');
      if (!outcomes.lastPostWaveClean) throw new Error('the post-wave critic accepted work; queue the work, run another wave and critique it, then try the final-clean pass');
      if (ledger.some(unit => unit.status === 'planned' || unit.status === 'in_progress')) {
        throw new Error('units are still planned or in progress; the final-clean pass runs only when no planned unit remains');
      }
      return;
    }
  }
}

/**
 * Compose one role's brief from the run's facts, its assignment and the skill's exact blocks.
 * @param input - everything the composer needs about the run and the attempt.
 * @returns the brief.
 * @throws {Error} when a candidate the role needs is missing.
 */
function composeBrief(input: {
  readonly ctx: Context;
  readonly config: Config;
  readonly context: RunContext;
  readonly snapshot: RunFiles;
  readonly agentId: string;
  readonly role: Role;
  readonly directories: { readonly scratch: string; readonly artifacts: string };
  readonly candidates: readonly CandidateEntry[];
  readonly units: readonly LedgerUnit[];
  readonly note: string | undefined;
  readonly focus: string | undefined;
  readonly fingerprint: string | undefined;
}): string {
  const run = briefRunOf({
    context: { ...input.context, state: input.snapshot.state },
    agentId: input.agentId,
    scratch: input.directories.scratch,
    artifacts: input.directories.artifacts,
    ctx: input.ctx,
    config: input.config,
  });
  const base: BriefContext = {
    run,
    ledger: input.snapshot.ledger,
    architecture: input.context.architecture,
    coordinatorNote: input.note,
  };
  if (input.role === 'recon') return reconBrief(base, input.focus);
  if (input.role === 'hunt') {
    const carried: CarriedRecord[] = [];
    for (const unit of input.units) {
      if (unit.prior_status !== 'prior_confirmed_same_source') continue;
      for (const fingerprint of unit.result_fingerprints) {
        const record = input.candidates.find(entry => entry.fingerprint === fingerprint);
        if (record === undefined) continue;
        carried.push({
          fingerprint,
          title: typeof record.record.title === 'string' ? record.record.title : fingerprint,
          rootCause: String(record.record.root_cause ?? record.record.claimed_root_cause ?? ''),
        });
      }
    }
    return hunterBrief(base, input.units, carried);
  }
  const candidate = input.candidates.find(entry => entry.fingerprint === String(input.fingerprint));
  if (input.role === 'critique' || input.role === 'final-clean') {
    const summaries: CandidateSummary[] = input.candidates.map(entry => ({
      fingerprint: entry.fingerprint,
      status: entry.status,
      final_verified: entry.final_verified,
      units: entry.proposed_units,
      title: typeof entry.record.title === 'string' ? entry.record.title : entry.fingerprint,
    }));
    return criticBrief(base, summaries, input.role === 'final-clean');
  }
  if (candidate === undefined) throw new Error('candidate ' + String(input.fingerprint) + ' is not in the candidate store');
  const linked = input.units.length > 0
    ? input.units
    : input.snapshot.ledger.filter(unit => unit.result_fingerprints.includes(candidate.fingerprint));
  return input.role === 'verify' ? verifierBrief(base, candidate, linked) : finalVerifierBrief(base, candidate, linked);
}
