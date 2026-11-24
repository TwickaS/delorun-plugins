/**
 * The intake checks `audit_init` makes before a run exists, and the derivations
 * it needs: the confinement facts of a role cwd, the source revision, a bounded
 * size estimate and the per-role model routes. Each check either establishes a
 * fact the run records or refuses the run naming the setting to change.
 * @module delorun-plugin-security-audit/tools/intake
 */
import { execFile } from 'node:child_process'
import { posix } from 'node:path'
import { promisify } from 'node:util'
import type { Context } from '@deepseek-ai/cordis'
import type { SandboxEnforcement, SandboxMode, SandboxNetwork } from '@deepseek-ai/dsh-sandbox'
import type { RoleModelOverrides } from '../config.ts'
import { MODELED_ROLES, REASONING_EFFORTS, type ModeledRole, type ReasoningEffort } from '../roles.ts'
import { ledgerValidator } from '../skill.ts'
import { type AuditFiles, now } from '../store.ts'
import type { RoleModels, RunLocation, SourceRef } from '../types.ts'

const execFileAsync = promisify(execFile)

/** The largest number of files intake counts before it stops estimating, so a huge target still starts quickly. */
const FILE_COUNT_CAP = 5_000

/** The deepest directory intake walks while estimating, so a link cycle cannot stall it. */
const WALK_DEPTH_CAP = 12

/** Directories that say nothing about a target's size. */
const SKIPPED_DIRECTORIES = new Set(['.git', 'node_modules', '.security-audit', 'lib', 'dist', 'coverage', '.turbo', '.next', 'target', 'build'])

/** The confinement facts intake established for the run. */
export interface IntakeSandbox {
  /** The network the resolved policy carries for a role cwd; the audit needs `off`. */
  readonly network: SandboxNetwork['mode']
  /** When the network was resolved. */
  readonly checked_at: string
  /** The file-effect mode the roles' cwds run under. */
  readonly mode: SandboxMode
  /** The home directory the confinement hides, or null when it reports none. */
  readonly protected_home: string | null
  /** How completely the backend enforces the policy, or null when it reports nothing. */
  readonly enforcement: SandboxEnforcement | null
}

/**
 * The example role cwd intake asks the policy about. Every role's cwd sits at
 * this depth under the run, so one answer covers them all until the role ids
 * exist; delegation asks again for each role before it spawns one.
 * @param run - the run.
 * @returns an absolute, not yet created role cwd.
 */
export function exampleRoleCwd(run: RunLocation): string {
  return posix.join(run.dir, 'agents', 'recon-1', 'scratch')
}

/**
 * Ask the sandbox what a role's cwd resolves to, and refuse a run whose roles
 * would reach a network or write outside their own scratch.
 * @param ctx - a plugin context.
 * @param cwd - the role cwd to ask about.
 * @param signal - the call's signal.
 * @returns the facts the run records.
 * @throws {Error} when no network resolver is mounted, the roles reach a network, or their mode is not workspace-write.
 */
export async function intakeSandbox(ctx: Context, cwd: string, signal: AbortSignal): Promise<IntakeSandbox> {
  const resolver = ctx.get('sandboxNetwork')
  if (resolver === undefined) {
    throw new Error('no sandbox network resolver is mounted, so the audit cannot prove its roles reach no network; mount @delorun/plugin-permission-defaults')
  }
  const network: SandboxNetwork['mode'] = resolver({ workspaceRoot: cwd })?.mode ?? 'host'
  if (network !== 'off') {
    throw new Error("the network for a role's scratch directory (" + cwd + ") resolves to '" + network + "', not 'off', so an audit role could reach the host network. Set this workspace's network to off in Settings, Network, on the computer running Delorun. If it is already off, this Delorun release predates subdirectory inheritance (A641), which the audit needs: without it a scratch directory resolves the deployment default rather than its workspace's setting.")
  }
  const policy = ctx.get('sandboxPolicy')?.resolve({})
  const mode: SandboxMode = policy?.mode ?? 'read-only'
  if (mode !== 'workspace-write') {
    throw new Error("the sandbox mode for audit roles is '" + mode + "', not 'workspace-write', so a role could write outside its own scratch directory. Set the deployment's sandbox file policy to workspace-write.")
  }
  const sandbox = ctx.get('sandbox')
  let enforcement: SandboxEnforcement | null = null
  if (sandbox !== undefined && policy !== undefined) {
    try {
      enforcement = (await sandbox.confine(['true'], { mode, workspaceRoot: policy.workspaceRoot }, signal)).enforcement
    } catch {
      // A provider that refuses this policy proves the run cannot execute its
      // checks; the refusal surfaces again when a role runs a command.
      enforcement = null
    }
  }
  return { network, checked_at: now(), mode, protected_home: sandbox?.protectedHome ?? null, enforcement }
}

/**
 * Read the reviewed revision from a local checkout. A target that is not a
 * checkout has no commit, and the run says so rather than inventing one.
 * @param target - the workspace directory.
 * @returns the source reference.
 */
export async function readSourceRef(target: string): Promise<SourceRef> {
  try {
    // The target's own configuration is untrusted: `core.fsmonitor` may name a
    // command that `git status` would run, so it is switched off for both calls.
    const commit = (await execFileAsync('git', ['-C', target, '-c', 'core.fsmonitor=false', 'rev-parse', 'HEAD'], { timeout: 5_000 })).stdout.trim()
    const status = (await execFileAsync('git', ['-C', target, '-c', 'core.fsmonitor=false', 'status', '--porcelain', '--untracked-files=no'], { timeout: 5_000 })).stdout
    return { commit: commit === '' ? null : commit, dirty: status.trim().length > 0, dirty_known: true, captured_at: now() }
  } catch {
    return { commit: null, dirty: false, dirty_known: false, captured_at: now() }
  }
}

/**
 * Count the target's source files up to a cap, so intake can state a budget the
 * target's size supports before any agent runs.
 * @param files - file access.
 * @param target - the workspace directory.
 * @param scopePaths - the run's scope, or empty for the whole target.
 * @returns the file count, capped.
 */
export async function countSourceFiles(files: AuditFiles, target: string, scopePaths: readonly string[]): Promise<number> {
  let count = 0
  const walk = async (path: string, depth: number): Promise<void> => {
    if (count >= FILE_COUNT_CAP || depth > WALK_DEPTH_CAP) return
    for (const entry of await files.list(path)) {
      if (count >= FILE_COUNT_CAP) return
      if (entry.type === 'directory') {
        if (SKIPPED_DIRECTORIES.has(entry.name) || entry.name.startsWith('.')) continue
        await walk(posix.join(path, entry.name), depth + 1)
      } else if (entry.type === 'file') {
        count += 1
      }
    }
  }
  for (const scope of scopePaths.length === 0 ? ['.'] : scopePaths) await walk(posix.join(target, scope), 0)
  return count
}

/**
 * Estimate how many coverage units reconnaissance will seed. A unit looks at
 * one surface of one subsystem, so several source files make one unit.
 * @param files - the target's source file count.
 * @returns the estimated unit count, at least four.
 */
export function estimatedUnits(files: number): number {
  return Math.max(4, Math.ceil(files / 12))
}

/** The role names, as the refusal messages list them. */
const ROLE_NAMES = MODELED_ROLES.join(', ')

/** The effort names, as the refusal messages list them. */
const EFFORT_NAMES = REASONING_EFFORTS.join(', ')

/**
 * Read the per-role model routes the person chose at intake. The roles are the
 * ones the composer strip offers, from the one list both halves read, so a choice
 * the strip writes is a choice this accepts.
 *
 * A route may set a provider and model, a reasoning effort, or both. A field it
 * leaves out inherits the chat's, so a role given only an effort runs the chat's
 * model at that effort.
 * @param value - the tool argument, keyed by role.
 * @returns the routes.
 * @throws {Error} for an unknown role, an empty route, a provider without a model or an unknown effort.
 */
export function roleModels(value: unknown): RoleModelOverrides {
  if (value === undefined) return {}
  if (typeof value !== 'object' || value === null || Array.isArray(value)) throw new Error('models must be an object keyed by ' + ROLE_NAMES)
  const result: RoleModelOverrides = {}
  for (const [role, raw] of Object.entries(value)) {
    if (!MODELED_ROLES.includes(role as ModeledRole)) throw new Error('models names unknown role ' + role + '; use ' + ROLE_NAMES)
    if (typeof raw !== 'object' || raw === null || Array.isArray(raw)) throw new Error('models.' + role + ' must be an object')
    const provider = Reflect.get(raw, 'provider')
    const model = Reflect.get(raw, 'model')
    const reasoningEffort = Reflect.get(raw, 'reasoningEffort')
    const hasProvider = provider !== undefined && provider !== ''
    const hasModel = model !== undefined && model !== ''
    if (hasProvider !== hasModel) throw new Error('models.' + role + ' needs both a provider and a model, or neither to inherit the chat\'s')
    if (hasProvider && (typeof provider !== 'string' || typeof model !== 'string')) throw new Error('models.' + role + ' needs a provider and a model as strings')
    if (reasoningEffort !== undefined && !REASONING_EFFORTS.includes(reasoningEffort as ReasoningEffort)) throw new Error('models.' + role + '.reasoningEffort must be one of ' + EFFORT_NAMES + ' when set')
    if (!hasProvider && reasoningEffort === undefined) throw new Error('models.' + role + ' sets nothing; omit the role to inherit the chat\'s model')
    result[role as ModeledRole] = {
      ...hasProvider ? { provider: provider as string, model: model as string } : {},
      ...reasoningEffort === undefined ? {} : { reasoningEffort: reasoningEffort as ReasoningEffort },
    }
  }
  return result
}

/**
 * Project role model choices into the run state's routes.
 * @param models - the choices.
 * @returns one route per chosen role.
 */
export function modelToRoutes(models: RoleModelOverrides): RoleModels {
  const routes: RoleModels = {}
  for (const [role, route] of Object.entries(models)) {
    if (route === undefined) continue
    routes[role as keyof RoleModels] = { provider: route.provider ?? null, model: route.model ?? null, reasoning_effort: route.reasoningEffort ?? null }
  }
  return routes
}

/**
 * Project stored role routes into the plain JSON a tool answer carries.
 * @param models - the run's role routes.
 * @returns one object per role.
 */
export function roleModelsJson(models: RoleModelOverrides): Record<string, Record<string, string>> {
  const result: Record<string, Record<string, string>> = {}
  for (const [role, route] of Object.entries(models)) {
    if (route === undefined) continue
    const value: Record<string, string> = {}
    if (route.provider !== undefined) value.provider = route.provider
    if (route.model !== undefined) value.model = route.model
    if (route.reasoningEffort !== undefined) value.reasoningEffort = route.reasoningEffort
    result[role] = value
  }
  return result
}

/**
 * The skill's own repository-relative path rule, so intake and the gate agree.
 * @param path - a candidate repository-relative path.
 * @returns whether it is a safe relative path.
 */
export function isSafePath(path: string): boolean {
  return ledgerValidator.isSafeRelativePath(path)
}
