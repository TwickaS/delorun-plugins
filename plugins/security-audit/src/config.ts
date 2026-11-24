/**
 * The plugin's configuration and the per-role model routes a run can record.
 * A profile mounts the package twice: once at the root with `mount: 'studio'`
 * so the studio serves the pane, and once inside the security-audit preset
 * with `mount: 'agent'`, where it registers the audit tools and the
 * coordinator prompt. `mount` has no default so neither row can register the
 * wrong half by omission.
 * @module delorun-plugin-security-audit/config
 */
import z from '@deepseek-ai/schemastery'
import type { ModelRoute } from './types.ts'

/** Which half of the plugin a row mounts. */
export type Mount = 'agent' | 'studio'

/** A per-role model route; an omitted field inherits the chat's. */
export interface RoleModelOverride {
  provider?: string
  model?: string
  reasoningEffort?: string
}

/** Roles whose model can be chosen separately; the coordinator uses the chat's. */
export const MODELED_ROLES = ['recon', 'hunter', 'verifier', 'critic'] as const

/** One role with its own model choice. */
export type ModeledRole = typeof MODELED_ROLES[number]

/** Model choices for one run, by role. */
export type RoleModelOverrides = Partial<Record<ModeledRole, RoleModelOverride>>

/** The role whose route a delegated brief uses. */
export function modeledRoleOf(kind: 'recon' | 'hunt' | 'verify' | 'final-verify' | 'critique'): ModeledRole {
  switch (kind) {
    case 'recon': return 'recon'
    case 'hunt': return 'hunter'
    case 'verify':
    case 'final-verify': return 'verifier'
    case 'critique': return 'critic'
  }
}

/** The plugin configuration. */
export interface Config {
  /** Which half this row mounts. */
  mount: Mount
  /** Target-relative directory holding every run. */
  runsDir: string
  /** Fresh-child retries after a structured result is refused. */
  resultRetries: number
  /** The subagent provider used for delegated roles. */
  provider: string
  /** Deployment defaults for per-role model routes; a run records its own. */
  models: RoleModelOverrides
}

/** The configuration schema the Loader validates a row against. */
export const Config: z<Config> = z.object({
  mount: z.union(['agent', 'studio'] as const).required().description('The half this row mounts: agent registers the audit tools and the coordinator prompt, studio only loads the package for the pane.'),
  runsDir: z.string().min(1).default('.security-audit').description('Target-relative directory holding every run.'),
  resultRetries: z.natural().max(2).default(1).description('Fresh-child retries after a structured result is refused.'),
  provider: z.string().min(1).default('spawn').description('The subagent provider used for delegated roles.'),
  models: z.dict(z.object({
    provider: z.string().min(1),
    model: z.string().min(1),
    reasoningEffort: z.string().min(1),
  })).default({}).description('Deployment defaults for per-role model routes, by role.'),
})

/**
 * Fill the schema's defaults into a row's raw configuration, which reaches a
 * preset child row unfilled.
 * @param value - the raw configuration; only `mount` is required.
 * @returns the configuration with every default applied.
 */
export function resolveConfig(value: Pick<Config, 'mount'> & Partial<Omit<Config, 'mount'>>): Config {
  return Config(value as Config)
}

/**
 * The model route one role runs on: the run's choice, then the deployment
 * default, then inheritance from the chat.
 * @param models - the deployment defaults.
 * @param runModels - the run's own choices, when it recorded any.
 * @param role - the role.
 * @returns the route to request, with every unset field absent.
 */
export function routeFor(models: RoleModelOverrides, runModels: RoleModelOverrides | undefined, role: ModeledRole): RoleModelOverride {
  const chosen = runModels?.[role] ?? models[role]
  return chosen === undefined ? {} : { ...chosen }
}

/**
 * Project a stored route into the plain JSON a tool answer carries.
 * @param route - the route, or undefined.
 * @returns one object, or null when nothing is set.
 */
export function routeJson(route: ModelRoute | RoleModelOverride | undefined): Record<string, string> | null {
  if (route === undefined) return null
  const value: Record<string, string> = {}
  const provider = Reflect.get(route, 'provider')
  const model = Reflect.get(route, 'model')
  const reasoningEffort = Reflect.get(route, 'reasoningEffort')
  if (typeof provider === 'string') value.provider = provider
  if (typeof model === 'string') value.model = model
  if (typeof reasoningEffort === 'string') value.reasoningEffort = reasoningEffort
  return value
}
