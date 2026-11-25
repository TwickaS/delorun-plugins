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
import { MODELED_ROLES, REASONING_EFFORTS, type ModeledRole, type ReasoningEffort } from './roles.ts'
import type { ModelRoute } from './types.ts'

// The role list and the brief-kind mapping live in ./roles.ts, which imports
// nothing at runtime, so the studio half reads the same list this half validates
// against. Re-exported here because this module is the host half's one import.
export { MODELED_ROLES, modeledRoleOf, type ModeledRole, type ReasoningEffort } from './roles.ts'

/** Which half of the plugin a row mounts. */
export type Mount = 'agent' | 'studio'

/**
 * A per-role model route; an omitted field inherits the chat's.
 *
 * `reasoningEffort` is typed as a plain string because the run state stores the
 * effort it recorded as one, and the delegation layer reads it back from there.
 * Both boundaries that accept one narrow it to {@link ReasoningEffort}: the
 * configuration schema below, and intake's validator.
 */
export interface RoleModelOverride {
  provider?: string
  model?: string
  reasoningEffort?: string
}

/** Model choices for one run, by role. */
export type RoleModelOverrides = Partial<Record<ModeledRole, RoleModelOverride>>

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
  })).default({}).description('Deployment defaults for per-role model routes, by role. A role the run sets nothing for takes these; a field neither sets inherits the chat. reasoningEffort is one of ' + REASONING_EFFORTS.join(', ') + '.'),
})

/**
 * Fill the schema's defaults into a row's raw configuration, which reaches a
 * preset child row unfilled.
 * @param value - the raw configuration; only `mount` is required.
 * @returns the configuration with every default applied.
 */
export function resolveConfig(value: Pick<Config, 'mount'> & Partial<Omit<Config, 'mount'>>): Config {
  const config = Config(value as Config)
  // The schema types an effort as a string so the run state's recorded route and
  // this default share one shape; the allowed names are checked here, where a
  // deployment's own configuration is read, and again at intake for a run's.
  for (const [role, route] of Object.entries(config.models)) {
    if (!MODELED_ROLES.includes(role as ModeledRole)) throw new Error('models names unknown role ' + role + '; use ' + MODELED_ROLES.join(', '))
    const effort = route.reasoningEffort
    if (effort !== undefined && !REASONING_EFFORTS.includes(effort as ReasoningEffort)) {
      throw new Error('models.' + role + '.reasoningEffort is ' + effort + '; use one of ' + REASONING_EFFORTS.join(', '))
    }
  }
  return config
}

/**
 * The model route one role runs on: the run's choice, then the deployment
 * default, then inheritance from the chat. The two are merged field by field, so
 * a run that sets only a role's reasoning effort keeps the deployment's model for
 * it, and a field neither sets stays absent for the chat's own route to fill.
 * @param models - the deployment defaults.
 * @param runModels - the run's own choices, when it recorded any.
 * @param role - the role.
 * @returns the route to request, with every unset field absent.
 */
export function routeFor(models: RoleModelOverrides, runModels: RoleModelOverrides | undefined, role: ModeledRole): RoleModelOverride {
  const chosen = runModels?.[role]
  const fallback = models[role]
  const route: RoleModelOverride = {}
  const provider = chosen?.provider ?? fallback?.provider
  const model = chosen?.model ?? fallback?.model
  const reasoningEffort = chosen?.reasoningEffort ?? fallback?.reasoningEffort
  if (provider !== undefined) route.provider = provider
  if (model !== undefined) route.model = model
  if (reasoningEffort !== undefined) route.reasoningEffort = reasoningEffort
  return route
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
