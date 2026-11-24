/**
 * The per-role model lane's acceptance check: no model, no key, no network. It
 * asserts that the one role list the studio half and the host half read is the
 * list the strip offers, the list intake accepts and the list the delegation
 * layer routes through, and that the start message states a route for every role.
 *
 * Run: cd ~/delorun/code && node --import tsx/esm \
 *        ../plugins/plugins/security-audit/scripts/check-roles.ts
 * @module @delorun/plugin-security-audit/scripts/check-roles
 */
import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { dirname, join } from 'node:path'
import { MODELED_ROLES, REASONING_EFFORTS, modeledRoleOf, type ModeledRole } from '../src/roles.ts'
import { routeFor } from '../src/config.ts'
import { roleModels } from '../src/tools/intake.ts'
import { buildStartMessage, type RoleModel } from '../src/client/start-message.ts'
import { en, zh } from '../src/client/locales.ts'
import type { BriefKind } from '../src/types.ts'

/** The failures the check collected. */
const failures: string[] = []

/**
 * Assert one fact.
 * @param condition - what must hold.
 * @param what - what it is.
 */
function check(condition: boolean, what: string): void {
  if (condition) console.log('ok   ' + what)
  else {
    failures.push(what)
    console.log('FAIL ' + what)
  }
}

/** The plugin package's root, from this script's own location. */
const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..')

/**
 * Read one of the plugin's source files.
 * @param path - package-relative path.
 * @returns its text.
 */
function source(path: string): string {
  return readFileSync(join(ROOT, path), 'utf8')
}

/** Every brief kind the delegation layer can run. */
const BRIEF_KINDS: readonly BriefKind[] = ['recon', 'hunt', 'verify', 'final-verify', 'critique', 'final-critique']

/**
 * A translate seat over one dictionary, so the start message can be built without
 * a browser. It refuses a key the dictionary lacks, which is what makes the
 * message's copy a checked fact rather than a hope.
 * @param dictionary - the dictionary to read.
 * @returns the translate function.
 */
function translate(dictionary: Readonly<Record<string, string>>): (key: string, params?: Record<string, string | number>) => string {
  return (key, params) => {
    const template = dictionary[key]
    if (template === undefined) throw new Error('the dictionary has no key ' + key)
    if (params === undefined) return template
    return template.replace(/\{(\w+)\}/gu, (whole, name: string) => {
      const value = params[name]
      return value === undefined ? whole : String(value)
    })
  }
}

/** The role list, as the strip and the start message read it. */
function checkOneList(): void {
  check(MODELED_ROLES.length === 4, 'four roles have their own model choice')
  check(new Set(MODELED_ROLES).size === MODELED_ROLES.length, 'the role list names each role once')
  const strip = source('src/client/strip.tsx')
  check(strip.includes("from './start-message.ts'") && strip.includes('MODELED_ROLES'),
    'the strip reads the role list from the start message, which re-exports the shared one')
  check(!/\[\s*'recon'\s*,\s*'hunter'/u.test(strip), 'the strip declares no role list of its own')
  const startMessage = source('src/client/start-message.ts')
  check(startMessage.includes("from '../roles.ts'"), 'the start message reads the shared role list')
  const intake = source('src/tools/intake.ts')
  check(intake.includes("from '../roles.ts'"), 'intake reads the shared role list')
  const config = source('src/config.ts')
  check(config.includes("from './roles.ts'"), 'the configuration reads the shared role list')
  const delegate = source('src/delegate.ts')
  check(delegate.includes('modeledRoleOf') && delegate.includes("from './config.ts'"),
    'the delegation layer routes through the shared role mapping')
}

/** The strip offers the apply-to-all, the clear and the per-role effort rows. */
function checkStripOffers(): void {
  const strip = source('src/client/strip.tsx')
  check(strip.includes("t('strip.models.all')"), 'the strip offers one row that sets every role at once')
  check(strip.includes("t('strip.models.clear')"), 'the strip offers one row that clears every role')
  check(strip.includes('REASONING_EFFORTS'), 'the strip offers the shared effort list')
  check(strip.includes("t('strip.models.effortLabel')"), 'the strip labels the per-role effort group')
  check(strip.includes('chosenRoles'), 'the strip shows how many roles have a choice of their own')
  // The menu renders two levels, so a role's effort rows must sit inside its own
  // submenu rather than in a third level the primitive would not draw.
  check(!/submenu: effortRows/u.test(strip), 'the effort rows are not a third menu level')
}

/** Every role the strip offers is a role intake accepts. */
function checkIntakeAccepts(): void {
  for (const role of MODELED_ROLES) {
    const route = { provider: 'test', model: 'test-model' }
    const accepted = roleModels({ [role]: route })
    check(accepted[role]?.provider === 'test' && accepted[role]?.model === 'test-model',
      'intake accepts the strip\'s role ' + role)
  }
  let refused = false
  try {
    roleModels({ orchestrator: { provider: 'test', model: 'test-model' } })
  } catch {
    refused = true
  }
  check(refused, 'intake refuses a role name outside the shared list')
  let unknownRefused = false
  try {
    roleModels({ 'final-verify': { provider: 'test', model: 'test-model' } })
  } catch {
    unknownRefused = true
  }
  check(unknownRefused, 'intake refuses a brief kind used as a role name')
}

/** Every effort the strip offers is an effort intake accepts, and no other. */
function checkEfforts(): void {
  for (const effort of REASONING_EFFORTS) {
    const accepted = roleModels({ recon: { provider: 'test', model: 'test-model', reasoningEffort: effort } })
    check(accepted.recon?.reasoningEffort === effort, 'intake accepts the strip\'s effort ' + effort)
  }
  let refused = false
  try {
    roleModels({ recon: { provider: 'test', model: 'test-model', reasoningEffort: 'medium' } })
  } catch {
    refused = true
  }
  check(refused, 'intake refuses an effort the strip does not offer')
  const effortOnly = roleModels({ verifier: { reasoningEffort: 'max' } })
  check(effortOnly.verifier?.reasoningEffort === 'max' && effortOnly.verifier.provider === undefined,
    'a role given only an effort keeps the chat\'s model')
  let emptyRefused = false
  try {
    roleModels({ critic: {} })
  } catch {
    emptyRefused = true
  }
  check(emptyRefused, 'a role that sets nothing is refused rather than silently ignored')
}

/** The delegation layer's mapping covers every brief kind and reaches every role. */
function checkDelegation(): void {
  const reached = new Set<ModeledRole>()
  for (const kind of BRIEF_KINDS) {
    const role = modeledRoleOf(kind)
    reached.add(role)
    check(MODELED_ROLES.includes(role), 'the brief kind ' + kind + ' routes to the modeled role ' + role)
  }
  for (const role of MODELED_ROLES) check(reached.has(role), 'some brief kind routes to the role ' + role)
  check(modeledRoleOf('final-verify') === modeledRoleOf('verify'), 'both verifier briefs share one route')
  check(modeledRoleOf('final-critique') === modeledRoleOf('critique'), 'both critic briefs share one route')
}

/** A run's choice wins over the deployment default, field by field. */
function checkRouteFor(): void {
  const deployment = { recon: { provider: 'p', model: 'm', reasoningEffort: 'low' } }
  const run = { recon: { reasoningEffort: 'max' as const } }
  const merged = routeFor(deployment, run, 'recon')
  check(merged.provider === 'p' && merged.model === 'm' && merged.reasoningEffort === 'max',
    'a run that sets only an effort keeps the deployment\'s model for that role')
  const inherited = routeFor({}, undefined, 'hunter')
  check(Object.keys(inherited).length === 0, 'a role neither the run nor the deployment sets inherits the chat')
  const own = routeFor(deployment, { recon: { provider: 'q', model: 'n' } }, 'recon')
  check(own.provider === 'q' && own.model === 'n' && own.reasoningEffort === 'low',
    'a run that sets only a model keeps the deployment\'s effort for that role')
}

/** The start message states one route per role, and every key it uses exists in both dictionaries. */
function checkStartMessage(): void {
  const models: Partial<Record<ModeledRole, RoleModel>> = {
    recon: { provider: 'deepseek', model: 'deepseek-v4.1-flash', label: 'V4.1 Flash', effort: 'low' },
    verifier: { effort: 'max' },
  }
  for (const [name, dictionary] of [['English', en], ['Chinese', zh]] as const) {
    const t = translate(dictionary as Readonly<Record<string, string>>)
    const text = buildStartMessage(t as never, { target: '/repo', profile: 'standard', budget: 50, checkIn: 'after_recon', models })
    const lines = text.split('\n')
    for (const role of MODELED_ROLES) {
      // The line's own template carries the separator, which differs by language.
      const prefix = t('strip.models.line', { role: t('strip.role.' + role), route: '' })
      const line = lines.find(candidate => candidate.startsWith(prefix))
      check(line !== undefined, name + ': the start message states a route for ' + role)
    }
    check(text.includes('deepseek/deepseek-v4.1-flash'), name + ': a role with its own model names its provider and model')
    check(text.includes(t('strip.models.effort.low')), name + ': a role with its own effort names that effort')
    check(text.includes(t('strip.models.routeChat', { effort: t('strip.models.effort.max') })),
      name + ': a role with only an effort says it runs this chat\'s model at that effort')
    check(text.includes(t('strip.models.chat')), name + ': a role with no choice says it uses this chat\'s model')
    check(text.includes('50'), name + ': the message states the budget')
    // The machine-readable line is what the coordinator passes to audit_init, so
    // it must be exactly what intake accepts.
    const jsonLine = lines.find(candidate => candidate.startsWith(t('strip.models.json', { json: '' })))
    const json = jsonLine?.slice(t('strip.models.json', { json: '' }).length)
    const parsed = json === undefined ? undefined : roleModels(JSON.parse(json) as unknown)
    check(parsed?.recon?.provider === 'deepseek' && parsed.recon.model === 'deepseek-v4.1-flash' && parsed.recon.reasoningEffort === 'low',
      name + ': the message carries the chosen model and effort in the shape audit_init accepts')
    check(parsed?.verifier?.reasoningEffort === 'max' && parsed.verifier.provider === undefined,
      name + ': the message carries an effort-only role in the shape audit_init accepts')
  }
  const t = translate(en as Readonly<Record<string, string>>)
  const empty = buildStartMessage(t as never, { target: undefined, profile: 'quick', budget: null, checkIn: 'straight_through', models: {} })
  check(empty.split('\n').filter(line => line.includes(t('strip.models.chat'))).length === MODELED_ROLES.length,
    'with no role chosen, every role says it uses this chat\'s model')
}

/** Both dictionaries carry the same keys, so neither language falls back silently. */
function checkDictionaries(): void {
  const english = Object.keys(en).sort()
  const chinese = Object.keys(zh).sort()
  check(english.length === chinese.length && english.every((key, index) => key === chinese[index]),
    'the English and Chinese dictionaries carry the same keys')
  for (const key of ['strip.models.all', 'strip.models.clear', 'strip.models.effortLabel', 'strip.models.route', 'strip.models.routeChat', 'strip.models.line']) {
    check(key in en && key in zh, 'both dictionaries carry ' + key)
  }
}

checkOneList()
checkStripOffers()
checkIntakeAccepts()
checkEfforts()
checkDelegation()
checkRouteFor()
checkStartMessage()
checkDictionaries()
console.log('')
if (failures.length > 0) {
  console.log(String(failures.length) + ' check(s) failed')
  process.exitCode = 1
} else {
  console.log('every check passed')
}
