/**
 * The composer strip: the audit settings for the chat about to run one. It writes
 * the start message into the message box and never sends it, so the person
 * sends when they are ready. New audit hides while a turn runs, so one turn
 * carries one start message.
 *
 * The strip appears in a chat whose preset is Security audit: the preset itself
 * is declared by the package's cordis.patch.yml, and this is the settings surface
 * that goes with it.
 * @module delorun-plugin-security-audit/client/strip
 */
import { useEffect, useMemo, useState, type ReactNode } from 'react'
import {
  Button, IconCheckOutlineRegular, IconChevronDownOutlineRegular, IconPlayOutlineRegular, IconShieldOutlineRegular,
  Menu, type MenuEntry,
} from '@deepseek-ai/dsh-client-ui-primitives'
import type { SnapshotStore } from '@deepseek-ai/dsh-client-store'
import type { InjectFace, PropsLocale, PropsRuntime } from '@deepseek-ai/dsh-client-ui-slots'
// Type-only: the ctx.sessions merge and the GlobalStandardProps merge (useSessions).
import type {} from '@deepseek-ai/dsh-client-ui-session/client'
// Type-only: the ctx.slots merge.
import type {} from '@deepseek-ai/dsh-client-ui-renderer/client'
import type { ModelProviderGroup } from '@deepseek-ai/dsh-api-remotes/client'
import { NS, pluralKey } from './locales.ts'
import type { ModelCatalogState } from './models.ts'
import { REASONING_EFFORTS } from '../roles.ts'
import {
  MODELED_ROLES, buildStartMessage, effortName, roleName,
  type AuditProfile, type CheckIn, type ModeledRole, type ReasoningEffort, type RoleModel,
} from './start-message.ts'

/** The preset id the strip belongs to, as the package's patch declares it. */
export const SECURITY_AUDIT_PRESET = 'security-audit'

/** The budgets the strip offers, in agent calls across all phases. */
const BUDGET_CHOICES: readonly (number | null)[] = [null, 20, 50, 100, 200]

/** Every profile, in the order the menu lists them. */
const PROFILES: readonly AuditProfile[] = ['quick', 'standard', 'deep']

/** Every check-in timing, in the order the menu lists them. */
const CHECK_INS: readonly CheckIn[] = ['straight_through', 'after_recon', 'every_stage']

/** The registrant's business face for the composer strip. */
export interface SecurityAuditStripInjected {
  hooks: {
    /** The Host model catalogue, for the per-role menus. */
    auditModels: SnapshotStore<ModelCatalogState>
  }
  /** Read the catalogue if this is the first time the strip appears. */
  readonly ensureModels: () => void
}

/** Full props of the composer strip. */
export type SecurityAuditStripProps =
  PropsRuntime<'conversation.input.dock'>
  & InjectFace<SecurityAuditStripInjected>
  & PropsLocale<typeof NS>

/** The locale's translate seat. */
type Translate = PropsLocale<typeof NS>['t']

/** One chip that opens a menu and shows the current choice. */
function ChipMenu({ name, value, label, items, selectedId, onSelect }: {
  readonly name: string
  readonly value: string
  readonly label: string
  readonly items: readonly MenuEntry[]
  readonly selectedId: string
  readonly onSelect: (id: string) => void
}): ReactNode {
  const [open, setOpen] = useState(false)
  return (
    <Menu
      open={open}
      align="start"
      dense
      items={items}
      selectedId={selectedId}
      onClose={() => { setOpen(false) }}
      onSelect={(id) => {
        setOpen(false)
        onSelect(id)
      }}
      anchor={(
        <button
          type="button"
          className="sa-chip"
          aria-haspopup="menu"
          aria-expanded={open}
          aria-label={label}
          onClick={() => { setOpen(current => !current) }}
        >
          <span className="sa-chip-name">{name}</span>
          <span className="sa-chip-value">{value}</span>
          <span className="sa-chip-chevron"><IconChevronDownOutlineRegular size={12} /></span>
        </button>
      )}
    />
  )
}

/** What choosing one row of the model menu does. */
type ModelAction =
  /** Give one role a route, or clear it with `undefined`. */
  | { readonly kind: 'role'; readonly role: ModeledRole; readonly route: RoleModel | undefined }
  /** Give one role a reasoning effort, or clear it with `undefined`. */
  | { readonly kind: 'effort'; readonly role: ModeledRole; readonly effort: ReasoningEffort | undefined }
  /** Give every role the same model, keeping each role's own effort. */
  | { readonly kind: 'all'; readonly route: RoleModel }
  /** Clear every role's own choice, so all of them use this chat's model. */
  | { readonly kind: 'clear' }

/**
 * The model rows of one menu, grouped by provider, with the chosen one ticked.
 * @param groups - the Host model catalogue.
 * @param idOf - the row id for one provider and model.
 * @param chosen - the route the menu is showing as chosen, when one is.
 * @returns the rows, and the route each row id stands for.
 */
function modelRows(
  groups: readonly ModelProviderGroup[],
  idOf: (provider: string, model: string) => string,
  chosen: RoleModel | undefined,
): { rows: MenuEntry[]; routes: [string, RoleModel][] } {
  const rows: MenuEntry[] = []
  const routes: [string, RoleModel][] = []
  const check = <IconCheckOutlineRegular size={12} />
  for (const group of groups) {
    if (groups.length > 1) rows.push({ type: 'label', id: idOf(group.id, '') + 'label', text: group.name })
    for (const model of group.models) {
      const id = idOf(group.id, model.id)
      const selected = chosen?.provider === group.id && chosen.model === model.id
      rows.push({ id, label: model.name, ...selected ? { icon: check } : {} })
      routes.push([id, { provider: group.id, model: model.id, label: model.name }])
    }
  }
  return { rows, routes }
}

/**
 * Build the model menu: one row that sets every role at once, one that clears
 * them all, then one row per role whose submenu holds its model and its
 * reasoning effort.
 * @param groups - the Host model catalogue, grouped by provider.
 * @param models - the role routes chosen so far.
 * @param t - the translate seat.
 * @returns the menu's rows and the action each row id carries.
 */
function modelMenu(
  groups: readonly ModelProviderGroup[],
  models: Partial<Record<ModeledRole, RoleModel>>,
  t: Translate,
): { items: MenuEntry[]; actions: Map<string, ModelAction> } {
  const actions = new Map<string, ModelAction>()
  const check = <IconCheckOutlineRegular size={12} />
  const items: MenuEntry[] = []
  if (groups.length === 0) {
    items.push({ type: 'label', id: 'empty', text: t('strip.models.empty') })
  } else {
    const all = modelRows(groups, (provider, model) => `all::${provider}::${model}`, undefined)
    for (const [id, route] of all.routes) actions.set(id, { kind: 'all', route })
    items.push({ id: 'all', label: t('strip.models.all'), submenu: all.rows })
    items.push({ type: 'separator', id: 'all::separator' })
  }
  actions.set('clear', { kind: 'clear' })
  items.push({ id: 'clear', label: t('strip.models.clear') })
  items.push({ type: 'separator', id: 'roles::separator' })
  for (const role of MODELED_ROLES) {
    const chosen = models[role]
    const chatId = `${role}::chat`
    actions.set(chatId, { kind: 'role', role, route: undefined })
    // A role given only an effort still runs this chat's model, so that row stays ticked.
    const usesChatModel = chosen?.provider === undefined || chosen.model === undefined
    // The menu renders two levels, so a role's effort choices are a labelled
    // group inside its own submenu rather than a third level.
    const rows: MenuEntry[] = [
      { id: chatId, label: t('strip.models.chat'), ...usesChatModel ? { icon: check } : {} },
      { type: 'separator', id: `${role}::effort::separator` },
      { type: 'label', id: `${role}::effort::label`, text: t('strip.models.effortLabel') },
    ]
    const chatEffortId = `${role}::effort::chat`
    rows.push({ id: chatEffortId, label: t('strip.models.effort.chat'), ...chosen?.effort === undefined ? { icon: check } : {} })
    actions.set(chatEffortId, { kind: 'effort', role, effort: undefined })
    for (const effort of REASONING_EFFORTS) {
      const id = `${role}::effort::${effort}`
      rows.push({ id, label: effortName(t, effort), ...chosen?.effort === effort ? { icon: check } : {} })
      actions.set(id, { kind: 'effort', role, effort })
    }
    if (groups.length > 0) {
      rows.push({ type: 'separator', id: `${role}::model::separator` })
      rows.push({ type: 'label', id: `${role}::model::label`, text: t('strip.models.modelLabel') })
      const roleModels = modelRows(groups, (provider, model) => `${role}::${provider}::${model}`, chosen)
      for (const [id, route] of roleModels.routes) actions.set(id, { kind: 'role', role, route })
      rows.push(...roleModels.rows)
    }
    items.push({ id: `role::${role}`, label: roleName(t, role), submenu: rows })
  }
  return { items, actions }
}

/**
 * Render the composer strip.
 * @param props - the Session, the message box's actions, the model catalogue and copy.
 * @returns the strip, or nothing outside a Security audit chat.
 */
export function SecurityAuditStrip(props: SecurityAuditStripProps): ReactNode {
  const { session, sessionId, useSessions, inputActions, useAuditModels, ensureModels, t } = props
  const summary = useSessions(state => state.byId[sessionId])
  const catalogue = useAuditModels(state => state)
  const [profile, setProfile] = useState<AuditProfile>('standard')
  const [rc, setRc] = useState(false)
  const [budget, setBudget] = useState<number | null>(null)
  const [checkIn, setCheckIn] = useState<CheckIn>('after_recon')
  const [models, setModels] = useState<Partial<Record<ModeledRole, RoleModel>>>({})
  const [written, setWritten] = useState(false)
  const auditing = summary?.projectionValues?.agentPreset === SECURITY_AUDIT_PRESET
  useEffect(() => {
    if (auditing) ensureModels()
  }, [auditing, ensureModels])
  const menu = useMemo(() => modelMenu(catalogue.groups, models, t), [catalogue.groups, models, t])
  if (!auditing) return null
  const write = (): void => {
    const text = buildStartMessage(t, { target: summary?.cwd, profile, rc, budget, checkIn, models })
    setWritten(inputActions.insertText(text, inputActions.captureInsertion()))
  }
  const chooseModel = (id: string): void => {
    const action = menu.actions.get(id)
    if (action === undefined) return
    setModels(current => {
      switch (action.kind) {
        case 'clear':
          return {}
        case 'all': {
          // Every role takes the model, and keeps whatever effort it already had.
          const next: Partial<Record<ModeledRole, RoleModel>> = {}
          for (const role of MODELED_ROLES) {
            const effort = current[role]?.effort
            next[role] = effort === undefined ? action.route : { ...action.route, effort }
          }
          return next
        }
        case 'role': {
          const next = { ...current }
          if (action.route === undefined) delete next[action.role]
          else next[action.role] = action.route
          return next
        }
        case 'effort': {
          // An effort stands on its own: a role given only an effort runs this
          // chat's model at that effort, so the route keeps whichever fields it had.
          const next = { ...current }
          const route = next[action.role]
          const { effort: _dropped, ...rest } = route ?? {}
          if (action.effort === undefined) {
            if (rest.provider === undefined && rest.model === undefined) delete next[action.role]
            else next[action.role] = rest
          } else {
            next[action.role] = { ...rest, effort: action.effort }
          }
          return next
        }
      }
    })
  }
  const chosenRoles = MODELED_ROLES.filter(role => models[role] !== undefined).length
  return (
    <section className="sa-strip" aria-label={t('strip.title')} data-testid="security-audit-strip">
      <div className="sa-strip-body">
        <div className="sa-strip-row">
          <span className="sa-strip-lead" aria-hidden><IconShieldOutlineRegular size={14} /></span>
          <span className="sa-strip-title">{t('strip.title')}</span>
          {!rc && (
            <ChipMenu
              name={t('strip.profile')}
              value={t(`strip.profile.${profile}`)}
              label={t('strip.profile')}
              selectedId={profile}
              items={PROFILES.map(value => ({ id: value, label: t(`strip.profile.${value}`) }))}
              onSelect={(id) => { setProfile(id as AuditProfile) }}
            />
          )}
          <ChipMenu
            name={t('strip.rc')}
            value={rc ? t('strip.rc.on') : t('strip.rc.off')}
            label={t('strip.rc')}
            selectedId={rc ? 'on' : 'off'}
            items={[
              { id: 'off', label: t('strip.rc.off') },
              { id: 'on', label: t('strip.rc.on') },
            ]}
            onSelect={(id) => { setRc(id === 'on') }}
          />
          <ChipMenu
            name={t('strip.budget')}
            value={budget === null ? t('strip.budget.none') : t('strip.budget.value', { n: budget })}
            label={t('strip.budget')}
            selectedId={budget === null ? 'none' : String(budget)}
            items={BUDGET_CHOICES.map(value => ({
              id: value === null ? 'none' : String(value),
              label: value === null ? t('strip.budget.none') : t('strip.budget.value', { n: value }),
            }))}
            onSelect={(id) => { setBudget(id === 'none' ? null : Number(id)) }}
          />
          <ChipMenu
            name={t('strip.checkIn')}
            value={t(`strip.checkIn.${checkIn}`)}
            label={t('strip.checkIn')}
            selectedId={checkIn}
            items={CHECK_INS.map(value => ({ id: value, label: t(`strip.checkIn.${value}`) }))}
            onSelect={(id) => { setCheckIn(id as CheckIn) }}
          />
          <ChipMenu
            name={t('strip.models')}
            value={chosenRoles === 0 ? t('strip.models.chat') : t(pluralKey('strip.models.set', chosenRoles), { n: chosenRoles })}
            label={t('strip.models')}
            selectedId=""
            items={menu.items}
            onSelect={chooseModel}
          />
          <div className="sa-strip-actions">
            {!session.running && (
              <Button size="sm" variant="primary" icon={<IconPlayOutlineRegular size={14} />} onClick={write}>
                {t('strip.new')}
              </Button>
            )}
          </div>
        </div>
        {(written || session.running) && (
          <p className="sa-strip-note" role="status">{written ? t('strip.written') : t('strip.running')}</p>
        )}
      </div>
    </section>
  )
}
