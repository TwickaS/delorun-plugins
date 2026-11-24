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
import { MODELED_ROLES, buildStartMessage, type AuditProfile, type CheckIn, type ModeledRole, type RoleModel } from './start-message.ts'

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

/** One role's model choice, as the menu builds and reads it. */
interface ModelChoice {
  readonly role: ModeledRole
  /** The route chosen, or `undefined` for this chat's model. */
  readonly route: RoleModel | undefined
}

/**
 * Build the per-role model menu, with the selection each role carries.
 * @param groups - the Host model catalogue, grouped by provider.
 * @param models - the role routes chosen so far.
 * @param t - the translate seat.
 * @returns the menu's parent rows and the map its ids resolve through.
 */
function modelMenu(
  groups: readonly ModelProviderGroup[],
  models: Partial<Record<ModeledRole, RoleModel>>,
  t: Translate,
): { items: MenuEntry[]; choices: Map<string, ModelChoice> } {
  const choices = new Map<string, ModelChoice>()
  const items: MenuEntry[] = MODELED_ROLES.map(role => {
    const roleName = {
      recon: t('strip.role.recon'),
      hunter: t('strip.role.hunter'),
      verifier: t('strip.role.verifier'),
      critic: t('strip.role.critic'),
    }[role]
    const chosen = models[role]
    const chatId = `${role}::chat`
    choices.set(chatId, { role, route: undefined })
    const check = <IconCheckOutlineRegular size={12} />
    const rows: MenuEntry[] = [{
      id: chatId,
      label: t('strip.models.chat'),
      ...chosen === undefined ? { icon: check } : {},
    }]
    for (const group of groups) {
      if (groups.length > 1) rows.push({ type: 'label', id: `${role}::${group.id}::label`, text: group.name })
      for (const model of group.models) {
        const id = `${role}::${group.id}::${model.id}`
        choices.set(id, { role, route: { provider: group.id, model: model.id, label: model.name } })
        const selected = chosen !== undefined && chosen.provider === group.id && chosen.model === model.id
        rows.push({ id, label: model.name, ...selected ? { icon: check } : {} })
      }
    }
    return { id: `role::${role}`, label: roleName, submenu: rows }
  })
  return { items, choices }
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
    const choice = menu.choices.get(id)
    if (choice === undefined) return
    setModels(current => {
      const next = { ...current }
      if (choice.route === undefined) delete next[choice.role]
      else next[choice.role] = choice.route
      return next
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