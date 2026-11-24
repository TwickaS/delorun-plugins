/**
 * Security audit's studio half: the Audit strip above the composer in a Security
 * audit chat, the run pane in the right sidebar, and the session-header control
 * that opens it.
 *
 * The pane reads the runs the coordinator writes under `.security-audit/` through
 * the existing workspace files Remote and follows the selected run directory's
 * change stream. The strip only prepares a message: it writes the start message
 * into the message box and never sends it.
 * @module @delorun/plugin-security-audit/client
 */
import type { Context as ClientContext } from '@deepseek-ai/cordis'
// Type-only: the ctx.locale Context merge.
import type {} from '@deepseek-ai/dsh-client-locale/client'
// Type-only: the ctx.slots Context merge.
import type {} from '@deepseek-ai/dsh-client-ui-renderer/client'
// Type-only: the ctx.sessions merge (session summaries and their workspace folder).
import type {} from '@deepseek-ai/dsh-api-session-controller/client'
// Type-only: the ctx.remote Context merge and the forwarded settings/adapter events.
import type {} from '@deepseek-ai/dsh-api-remotes/client'
// Type-only: the `workspaceFiles` Remote namespace the pane reads.
import type {} from '@deepseek-ai/dsh-api-workspace-files/remote'
// Type-only: the 'conversation.session.header.actions' and 'conversation.input.dock' SlotMap entries.
import type {} from '@deepseek-ai/dsh-client-ui-conversation/client'
// Type-only: ctx.sidebarRightTabs, ctx.sidebarRight, and the 'sidebar.right.pane.tab' SlotMap entry.
import type {} from '@deepseek-ai/dsh-client-ui-sidebar-right/client'
import type { SessionId } from '@deepseek-ai/dsh-session/types'
import { SecurityAuditController } from './controller.ts'
import { SECURITY_AUDIT_TAB_ID, SECURITY_AUDIT_TAB_KIND, securityAuditDefinition } from './definition.ts'
import { SecurityAuditHeaderAction, type SecurityAuditHeaderInjected } from './HeaderAction.tsx'
import { NS, en, zh, type SecurityAuditKey } from './locales.ts'
import { AuditModelCatalog } from './models.ts'
import { SecurityAuditPane, type SecurityAuditPaneInjected } from './pane.tsx'
import { SecurityAuditStrip, type SecurityAuditStripInjected } from './strip.tsx'
import { injectStyles } from './styles.ts'

export type { SecurityAuditKey } from './locales.ts'
export type { AuditMetadata, AuditRunRef, AuditRunStatus, AuditStage, CoverageSummary, CandidatesSummary, FindingsSummary } from './runs.ts'
export type { AuditPhase, AuditProblem, AuditSnapshot } from './controller.ts'
export type { SecurityAuditHeaderInjected, SecurityAuditHeaderProps } from './HeaderAction.tsx'
export type { SecurityAuditPaneInjected, SecurityAuditPaneProps } from './pane.tsx'
export type { SecurityAuditStripInjected, SecurityAuditStripProps } from './strip.tsx'
export type { AuditProfile, CheckIn, ModeledRole, RoleModel } from './start-message.ts'

declare module '@deepseek-ai/dsh-client-ui-slots' {
  interface LocaleNamespaceMap {
    /** The security-audit strip's, pane's and header control's copy. */
    delorunSecurityAudit: SecurityAuditKey
  }
}

export { NS }

/**
 * The header control's place in the Session's action band: before the
 * open-in-app control's `-10`, so the audit entry sits at the band's start.
 */
export const HEADER_ORDER = -20

/** The header control's registration id. */
export const HEADER_ID = 'security-audit'

/** The strip's registration id inside the composer dock. */
export const STRIP_ID = 'security-audit'

/** The strip's position: after the todo list's `0`, before the queue's `20`. */
export const STRIP_ORDER = 10

/** Required services: slots, copy, Sessions, the right sidebar's tabs, and the workspace files and model remotes. */
export const inject = ['slots', 'locale', 'sessions', 'sidebarRightTabs', 'sidebarRight', 'remote', 'remote.workspaceFiles', 'remote.session']

/**
 * Register the dictionaries, the stylesheet, the tab type, its body, the header
 * control and the composer strip.
 * @param ctx - the browser plugin context.
 */
export function apply(ctx: ClientContext): void {
  const t = ctx.locale.bind(NS)
  ctx.effect(() => ctx.locale.register(NS, { en, zh }), 'security-audit: dictionaries')
  ctx.effect(() => injectStyles(), 'security-audit: stylesheet')
  ctx.effect(() => ctx.sidebarRightTabs.register(securityAuditDefinition(t)), 'security-audit: tab type')

  const controllers = new Map<SessionId, SecurityAuditController>()
  const faces = new Map<SessionId, SecurityAuditPaneInjected>()
  ctx.effect(() => () => {
    for (const controller of controllers.values()) controller.dispose()
    controllers.clear()
    faces.clear()
  }, 'security-audit: run controllers')

  /**
   * One Session's controller, created on first use and disposed with the plugin.
   * @param sessionId - the Session whose workspace it reads.
   * @returns the controller.
   */
  const controllerFor = (sessionId: SessionId): SecurityAuditController => {
    const existing = controllers.get(sessionId)
    if (existing !== undefined) return existing
    const created = new SecurityAuditController({
      cwd: () => ctx.sessions.list.getSnapshot().byId[sessionId]?.cwd,
      list: (path, signal) => ctx.remote.workspaceFiles.list(sessionId, path, signal),
      read: (path, signal) => ctx.remote.workspaceFiles.read(sessionId, path, {}, signal),
      watch: (path, signal) => ctx.remote.workspaceFiles.changes(sessionId, path, signal),
    })
    controllers.set(sessionId, created)
    return created
  }

  /** One Session's stable pane face, so a redraw does not restart the read. */
  const faceFor = (sessionId: SessionId): SecurityAuditPaneInjected => {
    const existing = faces.get(sessionId)
    if (existing !== undefined) return existing
    const controller = controllerFor(sessionId)
    const face: SecurityAuditPaneInjected = {
      hooks: { audit: controller.state },
      attach: () => controller.attach(),
      select: directory => { controller.select(directory) },
      reload: () => { controller.reload() },
    }
    faces.set(sessionId, face)
    return face
  }

  ctx.effect(() => ctx.slots.inject('sidebar.right.pane.tab', () => ctx.slots.register({
    name: 'sidebar.right.pane.tab',
    key: SECURITY_AUDIT_TAB_ID,
    locale: NS,
    inject: (sessionId: SessionId): SecurityAuditPaneInjected => faceFor(sessionId),
  }, SecurityAuditPane)), 'security-audit: pane body')

  const headerFace: SecurityAuditHeaderInjected = {
    open: () => { ctx.sidebarRight.openTab(SECURITY_AUDIT_TAB_KIND) },
  }
  ctx.effect(() => ctx.slots.inject('conversation.session.header.actions', () => ctx.slots.register({
    name: 'conversation.session.header.actions',
    id: HEADER_ID,
    order: HEADER_ORDER,
    locale: NS,
    inject: () => headerFace,
  }, SecurityAuditHeaderAction)), 'security-audit: header control')

  // One catalogue serves every chat's strip; an adapter or settings change and a
  // new connection each invalidate it.
  const catalogue = new AuditModelCatalog(ctx)
  ctx.effect(() => () => { catalogue.dispose() }, 'security-audit: model catalogue')
  ctx.effect(() => ctx.remote.$on('llm/adapters-updated', () => { catalogue.refresh() }), 'security-audit: adapter invalidations')
  ctx.effect(() => ctx.on('connection/reset', () => { catalogue.refresh() }), 'security-audit: connection generation')

  const stripFace: SecurityAuditStripInjected = {
    hooks: { auditModels: catalogue.state },
    ensureModels: () => { catalogue.load() },
  }
  ctx.effect(() => ctx.slots.inject('conversation.input.dock', () => ctx.slots.register({
    name: 'conversation.input.dock',
    id: STRIP_ID,
    order: STRIP_ORDER,
    locale: NS,
    inject: () => stripFace,
  }, SecurityAuditStrip)), 'security-audit: composer strip')
}
