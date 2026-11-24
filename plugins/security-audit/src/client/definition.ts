/**
 * Stage one of the pane's registration: what the security-audit tab type is.
 *
 * A page type: it claims no resource address, is opened by kind from the
 * session-header control or the guide, and its body registers into the keyed
 * `sidebar.right.pane.tab` seat under {@link SECURITY_AUDIT_TAB_ID}.
 * @module @delorun/plugin-security-audit/client/definition
 */
import { IconShieldOutlineRegular } from '@deepseek-ai/dsh-client-ui-primitives'
import type { TranslateNS } from '@deepseek-ai/dsh-client-locale/client'
import type { SidebarRightTabDefinition } from '@deepseek-ai/dsh-client-ui-sidebar-right/client'
import type { NS } from './locales.ts'

/** This implementation's identity in the tab system, and the key its body registers under. */
export const SECURITY_AUDIT_TAB_ID = '@delorun/plugin-security-audit'

/** The page kind the header control and the guide open. */
export const SECURITY_AUDIT_TAB_KIND = 'delorun-security-audit'

/** The guide entry's position: after the files page's entry. */
const GUIDE_ORDER = 20

/**
 * The security-audit type's registry definition.
 * @param t - namespace-bound translate, read fresh on every label call.
 * @returns the definition to register.
 */
export function securityAuditDefinition(t: TranslateNS<typeof NS>): SidebarRightTabDefinition {
  return {
    id: SECURITY_AUDIT_TAB_ID,
    kind: SECURITY_AUDIT_TAB_KIND,
    priority: 'builtin',
    title: () => t('tab.title'),
    guide: [{
      id: 'runs',
      order: GUIDE_ORDER,
      title: () => t('guide.title'),
      description: () => t('guide.description'),
      icon: IconShieldOutlineRegular,
    }],
  }
}
