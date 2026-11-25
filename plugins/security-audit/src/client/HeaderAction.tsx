/**
 * The session-header control that opens the pane. It only navigates: the tab type
 * is registered independently, so the same control reveals an already open
 * security-audit tab instead of opening a second one.
 * @module delorun-plugin-security-audit/client/HeaderAction
 */
import type { ReactNode } from 'react'
import { IconShieldOutlineRegular, Tooltip } from '@deepseek-ai/dsh-client-ui-primitives'
import type { InjectFace, PropsLocale, PropsRuntime } from '@deepseek-ai/dsh-client-ui-slots'
import type { NS } from './locales.ts'

/** The registrant's business face for the header control. */
export interface SecurityAuditHeaderInjected {
  /** Open the security-audit tab, or focus it when it is already open. */
  readonly open: () => void
}

/** Full props of the session-header control. */
export type SecurityAuditHeaderProps =
  PropsRuntime<'conversation.session.header.actions'>
  & InjectFace<SecurityAuditHeaderInjected>
  & PropsLocale<typeof NS>

/**
 * Render the session-header control.
 * @param props - the click action and copy.
 * @returns the shield button.
 */
export function SecurityAuditHeaderAction({ open, t }: SecurityAuditHeaderProps): ReactNode {
  const label = t('header.open')
  return (
    <Tooltip label={label} side="bottom">
      <button type="button" className="sa-header-trigger" aria-label={label} onClick={open}>
        <IconShieldOutlineRegular size={15} />
      </button>
    </Tooltip>
  )
}
