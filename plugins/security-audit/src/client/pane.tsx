/**
 * The security-audit tab body: the selected run's phase, stage, coverage, budget
 * spend, profile, source ref, elapsed time and finding counts; the units a role
 * is working on now with their owners; the candidates under validation; the
 * findings themselves, each opening its cited line in the document preview; and
 * the draft prompts.
 *
 * Observe-only. The body reads the controller's snapshot and calls its
 * callbacks; it never starts, stops or steers a run.
 * @module delorun-plugin-security-audit/client/pane
 */
import { useEffect, useState, type ReactNode } from 'react'
import {
  Button, IconChevronDownOutlineRegular, IconRefreshOutlineRegular, IconShieldOutlineRegular, Menu, Tag,
  Tooltip, useClipboardCopy, type MenuEntry, type TagTone,
} from '@deepseek-ai/dsh-client-ui-primitives'
import type { SnapshotStore } from '@deepseek-ai/dsh-client-store'
import type { InjectFace, PropsLocale, PropsRuntime } from '@deepseek-ai/dsh-client-ui-slots'
// Type-only: the ctx.sessions merge and the GlobalStandardProps merge (useSessions).
import type {} from '@deepseek-ai/dsh-client-ui-session/client'
// Type-only: the 'sidebar.right.pane.tab' SlotMap entry and its tab information hook.
import type {} from '@deepseek-ai/dsh-client-ui-sidebar-right/client'
// Type-only: the file resource's navigation parameters ({ line }) that openResource types.
import type {} from '@deepseek-ai/dsh-client-ui-sidebar-documentpreview/client'
// Type-only: the ctx.slots merge.
import type {} from '@deepseek-ai/dsh-client-ui-renderer/client'
import type { SessionId } from '@deepseek-ai/dsh-session/types'
import { NS, pluralKey, type SecurityAuditKey } from './locales.ts'
import type { AuditProblem, AuditSnapshot } from './controller.ts'
import type { AuditCandidate, AuditFinding, AuditMetadata, AuditRunRef, AuditRunStatus, AuditStage, CoverageUnit, FindingCitation, FindingVerdict } from './runs.ts'
import { buildStartMessage } from './start-message.ts'

/** The registrant's business face for the pane body. */
export interface SecurityAuditPaneInjected {
  hooks: {
    /** The selected run's live snapshot. */
    audit: SnapshotStore<AuditSnapshot>
  }
  /**
   * Start reading while the body is drawn.
   * @returns the release that stops the watch.
   */
  readonly attach: () => () => void
  /**
   * Select one discovered run.
   * @param directory - its workspace-relative directory.
   */
  readonly select: (directory: string) => void
  /** Discover the runs again and read the selected one again. */
  readonly reload: () => void
}

/** Full props of the security-audit pane body. */
export type SecurityAuditPaneProps =
  PropsRuntime<'sidebar.right.pane.tab'>
  & InjectFace<SecurityAuditPaneInjected>
  & PropsLocale<typeof NS>

/** The locale's translate seat. */
type Translate = PropsLocale<typeof NS>['t']

/** How each recorded lifecycle state reads. */
const PHASE_LABEL: Readonly<Record<AuditRunStatus, SecurityAuditKey>> = {
  in_progress: 'phase.in_progress',
  complete: 'phase.complete',
  incomplete: 'phase.incomplete',
  unknown: 'phase.unknown',
}

/** How each recorded phase reads. */
const STAGE_LABEL: Readonly<Record<AuditStage, SecurityAuditKey>> = {
  reconnaissance: 'stage.reconnaissance',
  hunting: 'stage.hunting',
  validation: 'stage.validation',
  final_verification: 'stage.final_verification',
  reporting: 'stage.reporting',
  done: 'stage.done',
  unknown: 'stage.unknown',
}

/** How each verdict reads. */
const VERDICT_LABEL: Readonly<Record<FindingVerdict, SecurityAuditKey>> = {
  confirmed: 'findings.confirmed',
  needs_validation: 'findings.needsValidation',
  rejected: 'findings.rejected',
}

/** How each verdict's count reads. */
const VERDICT_TONE: Readonly<Record<FindingVerdict, TagTone>> = {
  confirmed: 'danger',
  needs_validation: 'warning',
  rejected: 'quiet',
}

/**
 * Spell out one elapsed span in the current language.
 * @param milliseconds - the elapsed span.
 * @param t - the translate seat.
 * @returns the copy.
 */
function elapsedText(milliseconds: number, t: Translate): string {
  const minutes = Math.floor(milliseconds / 60_000)
  if (minutes < 60) return t('elapsed.minutes', { n: minutes })
  const hours = Math.floor(minutes / 60)
  if (hours < 24) return t('elapsed.hours', { h: hours, m: minutes % 60 })
  return t('elapsed.days', { d: Math.floor(hours / 24), h: hours % 24 })
}

/**
 * Encode one path segment for a file address, keeping a drive colon literal.
 * @param segment - the segment.
 * @returns its encoded form.
 */
function encodeSegment(segment: string): string {
  return encodeURIComponent(segment).replace(/%3A/giu, ':')
}

/**
 * Build the document preview's address for one cited path.
 * @param sessionId - the Session the path is read in.
 * @param cwd - that Session's workspace root, when known.
 * @param path - the cited path: workspace-relative, or absolute on this machine.
 * @returns the `dsh-resource://file/…` address.
 */
function fileAddress(sessionId: SessionId, cwd: string | undefined, path: string): string {
  const normalized = path.replace(/\\/gu, '/').replace(/^(?:\.\/)+/u, '')
  const id = encodeSegment(String(sessionId))
  if (normalized.startsWith('/')) {
    return `dsh-resource://file/absolute/${normalized.split('/').map(encodeSegment).join('/')}`
  }
  const root = cwd === undefined ? '' : cwd.replace(/\\/gu, '/').replace(/\/+$/u, '')
  const relative = root !== '' && normalized.startsWith(`${root}/`) ? normalized.slice(root.length + 1) : normalized
  return `dsh-resource://file/session/${id}/${relative.split('/').map(encodeSegment).join('/')}`
}

/**
 * Spell out one quiet notice.
 * @param problem - the structured problem.
 * @param t - the translate seat.
 * @returns the copy.
 */
function problemText(problem: AuditProblem, t: Translate): string {
  switch (problem.kind) {
    case 'file': return problem.reason === 'malformed'
      ? t('notice.malformed', { file: problem.file })
      : problem.reason === 'truncated'
        ? t('notice.truncated', { file: problem.file })
        : t('notice.unreadable', { file: problem.file })
    case 'directory': return t('notice.directory', { directory: problem.directory })
    case 'watch': return t('notice.watch')
    case 'workspace': return t('workspace.missing')
    /* v8 ignore next -- closed union of quiet notices */
    default: return t('notice.watch')
  }
}

/** One inline draft prompt with its copy and insert controls. */
function DraftPrompt({ text, t, insert }: {
  readonly text: string
  readonly t: Translate
  readonly insert: (text: string) => boolean
}): ReactNode {
  const { copied, onCopy } = useClipboardCopy(text)
  const [failed, setFailed] = useState(false)
  return (
    <div className="sa-prompt">
      <p className="sa-prompt-text">{text}</p>
      <div className="sa-prompt-actions">
        <Button size="sm" variant="outline" aria-label={t('prompt.copyAria')} onClick={onCopy}>
          {copied ? t('prompt.copied') : t('prompt.copy')}
        </Button>
        <Button size="sm" variant="ghost" aria-label={t('prompt.insertAria')} onClick={() => { setFailed(!insert(text)) }}>
          {t('prompt.insert')}
        </Button>
      </div>
      {failed && <p className="sa-note" role="note">{t('prompt.insertUnavailable')}</p>}
    </div>
  )
}

/** The discovered runs as one switcher menu. */
function RunSwitcher({ runs, selected, select, t }: {
  readonly runs: readonly AuditRunRef[]
  readonly selected: string | undefined
  readonly select: (directory: string) => void
  readonly t: Translate
}): ReactNode {
  const [open, setOpen] = useState(false)
  const current = runs.find(run => run.directory === selected) ?? runs[0]
  const items: MenuEntry[] = runs.map(run => ({ id: run.directory, label: run.label }))
  return (
    <Menu
      open={open}
      align="end"
      dense
      items={items}
      selectedId={current?.directory}
      onClose={() => { setOpen(false) }}
      onSelect={(id) => {
        setOpen(false)
        select(id)
      }}
      anchor={(
        <button
          type="button"
          className="sa-select"
          aria-haspopup="menu"
          aria-expanded={open}
          aria-label={t('select')}
          onClick={() => { setOpen(value => !value) }}
        >
          <span className="sa-select-label">{current?.label ?? ''}</span>
          <IconChevronDownOutlineRegular size={12} />
        </button>
      )}
    />
  )
}

/** One labelled value in the run summary. */
function SummaryRow({ label, value, field }: {
  readonly label: string
  readonly value: string
  readonly field: string
}): ReactNode {
  return (
    <div className="sa-field" data-audit-field={field}>
      <span className="sa-field-label">{label}</span>
      <span className="sa-field-value" title={value}>{value}</span>
    </div>
  )
}

/**
 * Spell out the budget line.
 * @param metadata - the selected run's metadata.
 * @param t - the translate seat.
 * @returns the copy.
 */
function budgetText(metadata: AuditMetadata | undefined, t: Translate): string {
  const spend = metadata?.spend
  const limit = metadata?.budget
  if (limit === null) {
    return spend === undefined
      ? t('budget.none')
      : t(pluralKey('budget.spendUnlimited', spend), { used: spend })
  }
  if (limit !== undefined) {
    return spend === undefined
      ? t(pluralKey('budget.value', limit), { n: limit })
      : t(pluralKey('budget.spend', spend), { used: spend, limit })
  }
  return t('none')
}

/**
 * Spell out the reviewed source revision.
 * @param metadata - the selected run's metadata.
 * @param t - the translate seat.
 * @returns the copy.
 */
function sourceText(metadata: AuditMetadata | undefined, t: Translate): string {
  const ref = metadata?.sourceRef
  if (ref === undefined || ref.commit === undefined) return t('source.unknown')
  return ref.dirty ? t('source.dirty', { ref: ref.commit }) : ref.commit
}

/** The coverage counts as one compact row of tags. */
function CoverageCounts({ snapshot, t }: {
  readonly snapshot: AuditSnapshot
  readonly t: Translate
}): ReactNode {
  const coverage = snapshot.coverage
  if (coverage === undefined) return <p className="sa-muted">{t('coverage.none')}</p>
  const rows: readonly (readonly [SecurityAuditKey, number, TagTone])[] = [
    ['coverage.covered', coverage.covered, 'success'],
    ['coverage.inProgress', coverage.inProgress, 'info'],
    ['coverage.candidate', coverage.candidate, 'info'],
    ['coverage.blocked', coverage.blocked, 'warning'],
    ['coverage.deferred', coverage.deferred, 'quiet'],
    ['coverage.planned', coverage.planned, 'quiet'],
  ]
  return (
    <div className="sa-counts">
      {rows.filter(([, count]) => count > 0).map(([key, count, tone]) => (
        <Tag key={key} tone={tone}>{t(key, { n: count })}</Tag>
      ))}
    </div>
  )
}

/** One unit a role is working on. */
function UnitRow({ unit, t }: {
  readonly unit: CoverageUnit
  readonly t: Translate
}): ReactNode {
  return (
    <li className="sa-unit" data-unit-status={unit.status}>
      <span className="sa-unit-label" title={unit.id}>{unit.label}</span>
      {unit.owner !== undefined && <span className="sa-unit-owner">{unit.owner}</span>}
      {unit.wave !== undefined && <Tag tone="quiet">{t('units.wave', { n: unit.wave })}</Tag>}
      {unit.unresolved > 0 && <Tag tone="warning">{t('units.unresolved', { n: unit.unresolved })}</Tag>}
    </li>
  )
}

/** One candidate under validation. */
function CandidateRow({ candidate, t }: {
  readonly candidate: AuditCandidate
  readonly t: Translate
}): ReactNode {
  return (
    <li className="sa-unit">
      <span className="sa-unit-label">{candidate.title}</span>
      {candidate.proposedBy !== undefined && (
        <span className="sa-unit-owner">{t('candidates.proposedBy', { owner: candidate.proposedBy })}</span>
      )}
    </li>
  )
}

/** One finding, opening its first cited line. */
function FindingRow({ finding, open, t }: {
  readonly finding: AuditFinding
  readonly open: (citation: FindingCitation) => void
  readonly t: Translate
}): ReactNode {
  const citation = finding.citations[0]
  const body = (
    <>
      <Tag tone={VERDICT_TONE[finding.verdict]}>{t(VERDICT_LABEL[finding.verdict])}</Tag>
      <span className="sa-finding-title" title={finding.title}>{finding.title}</span>
      {finding.severity !== undefined && <Tag tone="neutral">{t('findings.severity', { severity: finding.severity })}</Tag>}
      {citation !== undefined && <span className="sa-finding-path">{citation.file}</span>}
    </>
  )
  if (citation === undefined) return <li className="sa-finding">{body}</li>
  const label = citation.line === undefined
    ? t('findings.open')
    : t('findings.openAria', { file: citation.file, line: citation.line })
  return (
    <li>
      <button type="button" className="sa-finding" aria-label={label} onClick={() => { open(citation) }}>
        {body}
      </button>
    </li>
  )
}

/** The run summary, live units, candidates, findings and draft prompts of a run the pane read. */
function RunBody({ snapshot, open, insert, t }: {
  readonly snapshot: AuditSnapshot
  readonly open: (citation: FindingCitation) => void
  readonly insert: (text: string) => boolean
  readonly t: Translate
}): ReactNode {
  const { metadata, coverage, candidates, findings, elapsedMs, selected } = snapshot
  const coverageValue = coverage === undefined
    ? t('coverage.none')
    : t('coverage.value', { covered: coverage.covered, total: coverage.total })
  const prompts: string[] = []
  const directory = selected ?? ''
  const status = metadata?.status
  if (status !== undefined && status !== 'in_progress') {
    prompts.push(t('prompts.continue', { directory, status: t(PHASE_LABEL[status]) }))
  }
  const needsValidation = findings?.needsValidation ?? 0
  if (needsValidation > 0) {
    prompts.push(t(pluralKey('prompts.needsValidation', needsValidation), { directory, n: needsValidation }))
  }
  const confirmedFinding = findings?.items.find(item => item.verdict === 'confirmed')
  if (confirmedFinding !== undefined) {
    prompts.push(t('prompts.confirmed', { directory, title: confirmedFinding.title }))
  } else if ((findings?.confirmed ?? 0) > 0) {
    prompts.push(t('prompts.confirmedAny', { directory }))
  }
  if (coverage !== undefined) prompts.push(t('prompts.coverage', { directory }))
  const active = coverage?.active ?? []
  const pending = candidates?.pending ?? []
  return (
    <>
      <dl className="sa-summary">
        <SummaryRow field="phase" label={t('phase.label')} value={t(PHASE_LABEL[metadata?.status ?? 'unknown'])} />
        <SummaryRow field="stage" label={t('stage.label')} value={t(STAGE_LABEL[metadata?.stage ?? 'unknown'])} />
        <SummaryRow field="coverage" label={t('coverage.label')} value={coverageValue} />
        <SummaryRow field="budget" label={t('budget.label')} value={budgetText(metadata, t)} />
        <SummaryRow field="profile" label={t('profile.label')} value={metadata?.profile ?? t('none')} />
        <SummaryRow field="source" label={t('source.label')} value={sourceText(metadata, t)} />
        <SummaryRow
          field="elapsed"
          label={t('elapsed.label')}
          value={elapsedMs === undefined ? t('none') : elapsedText(elapsedMs, t)}
        />
      </dl>
      <section className="sa-section" aria-label={t('coverage.title')}>
        <h3 className="sa-section-title">{t('coverage.title')}</h3>
        <CoverageCounts snapshot={snapshot} t={t} />
        {coverage !== undefined && coverage.skipped > 0 && (
          <p className="sa-note" role="note">{t(pluralKey('coverage.records', coverage.skipped), { n: coverage.skipped })}</p>
        )}
      </section>
      {active.length > 0 && (
        <section className="sa-section" aria-label={t('units.title')}>
          <h3 className="sa-section-title">{t('units.title')}</h3>
          <ul className="sa-list">
            {active.map(unit => <UnitRow key={unit.id} unit={unit} t={t} />)}
          </ul>
        </section>
      )}
      {pending.length > 0 && (
        <section className="sa-section" aria-label={t('candidates.title')}>
          <h3 className="sa-section-title">{t('candidates.title')}</h3>
          <ul className="sa-list">
            {pending.map((candidate, index) => (
              <CandidateRow key={candidate.fingerprint ?? `candidate:${String(index)}`} candidate={candidate} t={t} />
            ))}
          </ul>
          {candidates !== undefined && candidates.skipped > 0 && (
            <p className="sa-note" role="note">{t(pluralKey('candidates.records', candidates.skipped), { n: candidates.skipped })}</p>
          )}
        </section>
      )}
      <section className="sa-section" aria-label={t('findings.title')}>
        <h3 className="sa-section-title">{t('findings.title')}</h3>
        <div className="sa-counts">
          <Tag tone="danger">{t('findings.confirmed')} {findings?.confirmed ?? 0}</Tag>
          <Tag tone="warning">{t('findings.needsValidation')} {findings?.needsValidation ?? 0}</Tag>
          <Tag tone="quiet">{t('findings.rejected')} {findings?.rejected ?? 0}</Tag>
        </div>
        {findings === undefined || findings.items.length === 0
          ? <p className="sa-muted">{t('findings.empty')}</p>
          : (
            <ul className="sa-list">
              {findings.items.map((finding, index) => (
                <FindingRow
                  key={finding.fingerprint ?? `${finding.verdict}:${String(index)}`}
                  finding={finding}
                  open={open}
                  t={t}
                />
              ))}
            </ul>
          )}
        {findings !== undefined && findings.skipped > 0 && (
          <p className="sa-note" role="note">{t(pluralKey('findings.records', findings.skipped), { n: findings.skipped })}</p>
        )}
      </section>
      {prompts.length > 0 && (
        <section className="sa-section" aria-label={t('prompts.title')}>
          <h3 className="sa-section-title">{t('prompts.title')}</h3>
          <p className="sa-muted">{t('prompts.body')}</p>
          {prompts.map(text => <DraftPrompt key={text} text={text} t={t} insert={insert} />)}
        </section>
      )}
    </>
  )
}

/**
 * Render the security-audit tab body.
 * @param props - the tab, the Session's folder, the controller's snapshot and actions, the input actions and copy.
 * @returns the pane.
 */
export function SecurityAuditPane(props: SecurityAuditPaneProps): ReactNode {
  const { useTabInfo, sessionId, useSessions, useAudit, attach, select, reload, inputActions, t } = props
  const { tab } = useTabInfo()
  const snapshot = useAudit(state => state)
  const cwd = useSessions(state => state.byId[sessionId]?.cwd)
  useEffect(() => attach(), [attach])
  useEffect(() => tab.actions.bindCommands({ refresh: reload }), [tab.actions, reload])
  const open = (citation: FindingCitation): void => {
    const address = fileAddress(sessionId, cwd, citation.file)
    if (citation.line === undefined) tab.actions.openResource(address)
    else tab.actions.openResource(address, { params: { line: citation.line } })
  }
  const insert = (text: string): boolean => inputActions.insertQuote(text)
  const startMessage = buildStartMessage(t, {
    target: cwd, profile: 'standard', budget: null, checkIn: 'after_recon', models: {},
  })
  return (
    <div className="sa-pane" data-audit-phase={snapshot.phase}>
      <header className="sa-pane-header">
        <span className="sa-pane-icon"><IconShieldOutlineRegular size={15} /></span>
        <span className="sa-pane-title">{t('tab.title')}</span>
        <span className="sa-spacer" />
        {snapshot.runs.length > 0 && (
          <RunSwitcher runs={snapshot.runs} selected={snapshot.selected} select={select} t={t} />
        )}
        <Tooltip label={t('reload')} side="bottom">
          <button type="button" className="sa-icon-button" aria-label={t('reload')} aria-busy={snapshot.busy} onClick={reload}>
            <IconRefreshOutlineRegular size={14} />
          </button>
        </Tooltip>
      </header>
      {snapshot.problems.length > 0 && (
        <div className="sa-notices">
          {snapshot.problems.map((problem, index) => (
            <p key={`${problem.kind}:${String(index)}`} className="sa-notice" role="status">
              {problemText(problem, t)}
            </p>
          ))}
        </div>
      )}
      <div className="sa-pane-body">
        {snapshot.phase === 'loading' && <p className="sa-muted" role="status">{t('loading')}</p>}
        {snapshot.phase === 'empty' && (
          <div className="sa-empty">
            <span className="sa-empty-icon"><IconShieldOutlineRegular size={22} /></span>
            <h2 className="sa-empty-title">{t('empty.title')}</h2>
            <p className="sa-muted">{t('empty.body')}</p>
            <h3 className="sa-section-title">{t('empty.startLabel')}</h3>
            <DraftPrompt text={startMessage} t={t} insert={insert} />
          </div>
        )}
        {snapshot.phase === 'failed' && (
          <div className="sa-empty">
            <h2 className="sa-empty-title">{t('failed.title')}</h2>
            <p className="sa-muted">{t('failed.body')}</p>
          </div>
        )}
        {snapshot.phase === 'ready' && (
          <RunBody snapshot={snapshot} open={open} insert={insert} t={t} />
        )}
      </div>
    </div>
  )
}
