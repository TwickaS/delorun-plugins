/**
 * The security-audit tab body, in two modes. Live shows what the run is doing
 * now: an overview card with the phase, elapsed time, spend and settled units; the
 * boundary coverage map; the units a role owns; the candidates under validation;
 * the findings; the draft prompts; and the pause and stop controls. Report shows
 * the finished report: the counts header, the confirmed findings as cards with
 * their traces and denial tests, the records that need validation, the raw
 * markdown, and the copy and export actions.
 *
 * Report mode writes nothing; Live mode's controls run one human command each.
 * @module delorun-plugin-security-audit/client/pane
 */
import { useEffect, useState, type ReactNode } from 'react'
import {
  Button, IconChevronDownOutlineRegular, IconRefreshOutlineRegular, IconShieldOutlineRegular, Input, Menu, SegmentedControl,
  Tag, Tooltip, useClipboardCopy, type MenuEntry, type TagTone,
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
import type { AuditDigest, AuditProblem, AuditSnapshot } from './controller.ts'
import type { AuditCandidate, AuditFinding, AuditMetadata, AuditRunRef, AuditRunStatus, AuditStage, CoverageStatus, CoverageUnit, FindingCitation, FindingVerdict } from './runs.ts'
import { buildStartMessage } from './start-message.ts'

/** What one control command settled as. */
export interface ControlOutcome {
  /** Whether the command went through. */
  readonly ok: boolean
  /** The line the pane shows either way. */
  readonly message: string
}

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
  /**
   * Pause, resume or stop the shown run.
   * @param action - which control to ask for.
   * @param reason - why the run stops, for `stop`; empty otherwise.
   * @returns what the command settled as.
   */
  readonly control: (action: 'pause' | 'resume' | 'stop', reason: string) => Promise<ControlOutcome>
  /**
   * Write the report documents to one folder.
   * @param folder - an absolute folder the person names.
   * @returns what the command settled as.
   */
  readonly exportReport: (folder: string) => Promise<ControlOutcome>
}

/** Full props of the security-audit pane body. */
export type SecurityAuditPaneProps =
  PropsRuntime<'sidebar.right.pane.tab'>
  & InjectFace<SecurityAuditPaneInjected>
  & PropsLocale<typeof NS>

/** The locale's translate seat. */
type Translate = PropsLocale<typeof NS>['t']

/** Which of the pane's two modes is shown. */
type Mode = 'live' | 'report'

/** Which raw document the report's markdown view shows. */
type RawDocument = 'report' | 'detail'

/** How each recorded lifecycle state reads. */
const PHASE_LABEL: Readonly<Record<AuditRunStatus, SecurityAuditKey>> = {
  in_progress: 'phase.in_progress',
  complete: 'phase.complete',
  incomplete: 'phase.incomplete',
  unknown: 'phase.unknown',
}

/** The tone of each lifecycle state. */
const PHASE_TONE: Readonly<Record<AuditRunStatus, TagTone>> = {
  in_progress: 'info',
  complete: 'success',
  incomplete: 'warning',
  unknown: 'quiet',
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

/** Remaining units of a {@link COVERAGE_ROW} set have no copy of their own. */
const COVERAGE_STATUS_TONE: Readonly<Record<CoverageStatus, TagTone>> = {
  covered: 'success',
  in_progress: 'info',
  candidate: 'info',
  blocked: 'warning',
  deferred: 'quiet',
  planned: 'quiet',
  out_of_scope: 'quiet',
  not_applicable: 'quiet',
  unknown: 'quiet',
}

/** The tones a severity word selects, from the report schema's own order. */
const SEVERITY_TONE: Readonly<Record<string, TagTone>> = {
  critical: 'danger',
  high: 'danger',
  medium: 'warning',
  low: 'info',
  informational: 'quiet',
}

/** The severities that carry a denial test. */
const PROVEN_SEVERITIES: readonly string[] = ['critical', 'high']

/** How many recent digest lines Live mode lists. */
const DIGEST_LINES = 3

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
 * Spell out the clock time of one digest line.
 * @param at - the epoch milliseconds it was written at.
 * @returns the time, in the browser's own 24-hour form.
 */
function clockText(at: number): string {
  return new Date(at).toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit' })
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

/** The run's phase, elapsed time, spend and settled units, with its controls. */
function Overview({ snapshot, t, busy, act }: {
  readonly snapshot: AuditSnapshot
  readonly t: Translate
  readonly busy: boolean
  readonly act: (action: 'pause' | 'resume' | 'stop', reason: string) => void
}): ReactNode {
  const metadata = snapshot.metadata
  const status = metadata?.status ?? 'unknown'
  const coverage = snapshot.coverage
  const done = coverage === undefined ? 0 : coverage.covered + coverage.deferred + coverage.blocked
  const total = coverage?.total ?? 0
  const share = total === 0 ? 0 : Math.round((done / total) * 100)
  const paused = snapshot.control?.command === 'pause'
  const stopped = snapshot.control?.command === 'stop' || status === 'incomplete' || status === 'complete'
  const running = status === 'in_progress'
  return (
    <section className="sa-card sa-overview" aria-label={t('overview.title')}>
      <div className="sa-overview-grid">
        <div className="sa-field">
          <span className="sa-field-label">{t('overview.phase')}</span>
          <span className="sa-overview-tags">
            <Tag tone={PHASE_TONE[status]}>{t(PHASE_LABEL[status])}</Tag>
            <Tag tone="neutral">{t(STAGE_LABEL[metadata?.stage ?? 'unknown'])}</Tag>
          </span>
        </div>
        <div className="sa-field">
          <span className="sa-field-label">{t('overview.elapsed')}</span>
          <span className="sa-field-value">
            {snapshot.elapsedMs === undefined ? t('none') : elapsedText(snapshot.elapsedMs, t)}
          </span>
        </div>
        <div className="sa-field">
          <span className="sa-field-label">{t('overview.spend')}</span>
          <span className="sa-field-value" title={budgetText(metadata, t)}>{budgetText(metadata, t)}</span>
        </div>
        <div className="sa-field">
          <span className="sa-field-label">{t('overview.units')}</span>
          <span className="sa-field-value">{t('overview.unitsValue', { done, total })}</span>
        </div>
      </div>
      <div
        className="sa-bar"
        role="progressbar"
        aria-label={t('overview.progressAria', { done, total })}
        aria-valuemin={0}
        aria-valuemax={total}
        aria-valuenow={done}
      >
        <span className="sa-bar-fill" data-share={share} style={{ width: `${String(share)}%` }} />
      </div>
      {(running || paused) && (
        <div className="sa-overview-actions">
          {paused
            ? <Button size="sm" variant="outline" disabled={busy} onClick={() => { act('resume', '') }}>{t('control.resume')}</Button>
            : <Button size="sm" variant="outline" disabled={busy} onClick={() => { act('pause', '') }}>{t('control.pause')}</Button>}
          <Button size="sm" variant="ghost" disabled={busy || stopped} onClick={() => { act('stop', '') }}>{t('control.stop')}</Button>
        </div>
      )}
      {(paused || snapshot.control?.command === 'stop') && snapshot.control !== undefined && (
        <p className="sa-note" role="note">
          {snapshot.control.command === 'pause' ? t('control.paused') : t('control.stopped')}
          {snapshot.control.reason === undefined ? '' : ` — ${snapshot.control.reason}`}
        </p>
      )}
    </section>
  )
}

/** One phase-change notification, in the quiet card style, dismissible. */
function DigestNotice({ digest, t, dismiss }: {
  readonly digest: AuditDigest
  readonly t: Translate
  readonly dismiss: () => void
}): ReactNode {
  return (
    <section className="sa-card sa-notice-card" role="status">
      <span className="sa-notice-icon" data-kind={digest.kind} aria-hidden />
      <div className="sa-notice-text">
        <p className="sa-notice-title">{t(digest.kind === 'stage' ? 'digest.stage' : 'digest.units', {
          stage: t(STAGE_LABEL[digest.stage]), done: digest.covered, total: digest.total,
        })}</p>
        <p className="sa-notice-line">{digestLine(digest, t)}</p>
      </div>
      <button type="button" className="sa-notice-close" aria-label={t('digest.dismiss')} onClick={dismiss}>
        <IconChevronDownOutlineRegular size={12} />
      </button>
    </section>
  )
}

/**
 * Spell out one digest line.
 * @param digest - the digest.
 * @param t - the translate seat.
 * @returns the line.
 */
function digestLine(digest: AuditDigest, t: Translate): string {
  return t('digest.line', {
    time: clockText(digest.at),
    covered: digest.covered,
    total: digest.total,
    spend: digest.spend ?? 0,
    budget: digest.budget === null || digest.budget === undefined ? t('budget.none') : String(digest.budget),
  })
}

/** The newest digest lines, oldest first. */
function DigestLines({ digests, t }: {
  readonly digests: readonly AuditDigest[]
  readonly t: Translate
}): ReactNode {
  if (digests.length === 0) return null
  return (
    <section className="sa-section" aria-label={t('digest.recent')}>
      <h3 className="sa-section-title">{t('digest.recent')}</h3>
      {digests.map(digest => (
        <p key={`${String(digest.at)}:${digest.kind}`} className="sa-note">{digestLine(digest, t)}</p>
      ))}
    </section>
  )
}

/** The boundary tree with a state per branch, collapsed to its first branches. */
function CoverageMap({ units, t }: {
  readonly units: readonly CoverageUnit[]
  readonly t: Translate
}): ReactNode {
  const [open, setOpen] = useState(true)
  const branches = new Map<string, CoverageUnit[]>()
  for (const unit of units) {
    const branch = unit.boundary ?? ''
    const list = branches.get(branch)
    if (list === undefined) branches.set(branch, [unit])
    else list.push(unit)
  }
  const entries = [...branches.entries()].sort((left, right) => left[0].localeCompare(right[0]))
  if (entries.length === 0) return null
  return (
    <section className="sa-section" aria-label={t('map.title')}>
      <button
        type="button"
        className="sa-disclosure"
        aria-expanded={open}
        onClick={() => { setOpen(value => !value) }}
      >
        <h3 className="sa-section-title">{t('map.title')}</h3>
        <Tag tone="quiet">{t(pluralKey('map.branches', entries.length), { n: entries.length })}</Tag>
        <span className="sa-spacer" />
        <IconChevronDownOutlineRegular size={12} className={open ? 'sa-chevron sa-chevron-open' : 'sa-chevron'} />
      </button>
      {open && (
        <div className="sa-map">
          {entries.map(([boundary, group]) => (
            <div key={boundary === '' ? 'unrecorded' : boundary} className="sa-map-branch">
              <p className="sa-map-boundary" title={boundary}>{boundary === '' ? t('map.unrecorded') : boundary}</p>
              <div className="sa-counts">
                {[...group.reduce((counts, unit) => counts.set(unit.status, (counts.get(unit.status) ?? 0) + 1), new Map<CoverageStatus, number>())]
                  .map(([state, count]) => (
                    <Tag key={state} tone={COVERAGE_STATUS_TONE[state]}>{t(pluralKey('map.status', count), { n: count, state: t(`map.state.${state}` as SecurityAuditKey) })}</Tag>
                  ))}
              </div>
            </div>
          ))}
        </div>
      )}
    </section>
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

/** One cited line as a button that opens the document preview at it. */
function TraceLink({ citation, open, t }: {
  readonly citation: FindingCitation
  readonly open: (citation: FindingCitation) => void
  readonly t: Translate
}): ReactNode {
  const label = citation.line === undefined
    ? t('findings.open')
    : t('findings.openAria', { file: citation.file, line: citation.line })
  return (
    <button type="button" className="sa-trace" aria-label={label} onClick={() => { open(citation) }}>
      {citation.line === undefined ? citation.file : `${citation.file}:${String(citation.line)}`}
    </button>
  )
}

/** One confirmed finding as a report card, expandable to its full record. */
function FindingCard({ finding, sessionId, cwd, open, t }: {
  readonly finding: AuditFinding
  readonly sessionId: SessionId
  readonly cwd: string | undefined
  readonly open: (citation: FindingCitation) => void
  readonly t: Translate
}): ReactNode {
  const [expanded, setExpanded] = useState(false)
  const severity = finding.severity
  const needsTest = severity !== undefined && PROVEN_SEVERITIES.includes(severity)
  const copyText = [
    finding.title,
    severity === undefined ? '' : t('findings.severity', { severity }),
    finding.boundary === undefined ? '' : `${t('report.boundary')}: ${finding.boundary}`,
    ...finding.citations.map(citation => citation.line === undefined
      ? citation.file
      : `${citation.file}:${String(citation.line)}`),
    finding.summary ?? '',
  ].filter(line => line !== '').join('\n')
  const { copied, onCopy } = useClipboardCopy(copyText)
  return (
    <article className="sa-card sa-finding-card">
      <header className="sa-finding-head">
        <Tag tone={severity === undefined ? 'quiet' : SEVERITY_TONE[severity] ?? 'neutral'}>
          {severity === undefined ? t('report.severityNone') : t('findings.severity', { severity })}
        </Tag>
        <span className="sa-spacer" />
        <Button size="sm" variant="ghost" aria-label={t('report.copyAria', { title: finding.title })} onClick={onCopy}>
          {copied ? t('report.copied') : t('report.copy')}
        </Button>
      </header>
      <h3 className="sa-finding-name">{finding.title}</h3>
      <p className="sa-field-label sa-boundary" title={finding.boundary}>
        {t('report.boundary')}: {finding.boundary ?? t('report.noBoundary')}
      </p>
      {finding.summary !== undefined && <p className="sa-finding-summary">{finding.summary}</p>}
      <div className="sa-traces">
        {finding.citations.map(citation => (
          <TraceLink
            key={`${citation.file}:${String(citation.line)}`}
            citation={citation}
            open={open}
            t={t}
          />
        ))}
      </div>
      {needsTest && (
        <section className="sa-denial" aria-label={t('report.denial')}>
          <div className="sa-denial-head">
            <span className="sa-section-title">{t('report.denial')}</span>
            <Tag tone={finding.denialTest?.proven === true ? 'success' : 'warning'}>
              {finding.denialTest?.proven === true ? t('report.proven') : t('report.proposal')}
            </Tag>
          </div>
          {finding.denialTest === undefined
            ? <p className="sa-note" role="note">{t('report.denialMissing')}</p>
            : (
              <>
                {finding.denialTest.file !== undefined && (
                  <div className="sa-denial-line">
                    <span className="sa-field-label">{t('report.denialFile')}</span>
                    <TraceLink citation={{ file: finding.denialTest.file, line: undefined }} open={open} t={t} />
                  </div>
                )}
                {finding.denialTest.assertion !== undefined && (
                  <p className="sa-note">{t('report.denialAssertion')}: {finding.denialTest.assertion}</p>
                )}
              </>
            )}
        </section>
      )}
      <button
        type="button"
        className="sa-disclosure sa-record-toggle"
        aria-expanded={expanded}
        onClick={() => { setExpanded(value => !value) }}
      >
        <span className="sa-section-title">{expanded ? t('report.less') : t('report.full')}</span>
        <span className="sa-spacer" />
        <IconChevronDownOutlineRegular size={12} className={expanded ? 'sa-chevron sa-chevron-open' : 'sa-chevron'} />
      </button>
      {expanded && (
        <pre className="sa-raw" data-case={sessionId === undefined ? 'raw' : 'record'}>
          {JSON.stringify(finding.record, null, 2)}
        </pre>
      )}
    </article>
  )
}

/** One record that needs validation, as a table row. */
function NeedsRow({ finding, open, t }: {
  readonly finding: AuditFinding
  readonly open: (citation: FindingCitation) => void
  readonly t: Translate
}): ReactNode {
  const citation = finding.citations[0]
  return (
    <div className="sa-table-row" role="row">
      <span className="sa-table-cell sa-table-title" role="cell" title={finding.title}>{finding.title}</span>
      <span className="sa-table-cell" role="cell">
        {citation === undefined ? t('none') : <TraceLink citation={citation} open={open} t={t} />}
      </span>
      <span className="sa-table-cell" role="cell">
        {finding.blockers.length === 0 ? t('report.nvNoBlocker') : finding.blockers.join('; ')}
      </span>
      <span className="sa-table-cell" role="cell">
        {finding.nextStep ?? t('report.nvNoNext')}
      </span>
    </div>
  )
}

/** The report's counts and scope header, with the honest partial statement. */
function ReportHeader({ snapshot, t }: {
  readonly snapshot: AuditSnapshot
  readonly t: Translate
}): ReactNode {
  const metadata = snapshot.metadata
  const coverage = snapshot.coverage
  const partial = metadata?.status === 'incomplete'
  const scope = metadata === undefined || metadata.scopePaths.length === 0
    ? t('report.scopeAll')
    : metadata.scopePaths.join(', ')
  return (
    <section className="sa-card sa-report-head" aria-label={t('report.title')}>
      <p className="sa-report-repo">{metadata?.repo ?? t('none')}</p>
      <div className="sa-overview-grid">
        <div className="sa-field">
          <span className="sa-field-label">{t('report.profile')}</span>
          <span className="sa-field-value">{metadata?.profile ?? t('none')}</span>
        </div>
        <div className="sa-field">
          <span className="sa-field-label">{t('report.scope')}</span>
          <span className="sa-field-value" title={scope}>{scope}</span>
        </div>
        <div className="sa-field">
          <span className="sa-field-label">{t('report.budget')}</span>
          <span className="sa-field-value">{budgetText(metadata, t)}</span>
        </div>
        <div className="sa-field">
          <span className="sa-field-label">{t('coverage.label')}</span>
          <span className="sa-counts">
            <Tag tone="success">{t('report.covered', { n: coverage?.covered ?? 0 })}</Tag>
            <Tag tone="quiet">{t('report.deferred', { n: coverage?.deferred ?? 0 })}</Tag>
            <Tag tone="warning">{t('report.blocked', { n: coverage?.blocked ?? 0 })}</Tag>
          </span>
        </div>
      </div>
      {partial && (
        <p className="sa-partial" role="note">
          {metadata?.statusReason === undefined
            ? t('report.partialNoReason')
            : t('report.partial', { reason: metadata.statusReason })}
        </p>
      )}
    </section>
  )
}

/** The report's own body: findings, denial tests, the table and the raw markdown. */
function ReportBody({ snapshot, sessionId, cwd, open, t, exportReport }: {
  readonly snapshot: AuditSnapshot
  readonly sessionId: SessionId
  readonly cwd: string | undefined
  readonly open: (citation: FindingCitation) => void
  readonly t: Translate
  readonly exportReport: (folder: string) => Promise<ControlOutcome>
}): ReactNode {
  const [raw, setRaw] = useState(false)
  const [document, setDocument] = useState<RawDocument>('report')
  const [folder, setFolder] = useState('')
  const [outcome, setOutcome] = useState<ControlOutcome | undefined>(undefined)
  const [busy, setBusy] = useState(false)
  const items = snapshot.findings?.items ?? []
  const confirmed = items.filter(finding => finding.verdict === 'confirmed')
  const needsValidation = items.filter(finding => finding.verdict === 'needs_validation')
  const report = snapshot.report
  const run = async (): Promise<void> => {
    if (folder.trim() === '') return
    setBusy(true)
    const settled = await exportReport(folder.trim())
    setBusy(false)
    setOutcome(settled)
  }
  return (
    <>
      <ReportHeader snapshot={snapshot} t={t} />
      <div className="sa-report-actions">
        <Button
          size="sm"
          variant="ghost"
          aria-pressed={raw}
          onClick={() => { setRaw(value => !value) }}
        >
          {raw ? t('report.structured') : t('report.raw')}
        </Button>
        <span className="sa-spacer" />
      </div>
      {raw
        ? (
          <section className="sa-section" aria-label={t('report.document')}>
            <SegmentedControl
              id="sa-raw"
              value={document}
              label={t('report.document')}
              options={[
                { value: 'report', label: 'REPORT.md' },
                { value: 'detail', label: 'FINDINGS-DETAIL.md' },
              ]}
              onChange={setDocument}
            />
            {report === undefined || (document === 'report' ? report.report : report.detail) === undefined
              ? <p className="sa-muted">{t('report.notWritten')}</p>
              : <pre className="sa-raw">{document === 'report' ? report.report : report.detail}</pre>}
          </section>
        )
        : (
          <>
            <section className="sa-section" aria-label={t('report.confirmed')}>
              <h3 className="sa-section-title">{t('report.confirmed')}</h3>
              {confirmed.length === 0
                ? <p className="sa-muted">{t('report.none')}</p>
                : confirmed.map((finding, index) => (
                  <FindingCard
                    key={finding.fingerprint ?? `confirmed:${String(index)}`}
                    finding={finding}
                    sessionId={sessionId}
                    cwd={cwd}
                    open={open}
                    t={t}
                  />
                ))}
            </section>
            <section className="sa-section" aria-label={t('report.needsValidation')}>
              <h3 className="sa-section-title">{t('report.needsValidation')}</h3>
              <p className="sa-muted">{t('report.nvBody')}</p>
              {needsValidation.length === 0
                ? <p className="sa-muted">{t('report.nvEmpty')}</p>
                : (
                  <div className="sa-table" role="table" aria-label={t('report.needsValidation')}>
                    <div className="sa-table-head" role="row">
                      <span className="sa-table-cell" role="columnheader">{t('report.nvTitle')}</span>
                      <span className="sa-table-cell" role="columnheader">{t('report.nvTrace')}</span>
                      <span className="sa-table-cell" role="columnheader">{t('report.nvBlocker')}</span>
                      <span className="sa-table-cell" role="columnheader">{t('report.nvNext')}</span>
                    </div>
                    {needsValidation.map((finding, index) => (
                      <NeedsRow key={finding.fingerprint ?? `needs:${String(index)}`} finding={finding} open={open} t={t} />
                    ))}
                  </div>
                )}
            </section>
            <section className="sa-section" aria-label={t('report.export')}>
              <h3 className="sa-section-title">{t('report.export')}</h3>
              <p className="sa-muted">{t('report.exportBody')}</p>
              <div className="sa-export">
                <Input
                  value={folder}
                  aria-label={t('report.exportFolder')}
                  placeholder={t('report.exportPlaceholder')}
                  onChange={event => { setFolder(event.target.value) }}
                  onKeyDown={event => { if (event.key === 'Enter') void run() }}
                />
                <Button
                  size="sm"
                  variant="outline"
                  disabled={busy || folder.trim() === ''}
                  onClick={() => { void run() }}
                >
                  {t('report.export')}
                </Button>
              </div>
              {outcome !== undefined && (
                <p className={outcome.ok ? 'sa-note' : 'sa-note sa-error'} role="status">{outcome.message}</p>
              )}
            </section>
          </>
        )}
    </>
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
      {coverage !== undefined && <CoverageMap units={coverage.units} t={t} />}
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
  const {
    useTabInfo, sessionId, useSessions, useAudit, attach, select, reload, control, exportReport, inputActions, t,
  } = props
  const { tab } = useTabInfo()
  const snapshot = useAudit(state => state)
  const cwd = useSessions(state => state.byId[sessionId]?.cwd)
  const [mode, setMode] = useState<Mode>('live')
  const [stopOpen, setStopOpen] = useState(false)
  const [reason, setReason] = useState('')
  const [dismissedAt, setDismissedAt] = useState(0)
  const [outcome, setOutcome] = useState<ControlOutcome | undefined>(undefined)
  const [controlBusy, setControlBusy] = useState(false)
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
  const newest = snapshot.digests[snapshot.digests.length - 1]
  const notice = newest !== undefined && newest.at > dismissedAt ? newest : undefined
  const act = (action: 'pause' | 'resume' | 'stop', why: string): void => {
    if (action === 'stop' && !stopOpen && why === '') {
      setStopOpen(true)
      return
    }
    setControlBusy(true)
    void control(action, why).then((settled) => {
      setControlBusy(false)
      setOutcome(settled)
      if (settled.ok) {
        setStopOpen(false)
        if (action === 'stop') setReason('')
      }
    })
  }
  return (
    <div className="sa-pane" data-audit-phase={snapshot.phase} data-audit-mode={mode}>
      <header className="sa-pane-header">
        <span className="sa-pane-icon">
          <IconShieldOutlineRegular size={15} />
          {notice !== undefined && <span className="sa-badge" title={t('digest.badge')} />}
        </span>
        <span className="sa-pane-title">{t('tab.title')}</span>
        <span className="sa-spacer" />
        <SegmentedControl
          id="sa-mode"
          className="sa-mode"
          value={mode}
          label={t('mode.label')}
          options={[
            { value: 'live', label: t('mode.live') },
            { value: 'report', label: t('mode.report') },
          ]}
          onChange={setMode}
        />
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
          <>
            <Overview snapshot={snapshot} t={t} busy={controlBusy} act={act} />
            {stopOpen && (
              <div className="sa-card sa-stop">
                <p className="sa-field-label">{t('control.reason')}</p>
                <Input
                  value={reason}
                  aria-label={t('control.reason')}
                  placeholder={t('control.reasonPlaceholder')}
                  onChange={event => { setReason(event.target.value) }}
                  onKeyDown={(event) => { if (event.key === 'Enter') act('stop', reason.trim()) }}
                />
                <div className="sa-overview-actions">
                  <Button size="sm" variant="outline" disabled={controlBusy} onClick={() => { act('stop', reason.trim()) }}>
                    {t('control.stopConfirm')}
                  </Button>
                  <Button size="sm" variant="ghost" onClick={() => { setStopOpen(false) }}>{t('control.cancel')}</Button>
                </div>
              </div>
            )}
            {outcome !== undefined && (
              <p className={outcome.ok ? 'sa-note' : 'sa-note sa-error'} role="status">{outcome.message}</p>
            )}
            {mode === 'live' && notice !== undefined && (
              <DigestNotice digest={notice} t={t} dismiss={() => { setDismissedAt(notice.at) }} />
            )}
            {mode === 'live'
              ? (
                <>
                  <DigestLines digests={snapshot.digests.slice(-DIGEST_LINES)} t={t} />
                  <RunBody snapshot={snapshot} open={open} insert={insert} t={t} />
                </>
              )
              : (
                <ReportBody
                  snapshot={snapshot}
                  sessionId={sessionId}
                  cwd={cwd}
                  open={open}
                  t={t}
                  exportReport={exportReport}
                />
              )}
          </>
        )}
      </div>
    </div>
  )
}
