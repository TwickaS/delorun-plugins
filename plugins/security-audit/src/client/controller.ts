/**
 * The pane's data face: it discovers audit runs through the workspace files
 * Remote, reads the selected run's shared files, and follows that run directory's
 * change stream. The controller owns no copy: the body renders its snapshot
 * source, and a file this read cannot use keeps the run's last good value, with a
 * structured problem describing why.
 *
 * Observe-only. Nothing here starts, stops or steers a run.
 * @module delorun-plugin-security-audit/client/controller
 */
import { createSnapshotStore, type SnapshotStore } from '@deepseek-ai/dsh-client-store'
import type { WorkspaceDirectoryListing, WorkspaceFileText, WorkspaceFileWatchFrame } from '@deepseek-ai/dsh-api-workspace-files/types'
import type { RemoteResult, RemoteStreamHandle } from '@deepseek-ai/dsh-typert-protocol'
import {
  CANDIDATES_FILE, CONTROL_FILE, COVERAGE_LEDGER_FILE, FINDINGS_DETAIL_FILE, FINDINGS_FILE, NEEDS_VALIDATION_FILE,
  REPORT_FILE, RUNS_DIRECTORY, RUN_METADATA_FILE,
  candidateRuns, inWorkspace, orderRuns, parseCandidates, parseControl, parseCoverage, parseFindings, parseMetadata,
  type AuditCandidate, type AuditControl, type AuditDocumentName, type AuditFileName, type AuditListing,
  type AuditMetadata, type AuditRunRef,
  type AuditRunStatus, type AuditStage, type CandidatesSummary, type CoverageSummary, type FindingsSummary,
  type ReportDocuments,
} from './runs.ts'

/** How long a burst of watch frames waits before the run is read again. */
const WATCH_DEBOUNCE_MS = 150

/** How often the elapsed time advances while a run is in progress. */
const CLOCK_MS = 10_000

/** How many settled units pass before the run writes another digest line. */
const UNITS_PER_DIGEST = 5

/** How many digest lines one run keeps; older lines fall off the front. */
const DIGEST_LIMIT = 12

/** What the pane is doing with the selected run. */
export type AuditPhase = 'loading' | 'ready' | 'empty' | 'failed'

/** Why one shared file could not be used on this read. */
export type AuditFileReason = 'malformed' | 'truncated' | 'unreadable'

/** One digest line: what the run had reached when the line was written. */
export interface AuditDigest {
  /** The phase the run had reached. */
  readonly stage: AuditStage
  /** The lifecycle state at that moment. */
  readonly status: AuditRunStatus
  /** Units covered at that moment. */
  readonly covered: number
  /** Units the run planned to cover. */
  readonly total: number
  /** Agent invocations spent at that moment. */
  readonly spend: number | undefined
  /** The budget in force, or `null` when the run sets none. */
  readonly budget: number | null | undefined
  /** What moved: the phase, or a run of settled units. */
  readonly kind: 'stage' | 'units'
  /** When the line was written, in epoch milliseconds. */
  readonly at: number
}

/** One reason the pane shows a quiet notice. */
export type AuditProblem =
  | { readonly kind: 'file'; readonly file: AuditFileName | AuditDocumentName | typeof CONTROL_FILE; readonly reason: AuditFileReason }
  | { readonly kind: 'directory'; readonly directory: string }
  | { readonly kind: 'watch' }
  | { readonly kind: 'workspace' }

/** Everything the body renders. */
export interface AuditSnapshot {
  readonly phase: AuditPhase
  /** The digest lines written so far, oldest first. */
  readonly digests: readonly AuditDigest[]
  /** The report documents, or the last good value while a read fails. */
  readonly report: ReportDocuments | undefined
  /** The control a person last asked of the run, when the run directory records one. */
  readonly control: AuditControl | undefined
  /** Every discovered run, newest first. */
  readonly runs: readonly AuditRunRef[]
  /** The selected run's workspace-relative directory. */
  readonly selected: string | undefined
  /** The selected run's metadata, or the last good value while a read fails. */
  readonly metadata: AuditMetadata | undefined
  /** The selected run's coverage counts and live units, or the last good value while a read fails. */
  readonly coverage: CoverageSummary | undefined
  /** The selected run's candidates, or the last good value while a read fails. */
  readonly candidates: CandidatesSummary | undefined
  /** The selected run's records, or the last good value while a read fails. */
  readonly findings: FindingsSummary | undefined
  /** Elapsed time as of this snapshot, when the run records a start. */
  readonly elapsedMs: number | undefined
  /** Quiet notices: unreadable files, an unlistable directory, a stopped watch. */
  readonly problems: readonly AuditProblem[]
  /** Whether a discovery or run read is in flight. */
  readonly busy: boolean
}

/** What the pane can read, injected so the controller is testable without a Remote. */
export interface AuditFileAccess {
  /**
   * List one workspace-relative directory.
   * @param path - the workspace-relative directory.
   * @param signal - caller cancellation.
   * @returns the listing, or the Remote failure.
   */
  readonly list: (path: string, signal: AbortSignal) => Promise<RemoteResult<WorkspaceDirectoryListing>>
  /**
   * Read one workspace file.
   * @param path - the absolute or workspace-relative file path.
   * @param signal - caller cancellation.
   * @returns the page, or the Remote failure.
   */
  readonly read: (path: string, signal: AbortSignal) => Promise<RemoteResult<WorkspaceFileText>>
  /**
   * Watch one target for invalidations.
   * @param path - the target path.
   * @param signal - watch cancellation.
   * @returns the watch generation.
   */
  readonly watch: (path: string, signal: AbortSignal) => RemoteStreamHandle<WorkspaceFileWatchFrame, never>
}

/** Everything the controller needs from the page around it. */
export interface AuditControllerDeps extends AuditFileAccess {
  /** The Session's workspace root, as the Host reports it. */
  readonly cwd: () => string | undefined
  /** The clock, for elapsed time; defaults to `Date.now`. */
  readonly now?: () => number
}

/** The snapshot before anything was discovered. */
const INITIAL: AuditSnapshot = {
  phase: 'loading', digests: [], report: undefined, control: undefined,
  runs: [], selected: undefined, metadata: undefined, coverage: undefined,
  candidates: undefined, findings: undefined, elapsedMs: undefined, problems: [], busy: false,
}

/** One listed directory's outcome. */
type ListedDirectory =
  | { readonly kind: 'ok'; readonly entries: WorkspaceDirectoryListing['entries'] }
  | { readonly kind: 'missing' }
  | { readonly kind: 'failed' }

/** One read file's outcome, with a recognised parse. */
type ReadFile<Value> =
  | { readonly kind: 'ok'; readonly value: Value }
  | { readonly kind: 'missing' }
  | { readonly kind: 'invalid'; readonly reason: AuditFileReason }

/**
 * How long the run has been (or was) going.
 * @param metadata - the selected run's metadata.
 * @param now - the current time.
 * @returns the elapsed milliseconds, or `undefined` before the run records a start.
 */
export function elapsedOf(metadata: AuditMetadata | undefined, now: number): number | undefined {
  if (metadata?.startedAt === undefined) return undefined
  return Math.max(0, (metadata.finishedAt ?? now) - metadata.startedAt)
}

/**
 * The pane's run discovery, reads and watch.
 *
 * A body attaches while it is drawn; detaching stops the watch and the clock
 * without losing the last snapshot, and disposing the controller ends every
 * outstanding read.
 */
export class SecurityAuditController {
  /** The one source the body renders from. */
  readonly state: SnapshotStore<AuditSnapshot> = createSnapshotStore(INITIAL)

  private readonly deps: AuditControllerDeps
  private readonly lastGood: {
    metadata?: AuditMetadata
    coverage?: CoverageSummary
    candidates?: CandidatesSummary
    findings?: FindingsSummary
    report?: ReportDocuments
    control?: AuditControl
  } = {}

  private used = 0
  private disposed = false
  private discovery: AbortController | undefined
  private runRead: AbortController | undefined
  private discoveryGeneration = 0
  private readGeneration = 0
  private watchHandle: RemoteStreamHandle<WorkspaceFileWatchFrame, never> | undefined
  private watchAbort: AbortController | undefined
  private watched: string | undefined
  private timer: ReturnType<typeof setTimeout> | undefined
  private clock: ReturnType<typeof setInterval> | undefined
  private loadedDirectory: string | undefined
  private watchingParent = false

  private phase: AuditPhase = 'loading'
  private runs: readonly AuditRunRef[] = []
  private selected: string | undefined
  private metadata: AuditMetadata | undefined
  private coverage: CoverageSummary | undefined
  private candidates: CandidatesSummary | undefined
  private findings: FindingsSummary | undefined
  private elapsedMs: number | undefined
  private problems: readonly AuditProblem[] = []
  private busy = false
  private digests: readonly AuditDigest[] = []
  private report: ReportDocuments | undefined
  private control: AuditControl | undefined
  private digestStage: AuditStage | undefined
  private digestDone = 0

  /** @param deps - the workspace root, the file access, and the clock. */
  constructor(deps: AuditControllerDeps) {
    this.deps = deps
  }

  /**
   * Start reading while a body is drawn.
   * @returns the release; the last release stops the watch and the clock.
   */
  attach(): () => void {
    this.used += 1
    if (this.used === 1 && !this.disposed) {
      void this.refresh()
      this.startClock()
    }
    let attached = true
    return () => {
      if (!attached) return
      attached = false
      this.used -= 1
      if (this.used === 0) {
        this.stopWatch()
        this.stopClock()
      }
    }
  }

  /**
   * The run the pane shows, which its control commands name.
   * @returns the workspace-relative run directory, or `undefined` before one is selected.
   */
  directory(): string | undefined {
    return this.selected
  }

  /** Discover the runs again and read the selected one again. */
  reload(): void {
    if (!this.disposed) void this.refresh()
  }

  /**
   * Select one discovered run.
   * @param directory - its workspace-relative directory.
   */
  select(directory: string): void {
    if (this.disposed || this.selected === directory) return
    this.selected = directory
    this.stopWatch()
    void this.readSelected()
  }

  /** Stop every read, watch and timer; the controller is unusable afterwards. */
  dispose(): void {
    this.disposed = true
    this.discoveryGeneration += 1
    this.readGeneration += 1
    this.discovery?.abort()
    this.runRead?.abort()
    this.stopWatch()
    this.stopClock()
  }

  /** Rediscover every run and then read the selected one. */
  private async refresh(): Promise<void> {
    const generation = ++this.discoveryGeneration
    this.discovery?.abort()
    const abort = new AbortController()
    this.discovery = abort
    const cwd = this.deps.cwd()
    if (cwd === undefined) {
      this.phase = 'failed'
      this.busy = false
      this.problems = [{ kind: 'workspace' }]
      this.publish()
      return
    }
    this.busy = true
    if (this.runs.length === 0) this.phase = 'loading'
    this.publish()
    const listed = await this.listDirectory(RUNS_DIRECTORY, abort.signal)
    if (this.disposed || generation !== this.discoveryGeneration) return
    const problems: AuditProblem[] = []
    const listings: AuditListing[] = []
    if (listed.kind === 'ok') listings.push({ directory: RUNS_DIRECTORY, entries: listed.entries })
    else if (listed.kind === 'failed') problems.push({ kind: 'directory', directory: RUNS_DIRECTORY })
    const candidates = listings.flatMap(listing => candidateRuns(listing))
    const withRecency = await Promise.all(candidates.map(candidate => this.withRecency(candidate, cwd, abort.signal)))
    if (this.disposed || generation !== this.discoveryGeneration) return
    this.runs = orderRuns(withRecency)
    this.problems = problems
    const kept = this.runs.find(run => run.directory === this.selected)
    this.selected = (kept ?? this.runs[0])?.directory
    if (this.selected === undefined) {
      this.clearRun()
      this.loadedDirectory = undefined
      this.phase = problems.length > 0 ? 'failed' : 'empty'
      this.busy = false
      this.publish()
      this.watch(RUNS_DIRECTORY, true)
      return
    }
    await this.readSelected()
  }

  /**
   * List one directory, treating a missing directory as no runs.
   * @param directory - the workspace-relative directory.
   * @param signal - caller cancellation.
   * @returns what the listing says.
   */
  private async listDirectory(directory: string, signal: AbortSignal): Promise<ListedDirectory> {
    const result = await this.deps.list(directory, signal)
    if (result.ok) return { kind: 'ok', entries: result.value.entries }
    return result.error.code === 'workspace-file/not-found' ? { kind: 'missing' } : { kind: 'failed' }
  }

  /**
   * Read one run's metadata for the timestamp that orders it against the others.
   * @param run - the discovered run.
   * @param cwd - the workspace root.
   * @param signal - caller cancellation.
   * @returns the run with its recorded timestamp, or unchanged when it records none.
   */
  private async withRecency(run: AuditRunRef, cwd: string, signal: AbortSignal): Promise<AuditRunRef> {
    const result = await this.deps.read(inWorkspace(cwd, `${run.directory}/${RUN_METADATA_FILE}`), signal)
    if (!result.ok || !result.value.eof) return run
    const metadata = parseMetadata(result.value.text)
    return metadata === undefined ? run : { ...run, recordedAt: metadata.recordedAt }
  }

  /** Read the selected run's shared files and follow its directory. */
  private async readSelected(): Promise<void> {
    const generation = ++this.readGeneration
    this.runRead?.abort()
    const abort = new AbortController()
    this.runRead = abort
    const cwd = this.deps.cwd()
    const directory = this.selected
    if (cwd === undefined || directory === undefined) return
    if (directory !== this.loadedDirectory) {
      this.loadedDirectory = directory
      this.clearRun()
    }
    this.busy = true
    this.publish()
    const [metadata, coverage, candidates, findings, report, detail, needsValidation, control] = await Promise.all([
      this.readParsed(inWorkspace(cwd, `${directory}/${RUN_METADATA_FILE}`), abort.signal, parseMetadata),
      this.readParsed(inWorkspace(cwd, `${directory}/${COVERAGE_LEDGER_FILE}`), abort.signal, parseCoverage),
      this.readParsed(inWorkspace(cwd, `${directory}/${CANDIDATES_FILE}`), abort.signal, parseCandidates),
      this.readParsed(inWorkspace(cwd, `${directory}/${FINDINGS_FILE}`), abort.signal, parseFindings),
      this.readDocument(inWorkspace(cwd, `${directory}/${REPORT_FILE}`), abort.signal),
      this.readDocument(inWorkspace(cwd, `${directory}/${FINDINGS_DETAIL_FILE}`), abort.signal),
      this.readDocument(inWorkspace(cwd, `${directory}/${NEEDS_VALIDATION_FILE}`), abort.signal),
      this.readParsed(inWorkspace(cwd, `${directory}/${CONTROL_FILE}`), abort.signal, parseControl),
    ])
    if (this.disposed || generation !== this.readGeneration) return
    const problems: AuditProblem[] = this.problems.filter(problem => problem.kind !== 'file')
    if (metadata.kind === 'ok') this.lastGood.metadata = metadata.value
    if (coverage.kind === 'ok') this.lastGood.coverage = coverage.value
    if (candidates.kind === 'ok') this.lastGood.candidates = candidates.value
    if (findings.kind === 'ok') this.lastGood.findings = findings.value
    for (const [file, read] of [
      [RUN_METADATA_FILE, metadata],
      [COVERAGE_LEDGER_FILE, coverage],
      [CANDIDATES_FILE, candidates],
      [FINDINGS_FILE, findings],
      [REPORT_FILE, report],
      [FINDINGS_DETAIL_FILE, detail],
      [NEEDS_VALIDATION_FILE, needsValidation],
      [CONTROL_FILE, control],
    ] as const) {
      if (read.kind === 'invalid') problems.push({ kind: 'file', file, reason: read.reason })
    }
    this.metadata = metadata.kind === 'ok' ? metadata.value : this.lastGood.metadata
    this.coverage = coverage.kind === 'ok' ? coverage.value : this.lastGood.coverage
    this.candidates = candidates.kind === 'ok' ? candidates.value : this.lastGood.candidates
    this.findings = findings.kind === 'ok' ? findings.value : this.lastGood.findings
    if (report.kind === 'ok' || detail.kind === 'ok' || needsValidation.kind === 'ok') {
      this.lastGood.report = {
        report: report.kind === 'ok' ? report.value : this.lastGood.report?.report,
        detail: detail.kind === 'ok' ? detail.value : this.lastGood.report?.detail,
        needsValidation: needsValidation.kind === 'ok' ? needsValidation.value : this.lastGood.report?.needsValidation,
      }
    }
    if (control.kind === 'ok') this.lastGood.control = control.value
    this.report = this.lastGood.report
    this.control = control.kind === 'ok' ? control.value : this.lastGood.control
    this.problems = problems
    this.elapsedMs = elapsedOf(this.metadata, this.deps.now?.() ?? Date.now())
    this.noteDigest(this.deps.now?.() ?? Date.now())
    this.phase = 'ready'
    this.busy = false
    this.publish()
    this.watch(directory, false)
  }

  /**
   * Read one shared file and parse it.
   * @param path - its absolute path.
   * @param signal - caller cancellation.
   * @param parse - the file's parser.
   * @returns the parsed value, or why the read could not use the file.
   */
  private async readParsed<Value>(
    path: string, signal: AbortSignal, parse: (raw: string) => Value | undefined,
  ): Promise<ReadFile<Value>> {
    const result = await this.deps.read(path, signal)
    if (!result.ok) {
      return result.error.code === 'workspace-file/not-found'
        ? { kind: 'missing' }
        : { kind: 'invalid', reason: 'unreadable' }
    }
    if (!result.value.eof) return { kind: 'invalid', reason: 'truncated' }
    const value = parse(result.value.text)
    return value === undefined ? { kind: 'invalid', reason: 'malformed' } : { kind: 'ok', value }
  }

  /** Forget the selected run's values and their last good copies. */
  private clearRun(): void {
    delete this.lastGood.metadata
    delete this.lastGood.coverage
    delete this.lastGood.candidates
    delete this.lastGood.findings
    delete this.lastGood.report
    delete this.lastGood.control
    this.digests = []
    this.digestStage = undefined
    this.digestDone = 0
    this.resetRun()
  }

  /** Forget the selected run's shown values, keeping the last good copies for a retry. */
  private resetRun(): void {
    this.metadata = undefined
    this.coverage = undefined
    this.candidates = undefined
    this.findings = undefined
    this.report = undefined
    this.control = undefined
    this.elapsedMs = undefined
  }

  /**
   * Read one report document verbatim; a missing document is an empty one.
   * @param path - its absolute path.
   * @param signal - caller cancellation.
   * @returns the text, or why the read could not use the file.
   */
  private async readDocument(path: string, signal: AbortSignal): Promise<ReadFile<string | undefined>> {
    const result = await this.deps.read(path, signal)
    if (!result.ok) {
      return result.error.code === 'workspace-file/not-found'
        ? { kind: 'ok', value: undefined }
        : { kind: 'invalid', reason: 'unreadable' }
    }
    if (!result.value.eof) return { kind: 'invalid', reason: 'truncated' }
    return { kind: 'ok', value: result.value.text }
  }

  /**
   * Write a digest line when the phase moved or a few units settled. The first
   * read only seeds the comparison, so opening an old run writes nothing.
   * @param now - the current time.
   */
  private noteDigest(now: number): void {
    const stage = this.metadata?.stage ?? 'unknown'
    const done = (this.coverage?.covered ?? 0) + (this.coverage?.deferred ?? 0) + (this.coverage?.blocked ?? 0)
    if (this.digestStage === undefined) {
      this.digestStage = stage
      this.digestDone = done
      return
    }
    const moved = stage !== this.digestStage
    if (!moved && done - this.digestDone < UNITS_PER_DIGEST) return
    this.digestStage = stage
    this.digestDone = done
    const line: AuditDigest = {
      stage,
      status: this.metadata?.status ?? 'unknown',
      covered: this.coverage?.covered ?? 0,
      total: this.coverage?.total ?? 0,
      spend: this.metadata?.spend,
      budget: this.metadata?.budget,
      kind: moved ? 'stage' : 'units',
      at: now,
    }
    this.digests = [...this.digests, line].slice(-DIGEST_LIMIT)
  }

  /**
   * Follow one directory: every invalidation reads the run again, and a stream
   * that ends leaves a notice beside the manual Reload control.
   * @param directory - the workspace-relative directory to follow.
   * @param discovery - whether a change means the run list moved rather than one run's files.
   */
  private watch(directory: string, discovery: boolean): void {
    const cwd = this.deps.cwd()
    if (cwd === undefined) return
    const target = inWorkspace(cwd, directory)
    if (this.watched === target && this.watchHandle !== undefined && this.watchingParent === discovery) return
    this.stopWatch()
    this.watched = target
    this.watchingParent = discovery
    const abort = new AbortController()
    this.watchAbort = abort
    this.watchHandle = this.deps.watch(target, abort.signal)
    void this.pump(this.watchHandle, abort.signal, discovery)
  }

  /**
   * Read the watch frames and ask for a re-read after each burst.
   * @param handle - the watch generation.
   * @param signal - watch cancellation.
   * @param discovery - whether a change means the run list moved rather than one run's files.
   */
  private async pump(
    handle: RemoteStreamHandle<WorkspaceFileWatchFrame, never>, signal: AbortSignal, discovery: boolean,
  ): Promise<void> {
    try {
      for await (const frame of handle) {
        if (signal.aborted) return
        if (frame.kind === 'ready') continue
        this.scheduleRead(discovery)
      }
    } catch (error) {
      // A stream ends when its generation fails or is cancelled; a cancellation is ours.
      void error
      if (signal.aborted) return
      this.problems = [...this.problems.filter(problem => problem.kind !== 'watch'), { kind: 'watch' }]
      this.publish()
    }
  }

  /**
   * Coalesce one burst of watch frames into one read.
   * @param discovery - whether the burst means the run list moved rather than one run's files.
   */
  private scheduleRead(discovery: boolean): void {
    if (this.timer !== undefined) return
    this.timer = setTimeout(() => {
      this.timer = undefined
      void (discovery ? this.refresh() : this.readSelected())
    }, WATCH_DEBOUNCE_MS)
  }

  /** End the watch and any pending re-read. */
  private stopWatch(): void {
    if (this.timer !== undefined) {
      clearTimeout(this.timer)
      this.timer = undefined
    }
    this.watchAbort?.abort()
    this.watchAbort = undefined
    this.watchHandle?.dispose()
    this.watchHandle = undefined
    this.watched = undefined
    this.watchingParent = false
  }

  /** Advance the elapsed time while a run is in progress. */
  private startClock(): void {
    if (this.clock !== undefined) return
    this.clock = setInterval(() => {
      if (this.metadata?.status !== 'in_progress' || this.used === 0) return
      this.elapsedMs = elapsedOf(this.metadata, this.deps.now?.() ?? Date.now())
      this.publish()
    }, CLOCK_MS)
  }

  /** Stop advancing the elapsed time. */
  private stopClock(): void {
    if (this.clock === undefined) return
    clearInterval(this.clock)
    this.clock = undefined
  }

  /** Publish the internal fields as one snapshot. */
  private publish(): void {
    this.state.set({
      phase: this.phase,
      digests: this.digests,
      report: this.report,
      control: this.control,
      runs: this.runs,
      selected: this.selected,
      metadata: this.metadata,
      coverage: this.coverage,
      candidates: this.candidates,
      findings: this.findings,
      elapsedMs: this.elapsedMs,
      problems: this.problems,
      busy: this.busy,
    })
  }
}

/** One discovered run, exported for the switcher's props. */
export type { AuditRunRef, AuditCandidate }
