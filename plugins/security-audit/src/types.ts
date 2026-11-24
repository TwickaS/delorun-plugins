/**
 * The plugin's shared domain vocabulary: what an audit run is, what its coverage ledger and finding records hold, and
 * what its run files say. The shapes here are the interface between the run store, the audit tools, the delegation
 * layer and the studio surfaces, so a change to one of them changes what every other layer reads.
 *
 * The ledger vocabulary follows Cloudflare's security-audit skill exactly (RECONNAISSANCE.md, Deterministic coverage
 * ledger): a unit's semantic fields, its status table, its canonical references and its archived attempts keep the
 * skill's names, so the skill's own validators accept what the plugin writes.
 * @module @delorun/plugin-security-audit/types
 */
import type { SandboxEnforcement, SandboxMode, SandboxNetwork } from '@deepseek-ai/dsh-sandbox'

/**
 * The coverage profile: how finely units split, and how many waves run.
 *
 * `quick`, `standard` and `deep` are the skill's own profiles. `rc` is the release-candidate profile: it seeds the
 * ledger from the boundaries of Delorun's threat model and otherwise runs with `deep`'s settings.
 */
export type AuditProfile = 'quick' | 'standard' | 'deep' | 'rc'

/**
 * When the coordinator stops for a person's answer during an unattended run.
 * - `straight_through`: no check-ins; the run reports when it is done.
 * - `after_recon`: one check-in after reconnaissance, before hunting.
 * - `every_stage`: a check-in at the end of each stage.
 */
export type CheckIn = 'straight_through' | 'after_recon' | 'every_stage'

/** The run's lifecycle stage, in the order the skill's phases run. */
export type RunStage = 'reconnaissance' | 'hunting' | 'validation' | 'final_verification' | 'reporting' | 'done'

/**
 * Whether a run claims complete coverage.
 * - `in_progress`: the run is still working.
 * - `complete`: both validators pass, every unit is terminal, and every reported record is independently verified.
 * - `incomplete`: the run stopped early; `incomplete_reason` names the exact reason the skill gives.
 */
export type RunStatus = 'in_progress' | 'complete' | 'incomplete'

/**
 * Which list seeds the coverage ledger.
 * - `reconnaissance`: the general mode, where reconnaissance derives the units as the skill specifies.
 * - `rc`: the Delorun release-candidate seed list taken from the threat model's boundaries, so an audit of a release
 *   candidate is complete by construction against what Delorun claims.
 */
export type CoverageSeed = 'reconnaissance' | 'rc'

/** An audit role; `orchestrator` is the chat itself and the others are delegated agents. */
export type AgentRole = 'orchestrator' | 'recon' | 'hunter' | 'verifier' | 'critic'

/** What one delegated brief asks its agent to do, or what the record says it did. */
export type BriefKind = 'recon' | 'hunt' | 'verify' | 'final-verify' | 'critique' | 'final-critique'

/** The model route an agent ran on; `null` leaves the field to the agent's own adapter. */
export interface ModelRoute {
  /** The model provider's id. */
  readonly provider: string | null
  /** The model's id. */
  readonly model: string | null
  /** The reasoning effort the provider was asked for. */
  readonly reasoning_effort: string | null
}

/** The model route each role runs on, each overriding the chat's own model. */
export type RoleModels = Partial<Record<Exclude<AgentRole, 'orchestrator'>, ModelRoute>>

/** The reviewed source revision, including a dirty working tree. */
export interface SourceRef {
  /** The commit the audit read, or `null` when the source is not a checkout. */
  readonly commit: string | null
  /** Whether the working tree held changes the audit read but could not name by commit. */
  readonly dirty: boolean
  /** Whether the audit could see a working tree at all; a source-only target may not have one. */
  readonly dirty_known: boolean
  /** When the plugin read the revision, as an ISO 8601 UTC timestamp. */
  readonly captured_at: string
}

/**
 * A coverage unit's status. The skill's state table binds each status to its owner and its evidence:
 *
 * | Status | Unit `agent_id` | `reviewed_paths` / `local_checks` | `result_fingerprints` | `unresolved` |
 * |---|---|---|---|---|
 * | `planned` | null | empty | empty | empty |
 * | `not_applicable`, `out_of_scope`, `deferred` | null | empty | empty | nonempty reason |
 * | `in_progress` | canonical owner | empty | empty | empty |
 * | `blocked` | canonical owner | both nonempty, owned partial evidence | empty | nonempty blocker |
 * | `covered` | canonical owner | both nonempty | empty | empty |
 * | `candidate` | canonical owner | both nonempty | nonempty | optional |
 *
 * A unit with evidence is archived into `attempts` before a coverage critic reopens it, and the next assignment
 * increments `wave` and starts from empty evidence.
 */
export type UnitStatus = 'planned' | 'in_progress' | 'covered' | 'candidate' | 'blocked' | 'deferred' | 'out_of_scope' | 'not_applicable'

/**
 * Why a unit exists in this run, as the skill names the prior-run states. `none` marks a unit seeded when no
 * compatible prior ledger was available; `new` marks a surface first seen while a compatible prior ledger exists.
 */
export type PriorStatus =
  | 'new'
  | 'prior_confirmed_same_source'
  | 'prior_confirmed_changed_source'
  | 'prior_needs_validation'
  | 'prior_deferred'
  | 'prior_blocked'
  | 'prior_out_of_scope'
  | 'prior_covered_same_source'
  | 'prior_covered_changed_source'
  | 'prior_rejected_claim_changed'
  | 'none'

/** How a unit's check reached its result: reading source, or running something locally. */
export type CheckMethod = 'source' | 'local'

/** One check a unit records; a unit's `reviewed_paths` is exactly the union of its checks' paths. */
export interface LedgerCheck {
  /** The canonical agent id that made the check. */
  readonly agent_id: string
  /** Repository-relative paths the check read. */
  readonly reviewed_paths: readonly string[]
  /** The invariant the check establishes. */
  readonly invariant: string
  /** Whether the check read source or ran locally. */
  readonly method: CheckMethod
  /** What the check found. */
  readonly result: string
  /** A run-relative path under `agents/<agent_id>/artifacts/` for a local check, or `null` for a source-only one. */
  readonly artifact: string | null
}

/** A unit's canonical, source-derived references: the same source object keeps the same reference across runs. */
export interface CanonicalRefs {
  /** The entry surface, such as a repository-relative path plus the exported scope or route it defines. */
  readonly surface: string
  /** The source control that defines the trust boundary. */
  readonly boundary: string
  /** The subsystem, such as a package path. */
  readonly subsystem: string
  /** The exact attack-class block reference, `FILE.md#` plus the class name as that file writes it. */
  readonly attack_class: string
  /** The lifecycle mode, when the profile makes one material. */
  readonly lifecycle?: string
}

/** One block a unit considered and left out, with the source fact that excludes it. */
export interface ExcludedBlock {
  /** The block reference, `FILE.md#` plus the heading text before any parenthetical qualifier. */
  readonly block: string
  /** The source fact that excludes it. */
  readonly reason: string
}

/** One coverage unit, as `coverage-ledger.json` stores it. */
export interface LedgerUnit {
  /** The canonical id the skill derives from the references; percent-encoded, never a lossy slug. */
  readonly coverage_id: string
  /** The unit's canonical references. */
  readonly canonical_refs: CanonicalRefs
  /** The entry surface, as a person reads it. */
  readonly surface: string
  /** The trust boundary, as a person reads it. */
  readonly boundary: string
  /** The subsystem, as a person reads it. */
  readonly subsystem: string
  /** The attack class, as a person reads it. */
  readonly attack_class: string
  /** The lifecycle mode, when the profile makes one material. */
  readonly lifecycle?: string
  /** Repository-relative paths a hunter starts from. */
  readonly starting_paths: readonly string[]
  /** The ordinary attack-class block the unit assigns, or `null` when none applies. */
  readonly ordinary_attack_class_block: string | null
  /** The companion blocks the unit selects, each its class plus the discipline blocks it cites. */
  readonly selected_companion_blocks: readonly string[]
  /** Every block considered and not selected. */
  readonly excluded_blocks: readonly ExcludedBlock[]
  /** The prior-run state this unit descends from. */
  readonly prior_status: PriorStatus
  /** Evidence-bearing attempts a coverage critic archived, append-only. */
  readonly attempts: readonly Record<string, unknown>[]
  /** The coverage wave this unit's live state belongs to. */
  readonly wave: number
  /** The unit's live status. */
  readonly status: UnitStatus
  /** The assignment owner's canonical agent id, or `null` when nobody owns the unit. */
  readonly agent_id: string | null
  /** The union of the live checks' reviewed paths. */
  readonly reviewed_paths: readonly string[]
  /** The live checks. */
  readonly local_checks: readonly LedgerCheck[]
  /** The candidate fingerprints a `candidate` unit links. */
  readonly result_fingerprints: readonly string[]
  /** What the unit could not settle, or the reason it is closed without an assignment. */
  readonly unresolved: readonly string[]
  /** A hunter's hardening notes, kept as bookkeeping. */
  readonly harness_hardening?: readonly string[]
  /** Bookkeeping: the verifier's latest decision for a linked candidate. */
  readonly harness_decision?: string
}

/** The fields a caller gives to seed a unit; the live state starts `planned` and empty. */
export interface UnitSeed {
  /** The unit's canonical references. */
  readonly canonical_refs: CanonicalRefs
  /** The entry surface, as a person reads it. */
  readonly surface: string
  /** The trust boundary, as a person reads it. */
  readonly boundary: string
  /** The subsystem, as a person reads it. */
  readonly subsystem: string
  /** The attack class, as a person reads it. */
  readonly attack_class: string
  /** The lifecycle mode, when the profile makes one material. */
  readonly lifecycle?: string
  /** Repository-relative paths a hunter starts from. */
  readonly starting_paths: readonly string[]
  /** The ordinary attack-class block the unit assigns, or `null` when none applies. */
  readonly ordinary_attack_class_block: string | null
  /** The companion blocks the unit selects. */
  readonly selected_companion_blocks: readonly string[]
  /** Every block considered and not selected. */
  readonly excluded_blocks: readonly ExcludedBlock[]
  /** The prior-run state this unit descends from; `none` when no compatible prior ledger exists. */
  readonly prior_status?: PriorStatus
}

/** A hunter's result for one unit it owned. */
export interface HunterUnitResult {
  /** The unit the hunter worked. */
  readonly coverage_id: string
  /** What the hunter could establish. */
  readonly disposition: 'covered' | 'candidate' | 'blocked'
  /** Repository-relative paths the hunter read. */
  readonly reviewed_paths: readonly string[]
  /** The checks the hunter made. */
  readonly checks: readonly LedgerCheck[]
  /** The candidate fingerprints a `candidate` disposition links. */
  readonly candidate_fingerprints: readonly string[]
  /** What the hunter could not settle. */
  readonly unresolved: readonly string[]
}

/** How many units hold each status. */
export type StatusCounts = Record<UnitStatus, number>

/** A severity score, in the order the report schema lists them. */
export type SeverityScore = 'informational' | 'low' | 'medium' | 'high' | 'critical'

/** One scored factor of a confirmed finding's severity, with the reason it scores as it does. */
export interface ScoredFactor {
  /** The score. */
  readonly score: SeverityScore
  /** Why the factor scores as it does. */
  readonly reason: string
}

/** A confirmed finding's severity, as `report-schema.json` requires it. */
export interface Severity {
  /** How likely the flaw is to be met in ordinary use. */
  readonly likelihood: ScoredFactor
  /** What meeting it costs. */
  readonly impact: ScoredFactor
  /** The overall score the report leads with, at least as high as either factor. */
  readonly overall_severity: ScoredFactor
}

/** A confirmed finding's confidence that the flaw is real. */
export interface Confidence {
  /** The score. */
  readonly score: 'low' | 'medium' | 'high'
  /** Why it scores as it does. */
  readonly reason: string
}

/** One step of a confirmed finding's trace, from the entry point to the sink. */
export interface TraceEntry {
  /** Where the step sits in the trace. */
  readonly kind: 'entrypoint' | 'propagation' | 'sink'
  /** Repository-relative file. */
  readonly file: string
  /** 1-based line number. */
  readonly line: number
  /** The function, block or scope the line sits in. */
  readonly scope: string
  /** What this step establishes. */
  readonly description: string
}

/** A citation supporting a record. */
export interface EvidenceCitation {
  /** Repository-relative file. */
  readonly file: string
  /** 1-based line number. */
  readonly line: number
  /** What the cited code establishes. */
  readonly description: string
}

/** The kind of precondition a confirmed finding depends on. */
export type ConditionKind =
  | 'authentication_level'
  | 'authorization_role'
  | 'user_interaction'
  | 'system_configuration'
  | 'network_routing'
  | 'environmental_dependency'
  | 'data_state'
  | 'timing_dependency'
  | 'third_party_dependency'

/** One precondition a confirmed finding depends on. */
export interface FindingCondition {
  /** The kind of precondition. */
  readonly kind: ConditionKind
  /** The precondition, in the target's own terms. */
  readonly description: string
}

/** A confirmed finding's reproduction in the target's native interface. */
export interface Reproduction {
  /** The step from the attacker's perspective. */
  readonly attacker_perspective: string
  /** The inputs that reach the flaw. */
  readonly payloads: readonly string[]
  /** The instructions that reproduce it. */
  readonly instructions: readonly string[]
  /** What the auditor observed, bounded as the skill requires. */
  readonly observed_result: string
}

/** A confirmed finding's remediation. */
export interface Remediation {
  /** What to change. */
  readonly strategy: string
  /** The files to change and their fixed code, when the auditor wrote it. */
  readonly code_changes?: readonly { readonly file_name: string; readonly fixed_code: string }[]
}

/** What a `needs_validation` record names as the check that would settle it. */
export interface ValidationPlan {
  /** A check the person can run on their machine. */
  readonly local?: string
  /** A check only the deployment can answer. */
  readonly deployment?: string
}

/** The fields every finding record carries, whatever its verdict. */
export interface FindingCommon {
  /** The stable source-derived identifier, which does not change between validation states. */
  readonly fingerprint: string
  /** The finding's title, as a person reads it. */
  readonly title: string
  /** What the flaw is. */
  readonly description: string
  /** The trace from the entry point to the sink. */
  readonly trace: readonly TraceEntry[]
  /** The citations that support the record. */
  readonly evidence: readonly EvidenceCitation[]
}

/** A finding the verifier confirmed: the complete trace, the bounded observed result, and the severity. */
export interface ConfirmedFinding extends FindingCommon {
  /** The verdict. */
  readonly verdict: 'confirmed'
  /** The root cause the source establishes. */
  readonly root_cause: string
  /** What the code intended instead. */
  readonly intended_behavior: string
  /** The preconditions the flaw depends on. */
  readonly conditions: readonly FindingCondition[]
  /** The reproduction. */
  readonly execution: Reproduction
  /** The remediation. */
  readonly remediation: Remediation
  /** The severity the report leads with. */
  readonly severity: Severity
  /** The confidence that the flaw is real. */
  readonly confidence: Confidence
}

/** A finding that needs a check the audit could not make from inside its confinement. */
export interface NeedsValidationFinding extends FindingCommon {
  /** The verdict. */
  readonly verdict: 'needs_validation'
  /** The claimed root cause, which the missing check would confirm. */
  readonly claimed_root_cause: string
  /** The exact missing capability, each entry naming what the audit could not do. */
  readonly blockers: readonly string[]
  /** The check that would settle it. */
  readonly validation_plan: ValidationPlan
}

/** A finding the verifier refuted, retained so a later run can see the claim was tested. */
export interface RejectedFinding extends FindingCommon {
  /** The verdict. */
  readonly verdict: 'rejected'
  /** The claimed root cause the verifier disproved. */
  readonly claimed_root_cause: string
  /** Why the claim does not hold. */
  readonly reason: string
}

/**
 * One record of `findings.json`, in any of the skill's three verdicts. A stored record is read as
 * `Record<string, unknown>` and narrowed on `verdict`, because the skill's own validator is the authority on its
 * fields; these types state what that validator accepts.
 */
export type FindingRecord = ConfirmedFinding | NeedsValidationFinding | RejectedFinding

/** The verdicts `findings.json` distinguishes. */
export type FindingVerdict = FindingRecord['verdict']

/** One independent verification of a candidate. */
export interface CandidateVerification {
  /** The verifier's canonical agent id. */
  readonly agent_id: string
  /** What the verifier decided. */
  readonly decision: FindingVerdict
  /** The record the verifier settled on. */
  readonly record: Record<string, unknown>
  /** The checks the verifier made. */
  readonly checks: readonly LedgerCheck[]
  /** When the verifier recorded its decision, as an ISO 8601 UTC timestamp. */
  readonly at: string
}

/** One candidate and its independent verification history, as `candidates.json` stores it. */
export interface CandidateEntry {
  /** The record's stable fingerprint. */
  readonly fingerprint: string
  /** The candidate's current standing. */
  status: 'proposed' | 'confirmed' | 'needs_validation' | 'rejected'
  /** The candidate's record, in the shape of one `findings.json` branch. */
  record: Record<string, unknown>
  /** The hunter's canonical agent id. */
  readonly proposed_by: string
  /** When it was proposed, as an ISO 8601 UTC timestamp. */
  readonly proposed_at: string
  /** The coverage ids that link this fingerprint. */
  proposed_units: string[]
  /** Every independent verification of it, in order. */
  readonly verifications: readonly CandidateVerification[]
  /** Whether a Phase 5 record verifier accepted it. */
  final_verified: boolean
  /** The record verifier's canonical agent id. */
  final_by: string | null
  /** When the record verifier accepted it, as an ISO 8601 UTC timestamp. */
  final_at: string | null
  /** A Phase 5 replacement awaiting its own independent verifier. */
  pending_record?: Record<string, unknown> | undefined
  /** A coordinator note about a duplicate or a non-material correction. */
  note?: string | undefined
}

/**
 * A role's working copy: the reviewed tree extracted from the target's Git repository, which the role may edit and
 * build in. It lives at `<run>/agents/<id>/work/`, is the role's cwd, and is removed when the role finishes.
 */
export interface WorkCopy {
  /** The copy's run-relative path, `agents/<id>/work`. */
  readonly path: string
  /** The Git revision the copy holds. */
  readonly revision: string | null
  /** Whether the copy is the reviewed tree: false when the working tree was dirty at intake and the copy is HEAD alone. */
  readonly reviewed: boolean
  /** Its bytes. */
  readonly bytes: number
  /** How many files it holds. */
  readonly files: number
  /** How many seconds it took to make, to one decimal place. */
  readonly seconds: number
  /** When it was created, as an ISO 8601 UTC timestamp. */
  readonly created_at: string
  /** When it was removed, or null while it is live. */
  removed_at: string | null
}

/** One nested harness a role started from its working copy, and how it ended. */
export interface NestedStart {
  /** The agent id of the role that started it. */
  readonly agent_id: string
  /** The port it listens on, from 19988 to 19997. */
  readonly port: number
  /** The scratch HOME it runs with, run-relative. */
  readonly home: string
  /** Its process id, or null when it never started. */
  readonly pid: number | null
  /** When it started, as an ISO 8601 UTC timestamp. */
  readonly started_at: string
  /** When it stopped, or null while it runs. */
  stopped_at: string | null
  /** Its exit once stopped, or null while it runs or when it never started. */
  readonly exit: { readonly code: number | null; readonly signal: string | null } | null
}

/** The nested harness starts a run has made, with the cap that bounds them. */
export interface NestedHarness {
  /** How many starts the run allows. */
  readonly cap: number
  /** Every start, in order. */
  readonly starts: readonly NestedStart[]
}

/** One delegated agent of a run, as the run state records it. */
export interface AgentEntry {
  /** The role it plays. */
  readonly role: Exclude<AgentRole, 'orchestrator'>
  /** What its brief asks it to do. */
  readonly kind: BriefKind
  /** Run-relative path of the brief it was given. */
  readonly brief: string
  /** Coverage ids, fingerprints or the recon item this agent owns. */
  readonly assigned: readonly string[]
  /** When it was briefed, as an ISO 8601 UTC timestamp. */
  readonly created_at: string
  /** How far it has got. */
  status: 'briefed' | 'claimed' | 'recorded' | 'failed'
  /** The child session that claimed the brief. */
  claimed_by?: string
  /** When the child claimed it, as an ISO 8601 UTC timestamp. */
  claimed_at?: string
  /** The model route it ran on. */
  model?: ModelRoute
  /** Run-relative path of its recorded result. */
  result?: string
  /** When its result was recorded, as an ISO 8601 UTC timestamp. */
  recorded_at?: string
  /** How many results the validation gate refused before one passed. */
  refused_results: number
  /** The commands it ran: how many, and for how many seconds. */
  exec: { runs: number; seconds: number }
  /** Run-relative paths of the artifacts promoted for it. */
  promoted: string[]
  /** The coverage wave its assignment belongs to. */
  wave: number
  /** The role's working copy, from the moment it is reserved until the run is read. */
  work?: WorkCopy
}

/**
 * The confinement facts the run records rather than rebuilds: the file-effect mode and the network every role's
 * scratch cwd runs under, the home the confinement hides, and how completely the backend enforces it. A run whose
 * network is not `off` has not been started, because the audit must reach no network at all.
 */
export interface RunExecution {
  /** The file-effect mode the roles' cwds run under. */
  readonly sandbox_mode: SandboxMode
  /** The network the resolved policy carries for those cwds; the audit needs `off`. */
  readonly network: SandboxNetwork['mode']
  /** When the plugin last resolved that policy and checked the network, as an ISO 8601 UTC timestamp. */
  readonly network_checked_at: string
  /** The home directory the confinement hides from the roles, or `null` when it reports none. */
  readonly protected_home: string | null
  /** How completely the backend enforces the policy, or `null` when it reports nothing. */
  readonly enforcement: SandboxEnforcement | null
}

/** The run's own bookkeeping, as the audit tools keep it; `RunMetadata` is its reportable subset. */
export interface HarnessState {
  /** The state's format version. */
  readonly version: 1
  /** The run id, `run-N`. */
  readonly run_id: string
  /** The coordinating session's id. */
  readonly orchestrator_session: string
  /** When the run was created, as an ISO 8601 UTC timestamp. */
  readonly created_at: string
  /** The workspace directory the audit targets, absolute. */
  readonly target: string
  /** The repository's name, as the report names it. */
  readonly repo_name: string
  /** The revision the audit read. */
  source_ref: SourceRef
  /** The coverage profile. */
  profile: AuditProfile
  /** Which list seeded the ledger. */
  seed?: CoverageSeed
  /** The paths the run scoped itself to; empty for the whole target. */
  scope_paths: string[]
  /** When the coordinator interrupts the run for a person's answer. */
  check_in: CheckIn
  /** The coordinator's intake note, when one was given. */
  intake_note: string | null
  /** Repository-relative files or directories of audit inputs the person named at intake. */
  inputs?: string[]
  /** The confinement facts the run was started under. */
  execution: RunExecution
  /** The execution contract the skill requires the run to state. */
  readonly execution_policy: 'sandboxed-source-and-local-only'
  /** The model route the chat itself runs on. */
  orchestrator_model: ModelRoute
  /** Per-role model routes chosen for this run. */
  models?: RoleModels
  /** The maximum number of agent invocations, or `null` for no limit. */
  budget: number | null
  /** Agents started so far, counted at start; the skill's budget unit. */
  invocations: number
  /** The next sequence number of each agent id prefix. */
  next_seq: Record<string, number>
  /** Every delegated agent of the run, by canonical agent id. */
  agents: Record<string, AgentEntry>
  /** The coverage wave the run's live ledger work belongs to. */
  wave: number
  /** The stage the run is in. */
  stage: RunStage
  /** Whether the run claims complete coverage. */
  run_status: RunStatus
  /** Why the run is incomplete, when it is. */
  incomplete_reason: string | null
  /** The prior runs the coordinator was shown at intake. */
  prior_runs: string[]
  /** What a copy of the target measured the last time this run made one. */
  copy_measurement?: { readonly bytes: number; readonly files: number }
  /** The nested harness starts this run made, with its cap. */
  nested_harness?: NestedHarness
}

/** How many candidates hold each standing, as `run-metadata.json` reports it. */
export interface CandidateCounts {
  /** Every candidate proposed. */
  readonly total: number
  /** Candidates no verifier has decided yet. */
  readonly proposed: number
  /** Candidates a verifier confirmed. */
  readonly confirmed: number
  /** Candidates whose check the audit could not make. */
  readonly needs_validation: number
  /** Candidates a verifier refuted. */
  readonly rejected: number
  /** Candidates a Phase 5 record verifier accepted. */
  readonly final_verified: number
}

/** One run, as `run-metadata.json` reports it: the setup, the state and the cost, without the ledger's bulk. */
export interface RunMetadata {
  /** The run id, `run-N`. */
  readonly run_id: string
  /** The repository's name. */
  readonly repo: string
  /** The workspace directory the audit targets, absolute. */
  readonly target: string
  /** The revision the audit read. */
  readonly source_ref: SourceRef
  /** The coverage profile. */
  readonly profile: AuditProfile
  /** Which list seeded the ledger. */
  readonly seed?: CoverageSeed
  /** The paths the run scoped itself to. */
  readonly scope_paths: readonly string[]
  /** The maximum number of agent invocations, or `null` for no limit. */
  readonly budget: number | null
  /** The execution contract the skill requires the run to state. */
  readonly execution_policy: 'sandboxed-source-and-local-only'
  /** When the coordinator interrupts the run for a person's answer. */
  readonly check_in: CheckIn
  /** The coordinator's intake note, when one was given. */
  readonly intake_note: string | null
  /** Repository-relative files or directories of audit inputs the person named. */
  readonly inputs: readonly string[]
  /** Whether the run claims complete coverage. */
  readonly run_status: RunStatus
  /** Why the run is incomplete, when it is. */
  readonly incomplete_reason: string | null
  /** The stage the run is in. */
  readonly stage: RunStage
  /** When the run was created, as an ISO 8601 UTC timestamp. */
  readonly created_at: string
  /** When the file was last written, as an ISO 8601 UTC timestamp; the pane's liveness signal. */
  readonly updated_at: string
  /** When the run stopped working, as an ISO 8601 UTC timestamp, or `null` while it runs. */
  readonly completed_at: string | null
  /** The coordinating session's id. */
  readonly orchestrator_session: string
  /** The model route the chat itself runs on. */
  readonly orchestrator_model: ModelRoute
  /** The model route each agent ran on, by canonical agent id. */
  readonly agent_models: Record<string, { readonly role: Exclude<AgentRole, 'orchestrator'>; readonly kind: BriefKind; readonly model: ModelRoute | null }>
  /** How many agents the run started, and against what limit. */
  readonly agents: { readonly total: number; readonly invocations: number; readonly budget: number | null }
  /** The confinement facts the run was started under. */
  readonly execution: RunExecution
  /** Every role's working copy, by canonical agent id, as it was made; a removed copy keeps its measurement. */
  readonly work_copies: Readonly<Record<string, WorkCopy>>
  /** What a copy of the target measured the last time the run made one, or `null` before the first copy. */
  readonly copy_measurement: { readonly bytes: number; readonly files: number } | null
  /** The nested harness starts the run made, with its cap. */
  readonly nested_harness: NestedHarness
  /** The companion skill files the ledger selected. */
  readonly selected_companion_files: readonly string[]
  /** The prior runs the coordinator was shown at intake. */
  readonly prior_runs: readonly string[]
  /** Who writes each shared run file; always the coordinator. */
  readonly shared_file_owners: Readonly<Record<string, 'coordinator'>>
  /** How many candidates hold each standing. */
  readonly candidates: CandidateCounts
}

/** A run's location: the target it audits, its id, and its directory. */
export interface RunLocation {
  /** The workspace directory the audit targets, absolute. */
  readonly target: string
  /** The run id, `run-N`. */
  readonly runId: string
  /** The run directory, absolute. */
  readonly dir: string
}

/** The seven files the coordinator writes that the audit's report is built from. */
export type SharedRunFile =
  | 'run-metadata.json'
  | 'architecture.md'
  | 'coverage-ledger.json'
  | 'findings.json'
  | 'REPORT.md'
  | 'FINDINGS-DETAIL.md'
  | 'NEEDS-VALIDATION.md'

/** Every file at the run root the coordinator writes: the shared files and its own bookkeeping. */
export type CoordinatorRunFile = SharedRunFile | 'candidates.json'

/** The report documents a complete run writes. */
export type ReportDocument = 'REPORT' | 'FINDINGS_DETAIL' | 'NEEDS_VALIDATION'

/** The intake a person settles before the run starts; the composer strip writes it and `audit_init` checks it. */
export interface AuditIntake {
  /** The workspace directory to audit. */
  readonly target: string
  /** The repository's name, as the report names it. */
  readonly repo_name: string
  /** The coverage profile. */
  readonly profile: AuditProfile
  /** Which list seeds the ledger. */
  readonly seed: CoverageSeed
  /** Repository-relative paths to audit; empty for the whole target. */
  readonly scope_paths: readonly string[]
  /** The maximum number of agent invocations, or `null` for no limit. */
  readonly budget: number | null
  /** When the coordinator interrupts the run for a person's answer. */
  readonly check_in: CheckIn
  /** Per-role model routes, each overriding the chat's own model. */
  readonly models: RoleModels
  /** The coordinator's intake note, when one was given. */
  readonly intake_note: string | null
  /** Repository-relative files or directories of audit inputs the person named. */
  readonly inputs: readonly string[]
}
