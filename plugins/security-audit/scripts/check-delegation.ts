/**
 * The delegation lane's acceptance check: no model, no key, no network. It builds
 * a throwaway Git workspace holding one fixture run with a two-unit ledger,
 * registers the real delegation and nested-harness tools, starts the four
 * reconnaissance roles, one hunter, a post-wave critic and the final-clean critic
 * through a scripted subagent provider, and asserts what reached the run store:
 * every role's working copy, the disk and live-copy gates, the bounded nested
 * starts and their exits.
 *
 * Run: cd ~/delorun/code && node --import tsx/esm \
 *        ../plugins/plugins/security-audit/scripts/check-delegation.ts
 * @module delorun-plugin-security-audit/scripts/check-delegation
 */
import { execFileSync } from 'node:child_process'
import { chmodSync, existsSync, lstatSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, statSync, symlinkSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { basename, dirname, join } from 'node:path'
import type { Context } from '@deepseek-ai/cordis'
import { isCanonicalAgentId, promoteArtifacts, registerDelegationTool } from '../src/delegate.ts'
import { proposeBudget, reconnaissanceGate, validationGate, waveGate } from '../src/budget.ts'
import { seedUnits } from '../src/ledger.ts'
import { blockNames } from '../src/skill.ts'
import { criticBrief, hunterBrief, verifierBrief } from '../src/prompts/index.ts'
import { bytesText, copyGateProblem, DISK_FLOOR_BYTES, MAX_LIVE_COPIES, NESTED_HARNESS_CAP, NESTED_PORT_RANGE } from '../src/scripts-copy.ts'
import { rememberClaim, rememberCoordinatorRun } from '../src/store.ts'
import type { HarnessState, LedgerUnit, RunMetadata } from '../src/types.ts'

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

/** The path-entry type the run store's file accessor reads. */
function typeOf(path: string): string {
  const entry = lstatSync(path)
  if (entry.isSymbolicLink()) return 'symlink'
  if (entry.isDirectory()) return 'directory'
  if (entry.isFile()) return 'file'
  return 'other'
}

/** A file accessor over the host's own filesystem, as `ctx.fs` presents it. */
const fsService = {
  sandboxMode: 'workspace-write',
  async lstat(path: string): Promise<{ type: string } | undefined> {
    return existsSync(path) ? { type: typeOf(path) } : undefined;
  },
  async resolve(path: string): Promise<string> { return path },
  async stat(path: string): Promise<{ type: string; size: number } | undefined> {
    if (!existsSync(path)) return undefined;
    const info = statSync(path);
    return { type: info.isDirectory() ? 'directory' : 'file', size: info.size };
  },
  async readText(path: string): Promise<string> { return readFileSync(path, 'utf8') },
  async writeText(path: string, content: string, options?: { kind?: string }): Promise<void> {
    mkdirSync(dirname(path), { recursive: true });
    if (options?.kind === 'createIfAbsent' && existsSync(path)) throw new Error(path + ' already exists');
    writeFileSync(path, content);
  },
  async listDir(path: string): Promise<{ name: string; type: string }[]> {
    return readdirSync(path).map(name => ({ name, type: typeOf(join(path, name)) }));
  },
}

/** The session id the fixture run names. */
const SESSION = 'session-1'

/** What the fixture run holds. */
interface Fixture {
  /** The workspace the audit targets. */
  readonly workspace: string;
  /** The run directory. */
  readonly run: string;
  /** The seeded ledger. */
  readonly ledger: LedgerUnit[];
  /** The commit the fixture repository holds. */
  readonly commit: string;
}

/**
 * Commit a file into the fixture repository.
 * @param workspace - the repository directory.
 * @param message - the commit message.
 * @returns the commit's hash.
 */
function commit(workspace: string, message: string): string {
  const git = (args: string[]): string => execFileSync('git', ['-C', workspace, '-c', 'user.name=fixture', '-c', 'user.email=fixture@example.com', ...args], { encoding: 'utf8' })
  git(['add', '-A'])
  git(['commit', '-qm', message])
  return git(['rev-parse', 'HEAD']).trim()
}

/**
 * Build the fixture workspace and run.
 * @returns the workspace, the run directory, the ledger it seeded and its commit.
 */
function buildRun(): Fixture {
  const root = mkdtempSync(join(tmpdir(), 'sa-delegation-'));
  const workspace = join(root, 'repo');
  mkdirSync(join(workspace, 'src'), { recursive: true });
  writeFileSync(join(workspace, '.gitignore'), '.security-audit/\n');
  writeFileSync(join(workspace, 'src/app.ts'), 'export function handler(input: string): string {\n  return input.trim()\n}\n');
  execFileSync('git', ['-C', workspace, 'init', '-q'])
  const head = commit(workspace, 'fixture');
  const run = join(workspace, '.security-audit', 'run-1');
  mkdirSync(join(run, 'harness', 'recon'), { recursive: true });
  const names = blockNames('ATTACK-CLASSES.md');
  const classBlock = names.find(name => name.toLowerCase().includes('access')) ?? names[0] ?? 'Injection'
  const block = 'ATTACK-CLASSES.md#' + classBlock;
  const seed = (surface: string) => ({
    canonical_refs: { surface, boundary: 'src/app.ts#handler', subsystem: 'src', attack_class: block },
    surface, boundary: 'src/app.ts#handler', subsystem: 'src', attack_class: block,
    starting_paths: ['src/app.ts'], ordinary_attack_class_block: block, selected_companion_blocks: [], excluded_blocks: [],
  });
  const ledger = seedUnits([], [seed('src/app.ts#handler'), seed('src/app.ts#handler input')]).ledger;
  writeFileSync(join(run, 'coverage-ledger.json'), JSON.stringify(ledger, undefined, 2) + '\n');
  writeFileSync(join(run, 'candidates.json'), '[]\n');
  const state: HarnessState = {
    version: 1,
    run_id: 'run-1',
    orchestrator_session: SESSION,
    created_at: new Date().toISOString(),
    target: workspace,
    repo_name: 'fixture',
    source_ref: { commit: head, dirty: false, dirty_known: true, captured_at: new Date().toISOString() },
    profile: 'standard',
    seed: 'reconnaissance',
    scope_paths: [],
    check_in: 'after_recon',
    intake_note: null,
    execution: { sandbox_mode: 'workspace-write', network: 'off', network_checked_at: new Date().toISOString(), protected_home: '/home/fixture/.delorun', enforcement: 'full' },
    execution_policy: 'sandboxed-source-and-local-only',
    orchestrator_model: { provider: 'test', model: 'test-model', reasoning_effort: 'low' },
    budget: 40,
    invocations: 0,
    next_seq: {},
    agents: {},
    wave: 1,
    stage: 'reconnaissance',
    run_status: 'in_progress',
    incomplete_reason: null,
    prior_runs: [],
  };
  writeFileSync(join(run, 'state.json'), JSON.stringify(state, undefined, 2) + '\n');
  return { workspace, run, ledger, commit: head };
}

/** What the tool double captures. */
interface RegisteredTool {
  /** The tool's name. */
  name: string;
  /** Call the tool as the model would. */
  execute(args: Record<string, unknown>, exec: unknown): Promise<Record<string, unknown>>;
}

/** One start the scripted provider receives. */
interface StartSpec {
  /** The child's working directory, which is its working copy. */
  readonly cwd: string;
  /** Its prompt blocks. */
  readonly prompt: readonly { readonly text?: string }[];
  /** Its label. */
  readonly label: string;
}

/** One child's settled result. */
interface Settled {
  /** Its text output. */
  readonly output: readonly unknown[];
  /** Its enforced structured result. */
  readonly structured?: unknown;
  /** Why it ended. */
  readonly stopReason: string;
  /** Failure detail. */
  readonly diagnostic?: string;
}

/** What the scripted provider saw and what it asserts. */
interface Scripted {
  /** The working copies it saw, by agent id. */
  readonly copies: Map<string, { readonly path: string; readonly holdsSource: boolean }>;
  /** What the nested-harness tool answered, in order. */
  readonly nested: Record<string, unknown>[];
  /** Why a nested start was refused, when one was. */
  readonly nestedRefusal: string | null;
  /** What the harness tool said when it stopped, when it stopped. */
  readonly stopped: Record<string, unknown> | null;
}

/**
 * The structured result the scripted child returns for its brief. A hunter
 * answers exactly the coverage ids its brief names, writes one evidence file so
 * the promotion path is exercised, and drives the nested-harness tool while its
 * copy is live.
 * @param spec - the start the tool made.
 * @param harness - the registered `audit_harness` tool, when it is registered.
 * @param scripted - what the provider records.
 * @param child - the child agent the nested tool runs as.
 * @returns the child's structured result.
 */
function scriptedValue(spec: StartSpec, harness: RegisteredTool | undefined, scripted: Scripted, child: unknown): Record<string, unknown> {
  const brief = spec.prompt.map(block => block.text ?? '').join('\n');
  const agentId = basename(dirname(spec.cwd));
  scripted.copies.set(agentId, { path: spec.cwd, holdsSource: existsSync(join(spec.cwd, 'src/app.ts')) });
  if (brief.includes('# Security audit reconnaissance brief')) {
    return { facts: [{ item: '1', fact: 'the handler trims its input', refs: ['src/app.ts:1'] }], gaps: [] };
  }
  if (brief.includes('# Security audit hunter brief')) {
    const ids = (/Coverage ids: (.+)/u.exec(brief)?.[1] ?? '').split(',').map(id => id.trim()).filter(Boolean);
    // A stand-in for the target harness: it ignores its arguments and stays up
    // until it is stopped, so the start and stop paths are both exercised.
    writeFileSync(join(spec.cwd, 'fake-harness.sh'), '#!/bin/sh\nsleep 60\n');
    chmodSync(join(spec.cwd, 'fake-harness.sh'), 0o755);
    process.env['DELORUN_SECURITY_AUDIT_HARNESS'] = join(spec.cwd, 'fake-harness.sh');
    if (harness !== undefined) {
      const exec = { agent: child, signal: new AbortController().signal, callId: 'nested' };
      void (async () => {
        scripted.nested.push(await harness.execute({ action: 'start' }, exec));
        scripted.nested.push(await harness.execute({ action: 'start' }, exec));
        try {
          await harness.execute({ action: 'start' }, exec);
        } catch (error: unknown) {
          scripted.nestedRefusal = error instanceof Error ? error.message : String(error);
        }
        scripted.stopped = await harness.execute({ action: 'stop' }, exec);
      })().catch((error: unknown) => {
        scripted.nestedRefusal = error instanceof Error ? error.message : String(error);
        scripted.stopped = {};
      });
    }
    writeFileSync(join(spec.cwd, 'evidence.txt'), 'env -i PATH=/usr/bin HOME=' + spec.cwd + '/home TMPDIR=' + spec.cwd + '/tmp timeout 30 node --version\nv24.9.0\n');
    return {
      units: ids.map((id, index) => ({
        coverage_id: id,
        disposition: 'covered',
        reviewed_paths: ['src/app.ts'],
        checks: [index === 0
          ? { agent_id: agentId, reviewed_paths: ['src/app.ts'], invariant: 'the handler authorises its caller', method: 'local', result: 'env -i node --version printed v24.9.0 under timeout 30', artifact: 'agents/' + agentId + '/artifacts/evidence.txt' }
          : { agent_id: agentId, reviewed_paths: ['src/app.ts'], invariant: 'the handler authorises its caller', method: 'source', result: 'source review of the handler and its caller', artifact: null }],
        candidate_fingerprints: [],
        unresolved: [],
      })),
      candidates: [],
      hardening: [],
      uncovered: [],
    };
  }
  return { missing_units: [], reassign_ids: [], resolved_prior_leads: [], stop: true };
}

/**
 * Build the plugin context the tools read: the file accessor, the sandbox
 * decisions, the scripted subagent provider and the tool registry. The cast
 * states the double covers every service one delegation call touches.
 * @param run - the run directory the coordinator owns.
 * @param workspace - the workspace the audit targets.
 * @param onRegister - receives each tool when the plugin registers it.
 * @returns the context double.
 */
function contextOf(run: string, workspace: string, onRegister: (tool: RegisteredTool) => void): Context {
  const services = new Map<string, unknown>([
    ['sandboxNetwork', () => ({ mode: 'off' })],
    ['sandboxPolicy', { resolve: () => ({ mode: 'workspace-write', workspaceRoot: workspace }) }],
    ['workingDirectory', { get: () => workspace }],
    ['sessions', { get: (id: string) => id === SESSION ? { id: SESSION, header: { origin: 'user', cwd: workspace } } : undefined }],
  ]);
  const scripted: Scripted = { copies: new Map(), nested: [], nestedRefusal: null, stopped: null };
  const harness = (): RegisteredTool | undefined => tools.get('audit_harness');
  const tools = new Map<string, RegisteredTool>();
  services.set('subagents', {
    getProvider: (name: string) => name === 'spawn'
      ? { name: 'spawn', capabilities: { agentOptions: true, agentPreset: true, outputSchema: true, depthLimit: true }, inheritsParentContext: false }
      : undefined,
    resolveMaxDepth: () => 2,
    startActivation: async (spec: StartSpec): Promise<{ childId: string; name: string; result: Promise<Settled>; dispose: () => Promise<void> }> => {
      const childId = 'child-' + String(Math.random()).slice(2, 8);
      const agentId = basename(dirname(spec.cwd));
      rememberClaim(childId, { target: workspace, runId: 'run-1', dir: run }, agentId);
      const child = { id: childId, options: {}, session: { id: childId, header: { origin: 'subagent', parentSession: SESSION, cwd: spec.cwd } } };
      const value = scriptedValue(spec, harness(), scripted, child);
      return {
        childId,
        name: spec.label,
        result: (async () => {
          // Give the nested starts and their stop time to settle before the
          // role finishes and its copy is removed.
          await new Promise(resolve => setTimeout(resolve, 50));
          for (let waited = 0; scripted.stopped === null && waited < 15_000; waited += 20) await new Promise(resolve => setTimeout(resolve, 20));
          return { output: [], structured: value, stopReason: 'completed' as const };
        })(),
        dispose: async () => {},
      };
    },
  });
  const double = {
    fs: fsService,
    logger: { warn: () => {}, info: () => {}, debug: () => {} },
    get: (name: string) => services.get(name),
    tools: { register: (tool: RegisteredTool) => { tools.set(tool.name, tool); onRegister(tool); return () => {} } },
  };
  return double as unknown as Context;
}

/**
 * Read the run's state from disk.
 * @param run - the run directory.
 * @returns the state.
 */
function stateOf(run: string): HarnessState {
  return JSON.parse(readFileSync(join(run, 'state.json'), 'utf8')) as HarnessState;
}

/**
 * Write the run's state to disk.
 * @param run - the run directory.
 * @param state - the state.
 */
function writeState(run: string, state: HarnessState): void {
  writeFileSync(join(run, 'state.json'), JSON.stringify(state, undefined, 2) + '\n');
}

/**
 * Read the run's ledger from disk.
 * @param run - the run directory.
 * @returns its units.
 */
function ledgerOf(run: string): LedgerUnit[] {
  return JSON.parse(readFileSync(join(run, 'coverage-ledger.json'), 'utf8')) as LedgerUnit[];
}

/** The agent the tool thinks owns the chat. */
function fixtureAgent(workspace: string) {
  return {
    id: SESSION,
    options: { provider: 'test', model: 'test-model', reasoningEffort: 'low' },
    session: { id: SESSION, header: { origin: 'user', cwd: workspace } },
  };
}

/**
 * The budget gate's arithmetic, as the skill states it.
 */
function checkBudget(): void {
  const tooSmall = reconnaissanceGate({ profile: 'standard', budget: 6, spent: 0 });
  check(!tooSmall.ok && tooSmall.reason === 'budget_cannot_fund_reconnaissance_and_reserves', 'a budget below four reconnaissance calls, two critics and one verifier refuses to start');
  const minimum = reconnaissanceGate({ profile: 'standard', budget: 7, spent: 0 });
  check(minimum.ok && minimum.huntingAllowance === 0, 'the minimum standard budget funds reconnaissance, the critics and one verifier, and no hunter');
  const wave = waveGate({ profile: 'standard', budget: 10, spent: 7, requested: 3 });
  check(wave.hunters === 0 && wave.stop === 'budget_cannot_reserve_critics_and_validation', 'a wave with no room for its critic and the verifier reserve starts no hunter');
  const quick = waveGate({ profile: 'quick', budget: 10, spent: 7, requested: 3 });
  check(quick.hunters > 0, 'a quick run reserves one critic, so a hunter still fits');
  const validation = validationGate({ budget: 7, spent: 7, candidates: 2 });
  check(validation.canValidate === 0 && validation.unvalidated === 2 && validation.stop === 'validation_budget_exhausted', 'an exhausted budget leaves candidates unresolved');
  check(proposeBudget({ profile: 'standard', units: 20 }) > proposeBudget({ profile: 'standard', units: 2 }), 'a larger target proposes a larger budget');
}

/**
 * The copy gates: the disk floor and the live-copy cap, both naming what a
 * copy measures so the person can act.
 */
function checkCopyGates(): void {
  const measured = { bytes: 260 * 1024 * 1024, files: 26_041 };
  const floor = copyGateProblem({ live: 0, freeBytes: DISK_FLOOR_BYTES - 1, measured });
  check(floor !== undefined && floor.includes(bytesText(DISK_FLOOR_BYTES)) && floor.includes('260 MB') && floor.includes('26041'), 'a disk below the stated floor refuses the copy and states the floor and the measured size');
  const cap = copyGateProblem({ live: MAX_LIVE_COPIES, freeBytes: DISK_FLOOR_BYTES * 2, measured });
  check(cap !== undefined && cap.includes(String(MAX_LIVE_COPIES) + ' live working copies') && cap.includes('260 MB'), 'a run at its live-copy cap refuses another copy and states the count and the measured size');
  check(copyGateProblem({ live: 1, freeBytes: DISK_FLOOR_BYTES * 2, measured }) === undefined, 'a run under both bounds makes another copy');
  check(copyGateProblem({ live: 0, freeBytes: 40 * 1024 * 1024, measured: undefined }) !== undefined, 'the floor refuses the very first copy of a run, before any size is measured');
}

/**
 * The promotion procedure's refusals.
 * @param root - a directory to build the trial in.
 */
async function checkPromotion(root: string): Promise<void> {
  const agentId = 'hunter-9';
  const scratch = join(root, 'agents', agentId, 'work');
  const artifacts = join(root, 'agents', agentId, 'artifacts');
  mkdirSync(scratch, { recursive: true });
  mkdirSync(artifacts, { recursive: true });
  writeFileSync(join(scratch, 'ok.txt'), 'bounded evidence\n');
  writeFileSync(join(scratch, 'real.txt'), 'linked\n');
  symlinkSync(join(scratch, 'real.txt'), join(scratch, 'link.txt'));
  writeFileSync(join(scratch, 'big.txt'), 'x'.repeat(32));
  const reference = (name: string) => 'agents/' + agentId + '/artifacts/' + name;
  const outcome = await promoteArtifacts({ scratch, artifacts, agentId, references: [reference('ok.txt'), reference('link.txt'), reference('big.txt'), reference('../escape.txt')], limits: { perFile: 24, total: 64 } });
  check(outcome.promoted.includes(reference('ok.txt')) && existsSync(join(artifacts, 'ok.txt')), 'a regular file inside the working copy is promoted');
  check(outcome.refused.some(refusal => refusal.reference === reference('link.txt') && refusal.reason.includes('symbolic link')), 'a symbolic link is refused');
  check(outcome.refused.some(refusal => refusal.reference === reference('big.txt') && refusal.reason.includes('more than 24 bytes')), 'a file over its byte bound is refused');
  check(outcome.refused.some(refusal => refusal.reference === reference('../escape.txt')), 'a traversal path is refused');
}

/** The agent-id rule, and the briefs' verbatim skill text. */
function checkText(): void {
  check(isCanonicalAgentId('hunter-1') && !isCanonicalAgentId('Hunter') && !isCanonicalAgentId('con') && !isCanonicalAgentId('a_b'.repeat(40)), 'agent ids are canonical lowercase and never Windows device names');
  const run = { runId: 'run-1', target: '/repo', repoName: 'fixture', profile: 'standard', scopePaths: [], source: { commit: 'abc', dirty: false, capturedAt: 'now' }, priorRuns: [], scratch: '/repo/.security-audit/run-1/agents/hunter-1/work', artifacts: '/repo/.security-audit/run-1/agents/hunter-1/artifacts', agentId: 'hunter-1', sandboxMode: 'workspace-write' as const, schemaEnforced: true };
  const seeds = seedUnits([], [{ canonical_refs: { surface: 'src/app.ts#handler', boundary: 'src/app.ts#handler', subsystem: 'src', attack_class: 'ATTACK-CLASSES.md#' + (blockNames('ATTACK-CLASSES.md')[0] as string) }, surface: 'src/app.ts#handler', boundary: 'src/app.ts#handler', subsystem: 'src', attack_class: 'ATTACK-CLASSES.md#' + blockNames('ATTACK-CLASSES.md')[0], starting_paths: ['src/app.ts'], ordinary_attack_class_block: 'ATTACK-CLASSES.md#' + blockNames('ATTACK-CLASSES.md')[0], selected_companion_blocks: [], excluded_blocks: [] }]).ledger;
  const brief = hunterBrief({ run, ledger: seeds, architecture: 'the target trims input' }, seeds, []);
  check(brief.includes('## Defensive vulnerability-finding method'), 'the hunter brief copies the skill\u2019s hunting method');
  check(brief.includes('Artifact promotion procedure (trusted parent-side code only)'), 'the hunter brief copies the promotion procedure');
  check(brief.includes('needs_validation') && brief.includes('proposed_verdict'), 'the hunter brief copies the result contract and its schema branches');
  const verifier = verifierBrief({ run, ledger: seeds, architecture: 'x' }, { fingerprint: 'fp', record: { verdict: 'confirmed', fingerprint: 'fp' }, proposed_units: [seeds[0]?.coverage_id ?? ''] }, seeds);
  check(verifier.includes('You did not write this candidate.'), 'the verifier brief copies the candidate-verifier prompt');
  const critic = criticBrief({ run, ledger: seeds, architecture: 'x' }, [], true);
  check(critic.includes('Coverage-critic waves') && critic.includes('final-clean'), 'the final-clean brief carries the critic method and its own role');
}

/**
 * Run the fixture end to end.
 */
async function main(): Promise<void> {
  const fixture = buildRun();
  const registry = new Map<string, RegisteredTool>();
  const context = contextOf(fixture.run, fixture.workspace, tool => { registry.set(tool.name, tool); });
  registerDelegationTool(context, { mount: 'agent', runsDir: '.security-audit', resultRetries: 0, provider: 'spawn', models: {} });
  const tool = registry.get('audit_delegate') as RegisteredTool;
  const harness = registry.get('audit_harness') as RegisteredTool;
  check(tool !== undefined && harness !== undefined, 'the delegation and nested-harness tools are both registered');
  rememberCoordinatorRun(SESSION, { target: fixture.workspace, runId: 'run-1', dir: fixture.run });
  const exec = { agent: fixtureAgent(fixture.workspace), signal: new AbortController().signal, callId: 'check' };
  let coordinatorRefusal = '';
  try {
    await harness.execute({ action: 'start' }, exec);
  } catch (error: unknown) {
    coordinatorRefusal = error instanceof Error ? error.message : String(error);
  }
  check(coordinatorRefusal.includes('delegated role'), 'a chat that claimed no brief cannot start a nested harness');
  const calls: Record<string, unknown>[] = [];
  const recon = await Promise.all(['1a', '1b', '1c', '1d'].map(focus => tool.execute({ role: 'recon', focus }, exec)));
  calls.push(...recon);
  let state = stateOf(fixture.run);
  check(Object.values(state.agents).filter(entry => entry.kind === 'recon' && entry.status === 'recorded').length === 4, 'four reconnaissance roles ran and recorded');
  check(state.invocations === 4, 'four reconnaissance calls are counted against the budget');
  check(recon.filter(answer => answer.check_in !== null).length === 1, 'the after-recon check-in is reported once');
  check(recon.some(answer => (answer.check_in as { stage?: string } | null)?.stage === 'after_recon'), 'the check-in names the recon boundary');
  check(Object.values(state.agents).every(entry => entry.work !== undefined && entry.work.removed_at !== null), 'each reconnaissance role\u2019s working copy is recorded and removed when it finished');
  check(![...Object.keys(state.agents)].some(agentId => existsSync(join(fixture.run, 'agents', agentId, 'work'))), 'no reconnaissance copy is left on disk');

  // The live-copy cap, end to end: four copies the run still holds refuse a fifth role.
  const capped = stateOf(fixture.run);
  for (const entry of Object.values(capped.agents)) {
    if (entry.work !== undefined) entry.work = { ...entry.work, removed_at: null };
  }
  writeState(fixture.run, capped);
  let capRefusal = '';
  try {
    await tool.execute({ role: 'hunt', coverage_ids: fixture.ledger.map(unit => unit.coverage_id) }, exec);
  } catch (error: unknown) {
    capRefusal = error instanceof Error ? error.message : String(error);
  }
  check(capRefusal.includes('live working copies, its cap of 4'), 'a run holding its cap of live copies refuses the next role, naming the count and the cap');
  const restored = stateOf(fixture.run);
  for (const entry of Object.values(restored.agents)) {
    if (entry.work !== undefined) entry.work = { ...entry.work, removed_at: entry.work.removed_at === null ? new Date(0).toISOString() : entry.work.removed_at };
  }
  writeState(fixture.run, restored);

  const hunt = await tool.execute({ role: 'hunt', coverage_ids: fixture.ledger.map(unit => unit.coverage_id) }, exec);
  const afterHunt = ledgerOf(fixture.run);
  check(afterHunt.every(unit => unit.status === 'covered'), 'the hunter closed both assigned units');
  check(afterHunt.some(unit => unit.local_checks.some(check => check.method === 'local' && check.artifact !== null)), 'a local check carries its promoted artifact');
  const hunterId = String(hunt.agent_id);
  check(existsSync(join(fixture.run, 'agents', hunterId, 'artifacts', 'evidence.txt')), 'the evidence file was promoted into the agent\u2019s artifacts');
  check(!existsSync(join(fixture.run, 'agents', hunterId, 'work')), 'the hunter\u2019s working copy is removed when it finishes, keeping its artifacts');
  check(existsSync(join(fixture.run, 'agents', hunterId, 'brief.md')), 'the brief is written where the run records it');
  check(readFileSync(join(fixture.run, 'agents', hunterId, 'brief.md'), 'utf8').includes(join(fixture.run, 'agents', hunterId, 'work')), 'the brief names the role\u2019s working copy as its working directory');
  check(hunt.check_in === null, 'an after-recon run does not pause after a wave');
  const critique = await tool.execute({ role: 'critique' }, exec);
  check((critique.summary as { stop?: boolean }).stop === true, 'the post-wave critic accepted no further work');
  const finalClean = await tool.execute({ role: 'final-clean' }, exec);
  state = stateOf(fixture.run);
  check(state.invocations === 7, 'seven agent calls were counted in all');
  check(ledgerOf(fixture.run).every(unit => unit.status === 'covered'), 'the run reaches a critic-terminated stop with every unit covered');
  check(Object.values(state.agents).some(entry => entry.kind === 'final-critique' && entry.status === 'recorded'), 'the distinct final-clean critic is recorded separately');
  check((finalClean.budget as { remaining?: number }).remaining === 33, 'the answer reports the remaining budget');
  check(existsSync(join(fixture.run, 'run-metadata.json')), 'run-metadata.json is rewritten after the stores change');

  const metadata = JSON.parse(readFileSync(join(fixture.run, 'run-metadata.json'), 'utf8')) as RunMetadata;
  const copies = Object.values(metadata.work_copies);
  check(Object.keys(metadata.work_copies).length === 7, 'every role\u2019s working copy is in run-metadata.json');
  check(copies.every(copy => copy.files === 2 && copy.bytes > 0 && copy.seconds >= 0 && copy.removed_at !== null), 'each copy records its file count, bytes and seconds, and that it was removed');
  check(copies.every(copy => copy.revision === fixture.commit && copy.reviewed), 'each copy names the reviewed revision and is the reviewed tree');
  check(metadata.copy_measurement !== null && metadata.copy_measurement.files === 2, 'the run metadata records what one copy measured');
  check(metadata.nested_harness.cap === NESTED_HARNESS_CAP && metadata.nested_harness.starts.length === NESTED_HARNESS_CAP, 'run-metadata.json records every nested start against its cap');
  check(metadata.nested_harness.starts.every(start => start.exit !== null && start.stopped_at !== null), 'every nested start records its exit and when it stopped');
  check(new Set(metadata.nested_harness.starts.map(start => start.port)).size === NESTED_HARNESS_CAP && metadata.nested_harness.starts.every(start => NESTED_PORT_RANGE.includes(start.port)), 'nested starts take distinct spare ports from 19988 to 19997');
  check(metadata.nested_harness.starts.every(start => start.home.startsWith('agents/') && (statSync(join(fixture.run, start.home)).mode & 0o777) === 0o700), 'each nested start has its own scratch HOME at mode 0700');

  checkBudget();
  checkCopyGates();
  await checkPromotion(join(fixture.workspace, '..', 'promotion'));
  checkText();
  console.log('');
  console.log('run directory: ' + fixture.run);
  if (failures.length > 0) {
    console.log(String(failures.length) + ' check(s) failed');
    process.exitCode = 1;
  } else {
    console.log('every check passed');
  }
}

await main();
