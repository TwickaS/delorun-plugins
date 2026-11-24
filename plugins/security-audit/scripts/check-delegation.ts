/**
 * The delegation lane's acceptance check: no model, no key, no network. It builds
 * a throwaway workspace holding one fixture run with a two-unit ledger, registers
 * the real delegation tool, starts the four reconnaissance roles, one hunter, a
 * post-wave critic and the final-clean critic through a scripted subagent
 * provider, and asserts what reached the run store.
 *
 * Run: cd ~/delorun/code && node --import tsx/esm \
 *        ../plugins/plugins/security-audit/scripts/check-delegation.ts
 * @module @delorun/plugin-security-audit/scripts/check-delegation
 */
import { existsSync, lstatSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, statSync, symlinkSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { basename, dirname, join } from 'node:path'
import type { Context } from '@deepseek-ai/cordis'
import { isCanonicalAgentId, promoteArtifacts, registerDelegationTool } from '../src/delegate.ts'
import { proposeBudget, reconnaissanceGate, validationGate, waveGate } from '../src/budget.ts'
import { seedUnits } from '../src/ledger.ts'
import { blockNames } from '../src/skill.ts'
import { criticBrief, hunterBrief, verifierBrief } from '../src/prompts/index.ts'
import type { HarnessState, LedgerUnit } from '../src/types.ts'

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
}

/**
 * Build the fixture workspace and run.
 * @returns the workspace, the run directory and the ledger it seeded.
 */
function buildRun(): Fixture {
  const root = mkdtempSync(join(tmpdir(), 'sa-delegation-'));
  const workspace = join(root, 'repo');
  mkdirSync(join(workspace, 'src'), { recursive: true });
  writeFileSync(join(workspace, '.gitignore'), '.security-audit/\n');
  writeFileSync(join(workspace, 'src/app.ts'), 'export function handler(input: string): string {\n  return input.trim()\n}\n');
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
    source_ref: { commit: null, dirty: false, dirty_known: false, captured_at: new Date().toISOString() },
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
  return { workspace, run, ledger };
}

/** What the tool double captures. */
interface RegisteredTool {
  /** Call the tool as the model would. */
  execute(args: Record<string, unknown>, exec: unknown): Promise<Record<string, unknown>>;
}

/** One start the scripted provider receives. */
interface StartSpec {
  /** The child's working directory, which is its scratch. */
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

/**
 * The structured result the scripted child returns for its brief. A hunter
 * answers exactly the coverage ids its brief names, and writes one evidence
 * file so the promotion path is exercised.
 * @param spec - the start the tool made.
 * @returns the child's structured result.
 */
function scriptedValue(spec: StartSpec): Record<string, unknown> {
  const brief = spec.prompt.map(block => block.text ?? '').join('\n');
  const agentId = basename(dirname(spec.cwd));
  if (brief.includes('# Security audit reconnaissance brief')) {
    return { facts: [{ item: '1', fact: 'the handler trims its input', refs: ['src/app.ts:1'] }], gaps: [] };
  }
  if (brief.includes('# Security audit hunter brief')) {
    const ids = (/Coverage ids: (.+)/u.exec(brief)?.[1] ?? '').split(',').map(id => id.trim()).filter(Boolean);
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
 * Build the plugin context the tool reads: the file accessor, the sandbox
 * decisions, the scripted subagent provider and the tool registry. The cast
 * states the double covers every service one delegation call touches.
 * @param onRegister - receives the tool when the plugin registers it.
 * @returns the context double.
 */
function contextOf(run: string, workspace: string, onRegister: (tool: RegisteredTool) => void): Context {
  const services = new Map<string, unknown>([
    ['sandboxNetwork', () => ({ mode: 'off' })],
    ['sandboxPolicy', { resolve: () => ({ mode: 'workspace-write', workspaceRoot: workspace }) }],
    ['workingDirectory', { get: () => workspace }],
    ['subagents', {
      getProvider: (name: string) => name === 'spawn'
        ? { name: 'spawn', capabilities: { agentOptions: true, agentPreset: true, outputSchema: true, depthLimit: true }, inheritsParentContext: false }
        : undefined,
      resolveMaxDepth: () => 2,
      startActivation: async (spec: StartSpec): Promise<{ childId: string; name: string; result: Promise<Settled>; dispose: () => Promise<void> }> => ({
        childId: 'child-' + String(Math.random()).slice(2, 8),
        name: spec.label,
        result: Promise.resolve({ output: [], structured: scriptedValue(spec), stopReason: 'completed' }),
        dispose: async () => {},
      }),
    }],
  ]);
  const double = {
    fs: fsService,
    logger: { warn: () => {}, info: () => {}, debug: () => {} },
    get: (name: string) => services.get(name),
    tools: { register: (tool: RegisteredTool) => { onRegister(tool); return () => {} } },
  };
  void run;
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
 * The promotion procedure's refusals.
 * @param root - a directory to build the trial in.
 */
async function checkPromotion(root: string): Promise<void> {
  const agentId = 'hunter-9';
  const scratch = join(root, 'agents', agentId, 'scratch');
  const artifacts = join(root, 'agents', agentId, 'artifacts');
  mkdirSync(scratch, { recursive: true });
  mkdirSync(artifacts, { recursive: true });
  writeFileSync(join(scratch, 'ok.txt'), 'bounded evidence\n');
  writeFileSync(join(scratch, 'real.txt'), 'linked\n');
  symlinkSync(join(scratch, 'real.txt'), join(scratch, 'link.txt'));
  writeFileSync(join(scratch, 'big.txt'), 'x'.repeat(32));
  const reference = (name: string) => 'agents/' + agentId + '/artifacts/' + name;
  const outcome = await promoteArtifacts({ scratch, artifacts, agentId, references: [reference('ok.txt'), reference('link.txt'), reference('big.txt'), reference('../escape.txt')], limits: { perFile: 24, total: 64 } });
  check(outcome.promoted.includes(reference('ok.txt')) && existsSync(join(artifacts, 'ok.txt')), 'a regular file inside scratch is promoted');
  check(outcome.refused.some(refusal => refusal.reference === reference('link.txt') && refusal.reason.includes('symbolic link')), 'a symbolic link is refused');
  check(outcome.refused.some(refusal => refusal.reference === reference('big.txt') && refusal.reason.includes('more than 24 bytes')), 'a file over its byte bound is refused');
  check(outcome.refused.some(refusal => refusal.reference === reference('../escape.txt')), 'a traversal path is refused');
}

/** The agent-id rule, and the briefs' verbatim skill text. */
function checkText(): void {
  check(isCanonicalAgentId('hunter-1') && !isCanonicalAgentId('Hunter') && !isCanonicalAgentId('con') && !isCanonicalAgentId('a_b'.repeat(40)), 'agent ids are canonical lowercase and never Windows device names');
  const run = { runId: 'run-1', target: '/repo', repoName: 'fixture', profile: 'standard', scopePaths: [], source: { commit: 'abc', dirty: false, capturedAt: 'now' }, priorRuns: [], scratch: '/repo/.security-audit/run-1/agents/hunter-1/scratch', artifacts: '/repo/.security-audit/run-1/agents/hunter-1/artifacts', agentId: 'hunter-1', sandboxMode: 'workspace-write' as const, schemaEnforced: true };
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
  let registered: RegisteredTool | undefined;
  const context = contextOf(fixture.run, fixture.workspace, tool => { registered = tool; });
  registerDelegationTool(context, { mount: 'agent', runsDir: '.security-audit', resultRetries: 0, provider: 'spawn', models: {} });
  const tool = registered as RegisteredTool;
  const exec = { agent: fixtureAgent(fixture.workspace), signal: new AbortController().signal, callId: 'check' };
  const calls: Record<string, unknown>[] = [];
  const recon = await Promise.all(['1a', '1b', '1c', '1d'].map(focus => tool.execute({ role: 'recon', focus }, exec)));
  calls.push(...recon);
  let state = stateOf(fixture.run);
  check(Object.values(state.agents).filter(entry => entry.kind === 'recon' && entry.status === 'recorded').length === 4, 'four reconnaissance roles ran and recorded');
  check(state.invocations === 4, 'four reconnaissance calls are counted against the budget');
  check(recon.filter(answer => answer.check_in !== null).length === 1, 'the after-recon check-in is reported once');
  check(recon.some(answer => (answer.check_in as { stage?: string } | null)?.stage === 'after_recon'), 'the check-in names the recon boundary');
  const hunt = await tool.execute({ role: 'hunt', coverage_ids: fixture.ledger.map(unit => unit.coverage_id) }, exec);
  const afterHunt = ledgerOf(fixture.run);
  check(afterHunt.every(unit => unit.status === 'covered'), 'the hunter closed both assigned units');
  check(afterHunt.some(unit => unit.local_checks.some(check => check.method === 'local' && check.artifact !== null)), 'a local check carries its promoted artifact');
  const hunterId = String(hunt.agent_id);
  check(existsSync(join(fixture.run, 'agents', hunterId, 'artifacts', 'evidence.txt')), 'the evidence file was promoted into the agent\u2019s artifacts');
  check(existsSync(join(fixture.run, 'agents', hunterId, 'brief.md')), 'the brief is written where the run records it');
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
  checkBudget();
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
