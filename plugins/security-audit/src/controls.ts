/**
 * The pane's control over a run: pause, resume, stop, and the report export. The
 * pane is no longer observe-only, so these are the three writes a person can make
 * from it, each through one registered human command.
 *
 * `control.json` in the run directory is the contract: the coordinator reads it
 * before it spawns another role and stops spawning while it says `pause`, so a
 * pause lets the roles already running finish. `stop` records the reason the run
 * ends incomplete with, which the skill requires for a partial run.
 * @module @deepseek-ai/plugin-security-audit/controls
 */
import type { Context } from '@deepseek-ai/cordis'
import type { Agent } from '@deepseek-ai/dsh-agent'
import type { CommandInvocation, CommandResult } from '@deepseek-ai/dsh-commands'
import { coordinatingSession, filesFor, inRun, now, REPORT_FILES, RUN_METADATA_FILE } from './store.ts'
import type { RunLocation } from './types.ts'

/** How a control command reads in the slash menu. */
export const PAUSE_COMMAND = 'audit-pause'
/** How the resume command reads in the slash menu. */
export const RESUME_COMMAND = 'audit-resume'
/** How the stop command reads in the slash menu. */
export const STOP_COMMAND = 'audit-stop'
/** How the export command reads in the slash menu. */
export const EXPORT_COMMAND = 'audit-export'

/** The run directory a control command names: workspace-relative, under the runs directory. */
const RUN_DIRECTORY = /^\.security-audit\/run-[A-Za-z0-9._-]+$/u

/** One parsed control line. */
interface ControlLine {
  /** The workspace-relative run directory. */
  readonly directory: string
  /** Everything the person wrote after the directory. */
  readonly rest: string
}

/**
 * Split a control line into its run directory and the text after it.
 * @param rawInput - the text following the command name.
 * @returns the directory and the rest of the line.
 * @throws {Error} naming the expected first word when the line does not start with a run directory.
 */
function parseLine(rawInput: string): ControlLine {
  const trimmed = rawInput.trim()
  const [directory = '', ...rest] = trimmed.split(/\s+/u)
  if (!RUN_DIRECTORY.test(directory)) {
    throw new Error(`name the run directory first, as .security-audit/run-1; ${directory === '' ? 'the line is empty' : `"\${directory}" is not a run directory`}`)
  }
  return { directory, rest: rest.join(' ').trim() }
}

/**
 * The absolute path of one run in the calling agent's workspace.
 * @param agent - the calling agent.
 * @param directory - the workspace-relative run directory.
 * @returns the run's location, and its absolute directory.
 * @throws {Error} when the Session reports no workspace folder.
 */
function locate(agent: Agent, directory: string): { readonly run: RunLocation; readonly dir: string } {
  const cwd = agent.session.header.cwd
  if (cwd === undefined || cwd.trim() === '') {
    throw new Error('this chat reports no workspace folder, so the run cannot be found')
  }
  const root = cwd.replace(/[/\\]+$/u, '')
  const dir = `${root}/${directory}`
  return { run: { target: root, runId: directory.slice(directory.lastIndexOf('/') + 1), dir }, dir }
}

/**
 * Settle one command's outcome as a result the dispatching pane shows.
 * @param work - the work, which may throw to refuse.
 * @returns the settled result.
 */
async function settle(work: () => Promise<string>): Promise<CommandResult> {
  try {
    return { kind: 'success', text: await work() }
  } catch (error) {
    return { kind: 'error', text: error instanceof Error ? error.message : String(error) }
  }
}

/**
 * Write the control a person asked of one run.
 * @param ctx - the plugin context.
 * @param agent - the calling agent.
 * @param invocation - the command invocation to read the line and signal from.
 * @param command - the control to record.
 * @returns the confirmation text.
 */
async function record(ctx: Context, agent: Agent, invocation: CommandInvocation, command: 'pause' | 'resume' | 'stop'): Promise<string> {
  const line = parseLine(invocation.rawInput)
  const { run, dir } = locate(agent, line.directory)
  const files = filesFor(ctx, agent, invocation.signal)
  if (await files.read(inRun(run, RUN_METADATA_FILE)) === undefined) {
    throw new Error(`\${line.directory} holds no run metadata, so there is nothing to control`)
  }
  if (command === 'stop' && line.rest === '') {
    throw new Error('name the reason the run stops after the directory; a stopped run records why it is incomplete')
  }
  await files.writeJson(inRun(run, 'control.json'), {
    command,
    reason: line.rest === '' ? null : line.rest,
    at: now(),
    run: run.runId,
    agent_session: coordinatingSession(ctx, agent).header.id,
  })
  if (command === 'pause') return `Recorded a pause for \${line.directory}; roles already running finish, and no new role starts.`
  if (command === 'resume') return `Recorded a resume for \${line.directory}; hunting continues with the next wave.`
  return `Recorded a stop for \${line.directory}: \${line.rest}.`
}

/**
 * Write the report documents to a folder the person names.
 * @param ctx - the plugin context.
 * @param agent - the calling agent.
 * @param invocation - the command invocation to read the line and signal from.
 * @returns the confirmation text naming every written file.
 * @throws {Error} when the line names no absolute folder or the run has no report.
 */
async function exportReport(ctx: Context, agent: Agent, invocation: CommandInvocation): Promise<string> {
  const line = parseLine(invocation.rawInput)
  const folder = line.rest
  if (folder === '') throw new Error('name the folder to export to after the directory; an absolute path keeps the report outside the repository')
  if (!folder.startsWith('/')) throw new Error(`\${folder} is not an absolute folder; name one, so the report lands outside the audited repository`)
  const { run, dir } = locate(agent, line.directory)
  const files = filesFor(ctx, agent, invocation.signal)
  const written: string[] = []
  const missing: string[] = []
  for (const document of ['REPORT', 'FINDINGS_DETAIL', 'NEEDS_VALIDATION'] as const) {
    const name = REPORT_FILES[document]
    const text = await files.read(inRun(run, name))
    if (text === undefined) {
      missing.push(name)
      continue
    }
    await files.write(`${folder.replace(/\/+$/u, '')}/${name}`, text)
    written.push(name)
  }
  if (written.length === 0) throw new Error(`\${line.directory} holds no report document yet, and \${dir} has nothing to export`)
  const skipped = missing.length === 0 ? '' : ` \${missing.join(' and ')} ${missing.length === 1 ? 'is' : 'are'} not written yet.`
  return `Wrote \${written.join(', ')} to \${folder}.${skipped}`
}

/**
 * Register the four control commands.
 * @param ctx - the plugin context.
 * @returns the registration disposer.
 */
export function registerControlCommands(ctx: Context): () => void {
  const registrations = [
    ctx.commands.register({
      name: PAUSE_COMMAND,
      description: 'Pause a security audit run: roles already running finish and no new role starts.',
      input: { hint: '.security-audit/run-1' },
      handler: invocation => settle(() => record(ctx, invocation.agent, invocation, 'pause')),
    }),
    ctx.commands.register({
      name: RESUME_COMMAND,
      description: 'Resume a paused security audit run.',
      input: { hint: '.security-audit/run-1' },
      handler: invocation => settle(() => record(ctx, invocation.agent, invocation, 'resume')),
    }),
    ctx.commands.register({
      name: STOP_COMMAND,
      description: 'Stop a security audit run incomplete, with the reason it stopped.',
      input: { hint: '.security-audit/run-1 the reason' },
      handler: invocation => settle(() => record(ctx, invocation.agent, invocation, 'stop')),
    }),
    ctx.commands.register({
      name: EXPORT_COMMAND,
      description: 'Write a run\u2019s report documents to a folder outside the repository.',
      input: { hint: '.security-audit/run-1 /home/me/audit-reports' },
      handler: invocation => settle(() => exportReport(ctx, invocation.agent, invocation)),
    }),
  ]
  return () => { for (const dispose of registrations) dispose() }
}
