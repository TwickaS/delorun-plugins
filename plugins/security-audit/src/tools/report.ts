/**
 * `audit_report`: write one of the three report documents, checked against
 * `findings.json` by its machine-readable fingerprint footer, so the prose and
 * the records cannot disagree. A report never reaches a repository that may
 * publish it, so the tool also exports the three documents into a private
 * folder the person names outside the workspace.
 * @module delorun-plugin-security-audit/tools/report
 */
import { execFile } from 'node:child_process'
import { posix } from 'node:path'
import { promisify } from 'node:util'
import type { Context } from '@deepseek-ai/cordis'
import type { Agent } from '@deepseek-ai/dsh-agent'
import type {} from '@deepseek-ai/dsh-fs'
import type { SandboxExecutionPolicy } from '@deepseek-ai/dsh-sandbox'
import { defineTool } from '@deepseek-ai/dsh-tools'
import type { ToolRunContext } from '@deepseek-ai/dsh-tools'
import type { Config } from '../config.ts'
import { readCandidates } from '../candidates.ts'
import { REPORT_FILES, findingsDocument, writeReport } from '../report.ts'
import { requireMutable, runContext } from '../run-context.ts'
import { type AuditFiles, inRun } from '../store.ts'
import type { ReportDocument, RunLocation } from '../types.ts'

const execFileAsync = promisify(execFile)

/** The three report documents, in the order a reader takes them. */
const REPORT_DOCUMENT = ['REPORT', 'FINDINGS_DETAIL', 'NEEDS_VALIDATION'] as const

/** A git remote that may publish the repository the run audits. */
export interface PublicRemote {
  /** The remote's name. */
  readonly name: string
  /** The remote's URL. */
  readonly url: string
}

/**
 * Whether a git remote URL names another computer, so the remote may publish
 * the repository. A local path or `file:` URL stays on this one.
 * @param url - the remote URL.
 * @returns whether it is a remote-hosted URL.
 */
export function publicRemote(url: string): boolean {
  const value = url.trim()
  if (value === '' || value.startsWith('file:')) return false
  if (value.startsWith('/') || value.startsWith('.') || value.startsWith('~')) return false
  if (/^[A-Za-z]:[\\/]/u.test(value)) return false
  return true
}

/**
 * The first git remote that may publish the target, or `undefined` when it has
 * none or only local ones. The network is off during an audit, so no remote is
 * asked whether it is public: every host is treated as possibly public.
 * @param target - the workspace directory.
 * @returns the remote name and URL, when the target has one.
 */
export async function publicRemoteOf(target: string): Promise<PublicRemote | undefined> {
  let stdout: string
  try {
    // The target's configuration is untrusted: its fsmonitor command stays off.
    stdout = (await execFileAsync('git', ['-C', target, '-c', 'core.fsmonitor=false', 'remote', '-v'], { timeout: 5_000 })).stdout
  } catch {
    return undefined
  }
  for (const line of stdout.split('\n')) {
    const match = /^(\S+)\s+(\S+)\s+\(fetch\)$/u.exec(line.trim())
    if (match === null) continue
    const url = match[2] ?? ''
    if (publicRemote(url)) return { name: match[1] ?? '', url }
  }
  return undefined
}

/**
 * Resolve the folder a report is exported to.
 * @param target - the workspace directory a relative folder resolves against.
 * @param folder - the folder the person named.
 * @returns the absolute folder.
 * @throws {Error} when the folder is blank.
 */
export function exportFolder(target: string, folder: string): string {
  const value = folder.trim()
  if (value.length === 0) throw new Error('folder must name a directory, such as ../audit-reports')
  return posix.isAbsolute(value) ? posix.normalize(value) : posix.resolve(target, value)
}

/**
 * The problem that stops an export into this folder, or `null` when the folder
 * may receive it. A folder inside the workspace could be committed with the
 * target, so it needs the person's consent.
 * @param target - the workspace directory.
 * @param folder - the absolute export folder.
 * @param force - whether the person accepted a folder inside the workspace.
 * @returns the refusal, or `null`.
 */
export function exportFolderProblem(target: string, folder: string, force: boolean): string | null {
  const root = target.endsWith('/') ? target : target + '/'
  const inside = folder === root.slice(0, -1) || folder.startsWith(root)
  if (!inside || force) return null
  return folder + ' is inside the audited workspace, where a commit could carry it; name a folder outside the workspace, or pass force: true to export there anyway'
}

/**
 * Write one report document to the export folder. The folder is outside the
 * workspace by design, so the write runs with the host's own authority rather
 * than the session's workspace fence.
 * @param ctx - the plugin context.
 * @param policy - the policy the export writes under.
 * @param path - the absolute destination.
 * @param content - the document.
 * @param signal - the call's signal.
 * @throws {Error} when the destination is not a regular file.
 */
async function writeExport(ctx: Context, policy: SandboxExecutionPolicy, path: string, content: string, signal: AbortSignal): Promise<void> {
  const entry = await ctx.fs.lstat(path, undefined, signal)
  if (entry?.type === 'symlink' || entry?.type === 'other' || entry?.type === 'directory') throw new Error(path + ' is not a replaceable regular file')
  const destination = await ctx.fs.resolve(path, { signal })
  await ctx.fs.writeText(destination, content, undefined, signal, policy)
}

/**
 * Copy every report document the run holds into the export folder, so the
 * folder receives all three once the run has written them.
 * @param ctx - the plugin context.
 * @param files - file access.
 * @param run - the run.
 * @param folder - the absolute export folder.
 * @param policy - the policy the export writes under.
 * @param signal - the call's signal.
 * @returns the paths written.
 */
async function exportReports(ctx: Context, files: AuditFiles, run: RunLocation, folder: string, policy: SandboxExecutionPolicy, signal: AbortSignal): Promise<string[]> {
  const exported: string[] = []
  for (const document of REPORT_DOCUMENT) {
    const text = await files.read(inRun(run, REPORT_FILES[document]))
    if (text === undefined) continue
    const path = posix.join(folder, REPORT_FILES[document])
    await writeExport(ctx, policy, path, text, signal)
    exported.push(path)
  }
  return exported
}

/**
 * Register `audit_report`.
 * @param ctx - the plugin context.
 * @param config - the mounted row's configuration.
 */
export function registerReportTool(ctx: Context, config: Config): void {
  ctx.tools.register(defineTool({
    name: 'audit_report',
    presentCall: args => ({ card: 'generic', title: 'Write ' + args.document, kind: 'other' }),
    description: 'Write REPORT.md, FINDINGS-DETAIL.md or NEEDS-VALIDATION.md after checking its machine-readable fingerprint footer against findings.json. A report must not be committed into a repository that may publish it: when the target has a git remote, pass folder, a directory outside the workspace, and every report document is copied there; a folder inside the workspace needs force. Derive every word from the final records; never change a verdict, severity or blocker in prose.',
    parameters: {
      document: { type: 'string', required: true, enum: [...REPORT_DOCUMENT], description: 'The report document.' },
      content: { type: 'string', required: true, description: 'The complete Markdown, ending with <!-- audit-fingerprints: fp1, fp2 -->.' },
      folder: { type: 'string', description: 'A directory outside the workspace to export the report to. Relative names resolve against the workspace. Required when the target has a git remote.' },
      force: { type: 'boolean', description: 'Export into a folder inside the workspace anyway. The folder could be committed with the target.' },
    },
    output: {
      schema: {
        type: 'object', additionalProperties: false,
        properties: {
          document: { type: 'string', required: true },
          path: { type: 'string', required: true },
          bytes: { type: 'integer', required: true },
          folder: { oneOf: [{ type: 'string' }, { type: 'null' }], required: true },
          exported: { type: 'array', required: true, items: { type: 'string' } },
          content: { type: 'string', required: true },
        },
      },
      render: (_args, value) => [{ type: 'text', text: value.content }],
    },
    async execute(args, exec: ToolRunContext) {
      if (exec.agent === undefined) throw new Error('the audit tools need an owning agent session')
      const agent: Agent = exec.agent
      const context = await runContext(ctx, agent, exec.signal, config.runsDir)
      requireMutable(context.state)
      const candidates = await readCandidates(context.files, context.run)
      const records = findingsDocument(candidates).records
      const remote = await publicRemoteOf(context.target)
      if (args.folder === undefined && remote !== undefined) {
        throw new Error('the target has the git remote "' + remote.name + '" (' + remote.url + '), which may publish the repository; name a folder outside the workspace with the folder argument, such as ../audit-reports, and write the report again')
      }
      const folder = args.folder === undefined ? null : exportFolder(context.target, args.folder)
      if (folder !== null) {
        const problem = exportFolderProblem(context.target, folder, args.force === true)
        if (problem !== null) throw new Error(problem)
      }
      await writeReport(context.files, context.run, args.document as ReportDocument, args.content, records)
      const path = inRun(context.run, REPORT_FILES[args.document as ReportDocument])
      const exported = folder === null
        ? []
        : await exportReports(ctx, context.files, context.run, folder, { mode: 'danger-full-access', workspaceRoot: context.target }, exec.signal)
      const bytes = Buffer.byteLength(args.content, 'utf8')
      const note = folder === null ? '' : ' Exported ' + exported.map(file => posix.basename(file)).join(', ') + ' to ' + folder + '.'
      return { document: args.document, path, bytes, folder, exported, content: 'Wrote ' + args.document + ' to ' + path + ' (' + String(bytes) + ' bytes).' + note }
    },
  }))
}
