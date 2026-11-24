/**
 * `audit_report`: write one of the three report documents, checked against
 * `findings.json` by its machine-readable fingerprint footer, so the prose and
 * the records cannot disagree.
 * @module @delorun/plugin-security-audit/tools/report
 */
import type { Context } from '@deepseek-ai/cordis'
import type { Agent } from '@deepseek-ai/dsh-agent'
import { defineTool } from '@deepseek-ai/dsh-tools'
import type { ToolRunContext } from '@deepseek-ai/dsh-tools'
import type { Config } from '../config.ts'
import { readCandidates } from '../candidates.ts'
import { REPORT_FILES, findingsDocument, writeReport } from '../report.ts'
import { requireMutable, runContext } from '../run-context.ts'
import { inRun } from '../store.ts'
import type { ReportDocument } from '../types.ts'

const REPORT_DOCUMENT = ['REPORT', 'FINDINGS_DETAIL', 'NEEDS_VALIDATION'] as const

/**
 * Register `audit_report`.
 * @param ctx - the plugin context.
 * @param config - the mounted row's configuration.
 */
export function registerReportTool(ctx: Context, config: Config): void {
  ctx.tools.register(defineTool({
    name: 'audit_report',
    presentCall: args => ({ card: 'generic', title: 'Write ' + args.document, kind: 'other' }),
    description: 'Write REPORT.md, FINDINGS-DETAIL.md or NEEDS-VALIDATION.md after checking its machine-readable fingerprint footer against findings.json. Derive every word from the final records; never change a verdict, severity or blocker in prose.',
    parameters: {
      document: { type: 'string', required: true, enum: [...REPORT_DOCUMENT], description: 'The report document.' },
      content: { type: 'string', required: true, description: 'The complete Markdown, ending with <!-- audit-fingerprints: fp1, fp2 -->.' },
    },
    output: {
      schema: {
        type: 'object', additionalProperties: false,
        properties: {
          document: { type: 'string', required: true },
          path: { type: 'string', required: true },
          bytes: { type: 'integer', required: true },
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
      await writeReport(context.files, context.run, args.document as ReportDocument, args.content, records)
      const path = inRun(context.run, REPORT_FILES[args.document as ReportDocument])
      return { document: args.document, path, bytes: Buffer.byteLength(args.content, 'utf8'), content: 'Wrote ' + args.document + ' to ' + path + ' (' + String(Buffer.byteLength(args.content, 'utf8')) + ' bytes).' }
    },
  }))
}
