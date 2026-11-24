/**
 * `audit_finalize`: write `findings.json` from the independently verified
 * records, validate both skill files, and state exactly what the three report
 * documents must account for. It never turns an unverified candidate into a
 * finding.
 * @module delorun-plugin-security-audit/tools/finalize
 */
import type { Context } from '@deepseek-ai/cordis'
import type { Agent } from '@deepseek-ai/dsh-agent'
import { defineTool } from '@deepseek-ai/dsh-tools'
import type { ToolRunContext } from '@deepseek-ai/dsh-tools'
import type { Config } from '../config.ts'
import { readCandidates } from '../candidates.ts'
import { REPORT_FILES, expectedFingerprints, findingsDocument, writeFindings, writeLedger, writeRunMetadata } from '../report.ts'
import { requireMutable, runContext } from '../run-context.ts'
import { updateState } from '../store.ts'
import type { ReportDocument } from '../types.ts'

const REPORT_DOCUMENT = ['REPORT', 'FINDINGS_DETAIL', 'NEEDS_VALIDATION'] as const

/**
 * Register `audit_finalize`.
 * @param ctx - the plugin context.
 * @param config - the mounted row's configuration.
 */
export function registerFinalizeTool(ctx: Context, config: Config): void {
  ctx.tools.register(defineTool({
    name: 'audit_finalize',
    presentCall: () => ({ card: 'generic', title: 'Finalize audit findings', kind: 'other' }),
    description: 'Write findings.json from independently verified records, validate the ledger and findings with the skill’s own validators, update the run metadata, and return the exact report obligations. It never turns an unverified candidate into a finding.',
    parameters: {
      incomplete_reason: { type: 'string', description: 'Why the run cannot claim complete coverage. Required when unresolved candidates or non-terminal units remain.' },
    },
    output: {
      schema: {
        type: 'object', additionalProperties: false,
        properties: {
          status: { type: 'string', required: true },
          records: { type: 'integer', required: true },
          unresolved: { type: 'array', required: true, items: { type: 'string' } },
          open_units: { type: 'array', required: true, items: { type: 'string' } },
          expected: { type: 'object', additionalProperties: true, required: true },
          documents: { type: 'array', required: true, items: { type: 'string' } },
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
      if (args.incomplete_reason !== undefined && args.incomplete_reason.trim().length === 0) throw new Error('incomplete_reason must not be empty')
      const candidates = await readCandidates(context.files, context.run)
      const { records, unresolved: unverified } = findingsDocument(candidates)
      const known = new Set(candidates.map(candidate => candidate.fingerprint))
      const orphaned = [...new Set(context.ledger.flatMap(unit => unit.result_fingerprints.filter(fingerprint => !known.has(fingerprint))))]
      const unresolved = [...new Set([...unverified, ...orphaned])]
      const open = context.ledger.filter(unit => ['planned', 'in_progress', 'blocked', 'deferred'].includes(unit.status)).map(unit => unit.coverage_id)
      const incomplete = unresolved.length > 0 || open.length > 0 || args.incomplete_reason !== undefined
      const reason = args.incomplete_reason
        ?? (unresolved.length > 0 ? 'unvalidated candidates: ' + unresolved.join(', ')
          : open.length > 0 ? 'non-terminal coverage units: ' + open.join(', ') : null)
      await writeFindings(context.files, context.run, records)
      await writeLedger(context.files, context.run, context.ledger)
      const next = await updateState(context.files, context.run, current => {
        current.stage = 'reporting'
        current.run_status = incomplete ? 'incomplete' : 'in_progress'
        current.incomplete_reason = incomplete ? reason : null
        return current
      })
      await writeRunMetadata(context.files, context.run, next, context.ledger, candidates)
      const expected = Object.fromEntries(REPORT_DOCUMENT.map(document => [document, expectedFingerprints(document, records) as string[]]))
      const documents = REPORT_DOCUMENT.map(document => REPORT_FILES[document])
      const lines = [
        'Finalized ' + String(records.length) + ' record(s); status ' + next.run_status + '.',
        ...unresolved.length === 0 ? [] : ['Unresolved: ' + unresolved.join(', ')],
        ...open.length === 0 ? [] : ['Open units: ' + open.join(', ')],
        'Report expectations: ' + JSON.stringify(expected),
        'Documents: ' + documents.join(', '),
      ]
      return { status: next.run_status, records: records.length, unresolved, open_units: open, expected, documents, content: lines.join('\n') }
    },
  }))
}
