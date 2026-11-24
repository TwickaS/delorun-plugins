/**
 * `audit_candidates`: read the candidate store and its verification history.
 * The coordinator uses it to choose validation work and to write the report; a
 * candidate that is not final-verified is never a finding.
 * @module @delorun/plugin-security-audit/tools/candidates
 */
import type { Context } from '@deepseek-ai/cordis'
import type { Agent } from '@deepseek-ai/dsh-agent'
import { defineTool } from '@deepseek-ai/dsh-tools'
import type { ToolRunContext } from '@deepseek-ai/dsh-tools'
import type { Config } from '../config.ts'
import { readCandidates } from '../candidates.ts'
import { jsonArray } from './json.ts'
import { runContext } from '../run-context.ts'

/**
 * Register `audit_candidates`.
 * @param ctx - the plugin context.
 * @param config - the mounted row's configuration.
 */
export function registerCandidatesTool(ctx: Context, config: Config): void {
  ctx.tools.register(defineTool({
    name: 'audit_candidates',
    presentCall: args => ({ card: 'generic', title: 'Audit candidates', kind: 'other', rawInput: args }),
    description: 'List candidate records and their independent verification history, or read one fingerprint. Use it to choose validation work and to write the report; never infer a finding from a candidate that is not final-verified.',
    parameters: {
      action: { type: 'string', required: true, enum: ['list', 'get'], description: 'list every candidate, or read one fingerprint.' },
      fingerprint: { type: 'string', description: 'The candidate fingerprint for action=get.' },
      status: { type: 'string', enum: ['proposed', 'confirmed', 'needs_validation', 'rejected', 'all'], description: 'Filter for action=list.' },
    },
    output: {
      schema: {
        type: 'object', additionalProperties: false,
        properties: {
          total: { type: 'integer', required: true },
          candidates: { type: 'array', required: true, items: { type: 'object', additionalProperties: true } },
          content: { type: 'string', required: true },
        },
      },
      render: (_args, value) => [{ type: 'text', text: value.content }],
    },
    async execute(args, exec: ToolRunContext) {
      if (exec.agent === undefined) throw new Error('the audit tools need an owning agent session')
      const agent: Agent = exec.agent
      const context = await runContext(ctx, agent, exec.signal, config.runsDir)
      const candidates = await readCandidates(context.files, context.run)
      const found = args.action === 'get'
        ? candidates.filter(candidate => candidate.fingerprint === args.fingerprint)
        : args.status === undefined || args.status === 'all' ? candidates : candidates.filter(candidate => candidate.status === args.status)
      const summary = found.map(candidate => candidate.fingerprint + ' · ' + candidate.status + (candidate.final_verified ? ' · final-verified' : '') + ' · ' + String(candidate.record.title ?? '')).join('\n')
      return { total: found.length, candidates: jsonArray(found), content: found.length === 0 ? 'No candidate matches.' : summary + '\n\n' + JSON.stringify(found, undefined, 2) }
    },
  }))
}
