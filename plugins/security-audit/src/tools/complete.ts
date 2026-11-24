/**
 * `audit_complete`: the terminal state. It marks a run complete only when the
 * three report documents, both skill validators and every candidate state
 * agree, and otherwise records the exact reason the run is incomplete.
 * @module @delorun/plugin-security-audit/tools/complete
 */
import type { Context } from '@deepseek-ai/cordis'
import type { Agent } from '@deepseek-ai/dsh-agent'
import { defineTool } from '@deepseek-ai/dsh-tools'
import type { ToolRunContext } from '@deepseek-ai/dsh-tools'
import type { Config } from '../config.ts'
import { readCandidates } from '../candidates.ts'
import { completionProblems, writeRunMetadata } from '../report.ts'
import { runContext } from '../run-context.ts'
import { updateState } from '../store.ts'

/**
 * Register `audit_complete`.
 * @param ctx - the plugin context.
 * @param config - the mounted row's configuration.
 */
export function registerCompleteTool(ctx: Context, config: Config): void {
  ctx.tools.register(defineTool({
    name: 'audit_complete',
    presentCall: () => ({ card: 'generic', title: 'Complete security audit', kind: 'other' }),
    description: 'Mark a run complete or incomplete, but only after the three report documents, both skill validators and every candidate state agree. Returns where the run lives.',
    parameters: {
      incomplete_reason: { type: 'string', description: 'Set an incomplete terminal state with this exact reason.' },
    },
    output: {
      schema: {
        type: 'object', additionalProperties: false,
        properties: {
          status: { type: 'string', required: true },
          reason: { oneOf: [{ type: 'string' }, { type: 'null' }], required: true },
          directory: { type: 'string', required: true },
          warning: { type: 'string', required: true },
          content: { type: 'string', required: true },
        },
      },
      render: (_args, value) => [{ type: 'text', text: value.content }],
    },
    async execute(args, exec: ToolRunContext) {
      if (exec.agent === undefined) throw new Error('the audit tools need an owning agent session')
      const agent: Agent = exec.agent
      const context = await runContext(ctx, agent, exec.signal, config.runsDir)
      let state = context.state
      if (args.incomplete_reason !== undefined) {
        if (args.incomplete_reason.trim().length === 0) throw new Error('incomplete_reason must not be empty')
        state = await updateState(context.files, context.run, current => {
          current.run_status = 'incomplete'
          current.incomplete_reason = args.incomplete_reason ?? null
          return current
        })
      }
      const candidates = await readCandidates(context.files, context.run)
      const problems = await completionProblems(context.files, context.run, state, context.ledger, candidates)
      if (problems.length > 0) throw new Error('the run is not ready to end:\n' + problems.join('\n'))
      const status = state.run_status === 'incomplete' ? 'incomplete' : 'complete'
      const completedAt = new Date().toISOString()
      state = await updateState(context.files, context.run, current => {
        current.run_status = status
        current.stage = 'done'
        return current
      })
      await writeRunMetadata(context.files, context.run, state, context.ledger, candidates, completedAt)
      const reason = state.incomplete_reason
      const warning = 'The run directory is git-ignored and may describe unfixed vulnerabilities. Copy a report into a private destination such as ops/ until the findings are fixed; never commit one into a repository with a public remote.'
      const lines = ['Run ' + status + '.' + (reason === null ? '' : ' Reason: ' + reason), 'Run directory: ' + context.run.dir, warning]
      return { status, reason, directory: context.run.dir, warning, content: lines.join('\n') }
    },
  }))
}
