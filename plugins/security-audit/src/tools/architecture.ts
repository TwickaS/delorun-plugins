/**
 * `audit_architecture`: the coordinator writes the reconnaissance synthesis that
 * every later brief carries. RECONNAISSANCE.md caps it at about 1,000 words and
 * keeps assignment detail in the ledger, so this tool refuses a summary past the
 * cap rather than letting one grow into a second ledger.
 * @module @delorun/plugin-security-audit/tools/architecture
 */
import type { Context } from '@deepseek-ai/cordis'
import type { Agent } from '@deepseek-ai/dsh-agent'
import { defineTool } from '@deepseek-ai/dsh-tools'
import type { ToolRunContext } from '@deepseek-ai/dsh-tools'
import { readCandidates } from '../candidates.ts'
import type { Config } from '../config.ts'
import { writeRunMetadata } from '../report.ts'
import { requireMutable, runContext } from '../run-context.ts'
import { ARCHITECTURE_FILE, inRun } from '../store.ts'

/** The most words the summary may hold (RECONNAISSANCE.md, Architecture summary). */
const WORD_CAP = 1_000

/**
 * Count the words in Markdown prose.
 * @param text - the summary.
 * @returns its word count.
 */
function words(text: string): number {
  return text.trim().split(/\s+/u).filter(word => word.length > 0).length
}

/**
 * Register `audit_architecture`.
 * @param ctx - the plugin context.
 * @param config - the mounted row's configuration.
 */
export function registerArchitectureTool(ctx: Context, config: Config): void {
  ctx.tools.register(defineTool({
    name: 'audit_architecture',
    presentCall: () => ({ card: 'generic', title: 'Write the architecture summary', kind: 'other' }),
    description: 'Write architecture.md, the reconnaissance synthesis every role brief carries: product, principals, trust boundaries and their controls, entry surfaces, offline build limits, baseline, prior gaps and companion selection. Call it after reconnaissance and before seeding coverage units.',
    parameters: {
      content: { type: 'string', required: true, description: 'The complete Markdown summary, at most 1,000 words. Keep assignment detail in the ledger, not here.' },
    },
    output: {
      schema: {
        type: 'object', additionalProperties: false,
        properties: {
          path: { type: 'string', required: true },
          words: { type: 'integer', required: true },
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
      if (args.content.trim().length === 0) throw new Error('the architecture summary must not be empty')
      const count = words(args.content)
      if (count > WORD_CAP) {
        throw new Error('the architecture summary is ' + String(count) + ' words; RECONNAISSANCE.md caps it at ' + String(WORD_CAP) + '. Move per-unit detail into the coverage ledger and keep the boundary, control and entry-surface facts here')
      }
      const path = inRun(context.run, ARCHITECTURE_FILE)
      const text = args.content.trimEnd() + '\n'
      await context.files.write(path, text)
      await writeRunMetadata(context.files, context.run, context.state, context.ledger, await readCandidates(context.files, context.run))
      return { path, words: count, bytes: Buffer.byteLength(text, 'utf8'), content: 'Wrote the architecture summary (' + String(count) + ' words) to ' + path + '.' }
    },
  }))
}
