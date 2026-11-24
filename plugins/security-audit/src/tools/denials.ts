/**
 * `audit_denial`: record the denial test a high or critical finding carries.
 *
 * The vendored `findings.json` schema is upstream's and strict, so a denial test cannot live on the record itself.
 * It lives in `denial-tests.json` beside the other run files, keyed by fingerprint, and `audit_finalize` refuses a
 * run whose high or critical findings have no test there. This tool is the only way to write that file.
 * @module delorun-plugin-security-audit/tools/denials
 */
import type { Context } from '@deepseek-ai/cordis'
import type { Agent } from '@deepseek-ai/dsh-agent'
import { defineTool } from '@deepseek-ai/dsh-tools'
import type { ToolRunContext } from '@deepseek-ai/dsh-tools'
import type { Config } from '../config.ts'
import { overallSeverityOf, readCandidates } from '../candidates.ts'
import { DENIAL_SEVERITIES, readDenialTests, writeDenialTest } from '../denials.ts'
import { requireMutable, runContext } from '../run-context.ts'

/**
 * Register `audit_denial`.
 * @param ctx - the plugin context.
 * @param config - the mounted row's configuration.
 */
export function registerDenialsTool(ctx: Context, config: Config): void {
  ctx.tools.register(defineTool({
    name: 'audit_denial',
    presentCall: args => ({ card: 'generic', title: 'Record a denial test', kind: 'other', rawInput: args }),
    description: 'Record the denial test a high or critical finding carries: the test that fails before the fix and passes after it. audit_finalize refuses a run whose high or critical findings have no test here, so record one for each before finalizing. Use action=list to see which findings still need one.',
    parameters: {
      action: { type: 'string', required: true, enum: ['record', 'list'], description: 'record one test, or list the tests the run holds and the findings that still need one.' },
      fingerprint: { type: 'string', description: 'The confirmed finding fingerprint the test proves, for action=record.' },
      file: { type: 'string', description: 'The test file, repository-relative, for action=record.' },
      name: { type: 'string', description: 'The test name as the runner reports it, for action=record.' },
      assertion: { type: 'string', description: 'The assertion that fails before the fix and passes after it, for action=record.' },
      state: { type: 'string', enum: ['proven', 'proposal'], description: 'proven when the role ran it and saw the failure then the pass; proposal when it could not run it in its copy and states the test it would write.' },
      observed: { type: 'string', description: 'What the role observed, for state=proven: the failure before the fix and the pass after it.' },
    },
    output: {
      schema: {
        type: 'object', additionalProperties: false,
        properties: {
          recorded: { type: 'integer', required: true },
          missing: { type: 'array', required: true, items: { type: 'string' } },
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
      const confirmed = candidates.filter(candidate => candidate.final_verified && candidate.record.verdict === 'confirmed')
      if (args.action === 'record') {
        if (args.fingerprint === undefined) throw new Error('action=record needs the fingerprint of the finding the test proves')
        const candidate = confirmed.find(entry => entry.fingerprint === args.fingerprint)
        if (candidate === undefined) {
          throw new Error('no final-verified confirmed finding carries the fingerprint ' + JSON.stringify(args.fingerprint) + '; a denial test attaches to a confirmed finding, so verify the candidate first')
        }
        await writeDenialTest(context.files, context.run, {
          fingerprint: args.fingerprint,
          file: args.file,
          name: args.name,
          assertion: args.assertion,
          state: args.state,
          observed: args.observed,
        })
      }
      const tests = await readDenialTests(context.files, context.run)
      const held = new Set(tests.map(test => test.fingerprint))
      const missing = confirmed
        .filter(candidate => DENIAL_SEVERITIES.includes(overallSeverityOf(candidate.record)))
        .map(candidate => candidate.fingerprint)
        .filter(fingerprint => !held.has(fingerprint))
        .sort()
      const lines = [
        'Denial tests held: ' + String(tests.length) + '.',
        ...tests.length === 0 ? [] : tests.map(test => '  ' + test.fingerprint + ' · ' + test.state + ' · ' + test.file + ' · ' + test.name),
        ...missing.length === 0
          ? ['Every high or critical confirmed finding carries a denial test.']
          : ['Still needed for: ' + missing.join(', ') + '. Record one with audit_denial before audit_finalize, or lower the severity with the evidence that justifies it.'],
      ]
      return { recorded: tests.length, missing, content: lines.join('\n') }
    },
  }))
}
