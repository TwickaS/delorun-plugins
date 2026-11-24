/**
 * `audit_skill`: the coordinator's read access to the vendored skill pack, so a
 * block reaches a brief by exact text rather than from the model's memory.
 * @module delorun-plugin-security-audit/tools/skill
 */
import type { Context } from '@deepseek-ai/cordis'
import { defineTool } from '@deepseek-ai/dsh-tools'
import { blockNames, skillBlock, skillFile, skillFileNames } from '../skill.ts'

const ACTIONS = ['files', 'file', 'block', 'blocks'] as const

/**
 * Register `audit_skill`.
 * @param ctx - the plugin context.
 */
export function registerSkillTool(ctx: Context): void {
  ctx.tools.register(defineTool({
    name: 'audit_skill',
    presentCall: args => ({ card: 'generic', title: 'Read the audit skill: ' + args.action, kind: 'other', rawInput: args }),
    description: 'Read the vendored security-audit skill: its file names, one file, one FILE.md#Block, or every block name in a file. Use it before briefing a role, and copy the exact text it returns.',
    parameters: {
      action: { type: 'string', required: true, enum: [...ACTIONS], description: 'files lists the pack, file returns one file, block returns one block, blocks lists a file block names.' },
      name: { type: 'string', description: 'The file name for action=file or action=blocks.' },
      ref: { type: 'string', description: 'The FILE.md#Name reference for action=block.' },
    },
    output: {
      schema: {
        type: 'object', additionalProperties: false,
        properties: {
          action: { type: 'string', required: true },
          names: { type: 'array', required: true, items: { type: 'string' } },
          content: { type: 'string', required: true },
        },
      },
      render: (_args, value) => [{ type: 'text', text: value.content }],
    },
    execute(args) {
      switch (args.action) {
        case 'files': {
          const names = skillFileNames()
          return Promise.resolve({ action: args.action, names, content: names.join('\n') })
        }
        case 'file': {
          if (args.name === undefined) throw new Error('action=file needs name')
          const content = skillFile(args.name)
          return Promise.resolve({ action: args.action, names: [args.name], content })
        }
        case 'block': {
          if (args.ref === undefined) throw new Error('action=block needs ref, such as HUNTING.md#Parent consolidation and Coverage-critic waves')
          const content = skillBlock(args.ref)
          return Promise.resolve({ action: args.action, names: [args.ref], content })
        }
        case 'blocks': {
          if (args.name === undefined) throw new Error('action=blocks needs name')
          const names = blockNames(args.name)
          return Promise.resolve({ action: args.action, names, content: names.join('\n') })
        }
      }
    },
  }))
}
