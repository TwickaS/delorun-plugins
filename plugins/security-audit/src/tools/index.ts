/**
 * Register every coordinator tool the Security audit chat mode exposes: intake,
 * the skill pack, the architecture summary, the coverage ledger, the candidate
 * store, the denial tests, finalization, the report documents and the terminal
 * state. Delegation registers its own tool beside these.
 * @module delorun-plugin-security-audit/tools
 */
import type { Context } from '@deepseek-ai/cordis'
import type { Config } from '../config.ts'
import { registerArchitectureTool } from './architecture.ts'
import { registerCandidatesTool } from './candidates.ts'
import { registerCompleteTool } from './complete.ts'
import { registerDenialsTool } from './denials.ts'
import { registerFinalizeTool } from './finalize.ts'
import { registerInitTool } from './init.ts'
import { registerLedgerTool } from './ledger.ts'
import { registerReportTool } from './report.ts'
import { registerSkillTool } from './skill.ts'

/**
 * Register the audit tools on one mounted row.
 * @param ctx - the plugin context.
 * @param config - the mounted row's configuration.
 */
export function registerAuditTools(ctx: Context, config: Config): void {
  registerInitTool(ctx, config)
  registerSkillTool(ctx)
  registerArchitectureTool(ctx, config)
  registerLedgerTool(ctx, config)
  registerCandidatesTool(ctx, config)
  registerDenialsTool(ctx, config)
  registerFinalizeTool(ctx, config)
  registerReportTool(ctx, config)
  registerCompleteTool(ctx, config)
}
