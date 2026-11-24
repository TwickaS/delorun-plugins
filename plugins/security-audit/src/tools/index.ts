/**
 * Register every coordinator tool the Security audit chat mode exposes: intake,
 * the skill pack, the coverage ledger, the candidate store, finalization, the
 * report documents and the terminal state. Delegation registers its own tool
 * beside these.
 * @module @delorun/plugin-security-audit/tools
 */
import type { Context } from '@deepseek-ai/cordis'
import type { Config } from '../config.ts'
import { registerCandidatesTool } from './candidates.ts'
import { registerCompleteTool } from './complete.ts'
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
  registerLedgerTool(ctx, config)
  registerCandidatesTool(ctx, config)
  registerFinalizeTool(ctx, config)
  registerReportTool(ctx, config)
  registerCompleteTool(ctx, config)
}
