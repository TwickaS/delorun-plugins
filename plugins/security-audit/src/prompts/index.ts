/**
 * The prompt composer and result schemas for every delegated role. The
 * delegation tool imports one entry point so a brief and its enforced schema
 * always travel together.
 * @module @delorun/plugin-security-audit/prompts
 */
export {
  MAX_ARTIFACT_BYTES,
  MAX_PROMOTED_BYTES,
  criticBrief,
  finalVerifierBrief,
  hunterBrief,
  reconBrief,
  verifierBrief,
} from './briefs.ts'
export type { BriefContext, BriefRun, CandidateSummary, CandidateView, CarriedRecord } from './briefs.ts'
export { CRITIC_RESULT, FINAL_VERIFIER_RESULT, HUNTER_RESULT, RECON_RESULT, VERIFIER_RESULT } from './schemas.ts'
