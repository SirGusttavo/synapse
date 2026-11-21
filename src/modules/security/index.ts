export {
  analyzeShellCommand,
  type CommandAnalysisResult,
} from "./command-analyzer.js";
export { isBlockedEnvKey, sanitizeEnvironment } from "./env-sanitizer.js";
export {
  isMutatingOperation,
  NonInteractiveApprovalHandler,
  PolicyEngine,
  type PolicyEngineOptions,
} from "./policy-engine.js";
export { isSensitiveKey, redactText, redactValue } from "./redactor.js";
export {
  type ApprovalRequest,
  type ApprovalResponse,
  AUTHORIZED_OPERATION_BRAND,
  type AuthorizedOperation,
  computeAuthorizationDigest,
  type IApprovalHandler,
  type IPolicyEngine,
  isAuthorizedOperation,
  type PolicyEvaluationResult,
  type RevalidationResult,
} from "./types.js";
export {
  assertWorkingDirectoryAllowed,
  isPathWithinWorkspace,
  isSensitiveFilePath,
  type WorkingDirectoryValidation,
} from "./workspace-guard.js";
