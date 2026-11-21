import type { SynapseConfig } from "../../config/schema.js";
import { PolicyDeniedError } from "../../core/errors.js";
import type { ApprovalStatus, OperationRequest, PermissionLevel } from "../../core/types.js";
import { analyzeShellCommand } from "./command-analyzer.js";
import { redactValue } from "./redactor.js";
import {
  type ApprovalRequest,
  type ApprovalResponse,
  AUTHORIZED_OPERATION_BRAND,
  type AuthorizedOperation,
  type IApprovalHandler,
  type IPolicyEngine,
  type PolicyEvaluationResult,
} from "./types.js";
import { assertWorkingDirectoryAllowed } from "./workspace-guard.js";

function deepFreeze<T>(value: T): T {
  if (value === null || typeof value !== "object") {
    return value;
  }
  Object.freeze(value);
  for (const nested of Object.values(value as Record<string, unknown>)) {
    if (nested !== null && typeof nested === "object" && !Object.isFrozen(nested)) {
      deepFreeze(nested);
    }
  }
  return value;
}

function snapshotRequest(request: OperationRequest): Readonly<OperationRequest> {
  return deepFreeze(structuredClone(request));
}

/**
 * Default fail-closed approval handler used when no interactive operator is attached.
 */
export class NonInteractiveApprovalHandler implements IApprovalHandler {
  public async requestApproval(
    _request: ApprovalRequest,
    _signal?: AbortSignal,
  ): Promise<ApprovalResponse> {
    return {
      approved: false,
      approvedBy: null,
      reason: "Approval required but no interactive approval handler is available (fail-closed)",
    };
  }
}

export interface PolicyEngineOptions {
  workspaceDir: string;
  securityConfig: SynapseConfig["security"];
  approvalHandler?: IApprovalHandler;
}

export class PolicyEngine implements IPolicyEngine {
  private readonly workspaceDir: string;
  private readonly securityConfig: SynapseConfig["security"];
  private readonly approvalHandler: IApprovalHandler;

  constructor(options: PolicyEngineOptions) {
    this.workspaceDir = options.workspaceDir;
    this.securityConfig = options.securityConfig;
    this.approvalHandler = options.approvalHandler ?? new NonInteractiveApprovalHandler();
  }

  public async evaluateAndAuthorize(
    taskId: string,
    request: OperationRequest,
    hooks?: { onAwaitingApproval?: (req: ApprovalRequest) => void; signal?: AbortSignal },
  ): Promise<PolicyEvaluationResult> {
    // Freeze an immutable snapshot immediately to eliminate TOCTOU mutation attacks
    const frozenRequest = snapshotRequest(request);

    let canonicalWorkingDirectory: string;
    let insideWorkspace: boolean;
    try {
      const validation = assertWorkingDirectoryAllowed(
        this.workspaceDir,
        frozenRequest.workingDirectory,
        this.securityConfig.allowOutsideWorkspace,
      );
      canonicalWorkingDirectory = validation.canonicalPath;
      insideWorkspace = validation.insideWorkspace;
    } catch (error) {
      const reason =
        error instanceof PolicyDeniedError
          ? error.message
          : "Working directory failed workspace boundary validation";
      return {
        allowed: false,
        policyLevel: "DENIED",
        policyDecision: "DENIED",
        approvalStatus: "not_required",
        approvedBy: null,
        reasons: [reason],
        detectedRisks: ["workspace_escape"],
      };
    }

    const classification = this.classifyOperation(frozenRequest, insideWorkspace);

    if (classification.level === "DENIED") {
      return {
        allowed: false,
        policyLevel: "DENIED",
        policyDecision: "DENIED",
        approvalStatus: "not_required",
        approvedBy: null,
        reasons: classification.reasons,
        detectedRisks: classification.detectedRisks,
      };
    }

    if (classification.level === "AUTO") {
      const authorized: AuthorizedOperation = deepFreeze({
        [AUTHORIZED_OPERATION_BRAND]: true,
        taskId,
        request: frozenRequest,
        canonicalWorkingDirectory,
        policyLevel: "AUTO",
        policyDecision: "AUTO",
        approvalStatus: "not_required",
        approvedBy: null,
        reasons: [...classification.reasons],
      });
      return { allowed: true, authorized };
    }

    if (hooks?.signal?.aborted) {
      return {
        allowed: false,
        policyLevel: classification.level,
        policyDecision: "DENIED",
        approvalStatus: "denied",
        approvedBy: null,
        reasons: [...classification.reasons, "Operation cancelled before approval"],
        detectedRisks: classification.detectedRisks,
      };
    }

    // CONDITIONAL (in baseline) and HUMAN_APPROVAL require explicit approval
    const approvalRequest: ApprovalRequest = {
      taskId,
      actor: frozenRequest.actor,
      toolName: frozenRequest.toolName,
      category: frozenRequest.category,
      workingDirectory: canonicalWorkingDirectory,
      sanitizedInput: redactValue(frozenRequest.input) as Record<string, unknown>,
      permissionLevel: classification.level,
      reasons: classification.reasons,
      detectedRisks: classification.detectedRisks,
    };

    hooks?.onAwaitingApproval?.(approvalRequest);

    const response = await this.approvalHandler.requestApproval(approvalRequest, hooks?.signal);
    const approvalStatus: ApprovalStatus = response.approved
      ? "approved"
      : response.timedOut
        ? "timed_out"
        : "denied";

    if (!response.approved || hooks?.signal?.aborted) {
      const denialReasons = hooks?.signal?.aborted
        ? [...classification.reasons, "Operation cancelled during approval"]
        : response.reason
          ? [...classification.reasons, response.reason]
          : [...classification.reasons, "Operation denied by operator"];
      return {
        allowed: false,
        policyLevel: classification.level,
        policyDecision: "DENIED",
        approvalStatus: hooks?.signal?.aborted ? "denied" : approvalStatus,
        approvedBy: response.approvedBy,
        reasons: denialReasons,
        detectedRisks: classification.detectedRisks,
      };
    }

    const authorized: AuthorizedOperation = deepFreeze({
      [AUTHORIZED_OPERATION_BRAND]: true,
      taskId,
      request: frozenRequest,
      canonicalWorkingDirectory,
      policyLevel: classification.level,
      policyDecision: classification.level,
      approvalStatus: "approved",
      approvedBy: response.approvedBy ?? "human-operator",
      reasons: [...classification.reasons],
    });

    return { allowed: true, authorized };
  }

  private classifyOperation(
    request: Readonly<OperationRequest>,
    insideWorkspace: boolean,
  ): {
    level: PermissionLevel;
    reasons: string[];
    detectedRisks: string[];
  } {
    let base: { level: PermissionLevel; reasons: string[]; detectedRisks: string[] };

    if (request.category === "shell" && request.toolName === "shell.exec") {
      const rawCommand = typeof request.input.command === "string" ? request.input.command : "";
      const analysis = analyzeShellCommand(rawCommand, this.securityConfig.allowedShellCommands);
      base = {
        level: analysis.level,
        reasons: analysis.reasons,
        detectedRisks: analysis.detectedRisks,
      };
    } else if (request.category === "file" && request.toolName === "file.delete") {
      // D-06: Single file deletion defaults to HUMAN_APPROVAL
      base = {
        level: this.securityConfig.singleFileDeletePermission,
        reasons: ["Single file deletion requires human approval by policy (D-06)"],
        detectedRisks: ["file_deletion"],
      };
    } else {
      // RNF-01: Strict deny-by-default for unmapped/unknown operations
      return {
        level: "DENIED",
        reasons: [`Unmapped operation '${request.toolName}' is denied by default policy`],
        detectedRisks: ["unmapped_operation"],
      };
    }

    // Operations outside workspace (when explicitly enabled by config) can never run as AUTO
    if (!insideWorkspace && base.level !== "DENIED") {
      return {
        level: "HUMAN_APPROVAL",
        reasons: [...base.reasons, "Operation targets directory outside workspace"],
        detectedRisks: [...base.detectedRisks, "outside_workspace"],
      };
    }

    return base;
  }
}
