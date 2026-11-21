import type { SynapseConfig } from "../../config/schema.js";
import { PolicyDeniedError } from "../../core/errors.js";
import type { ApprovalStatus, OperationRequest, PermissionLevel } from "../../core/types.js";
import { analyzeShellCommand } from "./command-analyzer.js";
import { redactValue } from "./redactor.js";
import {
  type ApprovalRequest,
  type ApprovalResponse,
  AUTHORIZED_OPERATION_BRAND,
  type IApprovalHandler,
  type IPolicyEngine,
  type PolicyEvaluationResult,
} from "./types.js";
import { assertWorkingDirectoryAllowed } from "./workspace-guard.js";

/**
 * Default fail-closed approval handler used when no interactive operator is attached.
 */
export class NonInteractiveApprovalHandler implements IApprovalHandler {
  public async requestApproval(_request: ApprovalRequest): Promise<ApprovalResponse> {
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
    hooks?: { onAwaitingApproval?: (req: ApprovalRequest) => void },
  ): Promise<PolicyEvaluationResult> {
    let canonicalWorkingDirectory: string;
    try {
      canonicalWorkingDirectory = assertWorkingDirectoryAllowed(
        this.workspaceDir,
        request.workingDirectory,
        this.securityConfig.allowOutsideWorkspace,
      );
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

    const classification = this.classifyOperation(request);

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
      return {
        allowed: true,
        authorized: {
          [AUTHORIZED_OPERATION_BRAND]: true,
          taskId,
          request,
          canonicalWorkingDirectory,
          policyLevel: "AUTO",
          policyDecision: "AUTO",
          approvalStatus: "not_required",
          approvedBy: null,
          reasons: classification.reasons,
        },
      };
    }

    // CONDITIONAL (in strict baseline) and HUMAN_APPROVAL require explicit approval
    const approvalRequest: ApprovalRequest = {
      taskId,
      actor: request.actor,
      toolName: request.toolName,
      category: request.category,
      workingDirectory: canonicalWorkingDirectory,
      sanitizedInput: redactValue(request.input) as Record<string, unknown>,
      permissionLevel: classification.level,
      reasons: classification.reasons,
      detectedRisks: classification.detectedRisks,
    };

    hooks?.onAwaitingApproval?.(approvalRequest);

    const response = await this.approvalHandler.requestApproval(approvalRequest);
    const approvalStatus: ApprovalStatus = response.approved
      ? "approved"
      : response.timedOut
        ? "timed_out"
        : "denied";

    if (!response.approved) {
      const denialReasons = response.reason
        ? [...classification.reasons, response.reason]
        : [...classification.reasons, "Operation denied by operator"];
      return {
        allowed: false,
        policyLevel: classification.level,
        policyDecision: "DENIED",
        approvalStatus,
        approvedBy: response.approvedBy,
        reasons: denialReasons,
        detectedRisks: classification.detectedRisks,
      };
    }

    return {
      allowed: true,
      authorized: {
        [AUTHORIZED_OPERATION_BRAND]: true,
        taskId,
        request,
        canonicalWorkingDirectory,
        policyLevel: classification.level,
        policyDecision: classification.level,
        approvalStatus: "approved",
        approvedBy: response.approvedBy ?? "human-operator",
        reasons: classification.reasons,
      },
    };
  }

  private classifyOperation(request: OperationRequest): {
    level: PermissionLevel;
    reasons: string[];
    detectedRisks: string[];
  } {
    if (request.category === "shell") {
      const rawCommand = typeof request.input.command === "string" ? request.input.command : "";
      const analysis = analyzeShellCommand(rawCommand, this.securityConfig.allowedShellCommands);
      return {
        level: analysis.level,
        reasons: analysis.reasons,
        detectedRisks: analysis.detectedRisks,
      };
    }

    // D-06: Single file deletion defaults to HUMAN_APPROVAL
    if (request.category === "file" && request.toolName === "file.delete") {
      return {
        level: this.securityConfig.singleFileDeletePermission,
        reasons: ["Single file deletion requires human approval by policy (D-06)"],
        detectedRisks: ["file_deletion"],
      };
    }

    // Default-deny / escalate for any unknown operation not explicitly mapped
    return {
      level: "HUMAN_APPROVAL",
      reasons: [`Unmapped operation '${request.toolName}' requires explicit approval`],
      detectedRisks: ["unmapped_operation"],
    };
  }
}
