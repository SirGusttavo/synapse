import type { ApprovalStatus, OperationRequest, PermissionLevel } from "../../core/types.js";

export const AUTHORIZED_OPERATION_BRAND = Symbol("synapse.authorized_operation");

export interface ApprovalRequest {
  taskId: string;
  actor: string;
  toolName: string;
  category: OperationRequest["category"];
  workingDirectory: string;
  sanitizedInput: Record<string, unknown>;
  permissionLevel: Extract<PermissionLevel, "CONDITIONAL" | "HUMAN_APPROVAL">;
  reasons: string[];
  detectedRisks: string[];
}

export interface ApprovalResponse {
  approved: boolean;
  approvedBy: string | null;
  reason?: string;
  timedOut?: boolean;
}

export interface IApprovalHandler {
  requestApproval(request: ApprovalRequest, signal?: AbortSignal): Promise<ApprovalResponse>;
}

export interface AuthorizedOperation {
  readonly [AUTHORIZED_OPERATION_BRAND]: true;
  readonly taskId: string;
  readonly request: Readonly<OperationRequest>;
  readonly canonicalWorkingDirectory: string;
  readonly policyLevel: PermissionLevel;
  readonly policyDecision: PermissionLevel;
  readonly approvalStatus: ApprovalStatus;
  readonly approvedBy: string | null;
  readonly reasons: readonly string[];
}

export type PolicyEvaluationResult =
  | {
      allowed: true;
      authorized: AuthorizedOperation;
    }
  | {
      allowed: false;
      policyLevel: PermissionLevel;
      policyDecision: "DENIED";
      approvalStatus: ApprovalStatus;
      approvedBy: string | null;
      reasons: string[];
      detectedRisks: string[];
    };

export interface IPolicyEngine {
  evaluateAndAuthorize(
    taskId: string,
    request: OperationRequest,
    hooks?: {
      onAwaitingApproval?: (req: ApprovalRequest) => void;
      signal?: AbortSignal;
    },
  ): Promise<PolicyEvaluationResult>;
}

export function isAuthorizedOperation(value: unknown): value is AuthorizedOperation {
  return (
    typeof value === "object" &&
    value !== null &&
    AUTHORIZED_OPERATION_BRAND in value &&
    (value as Record<symbol, unknown>)[AUTHORIZED_OPERATION_BRAND] === true
  );
}
