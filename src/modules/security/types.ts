import crypto from "node:crypto";
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
  readonly mutating: boolean;
  readonly inputDigest: string;
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

export type RevalidationResult =
  | { valid: true }
  | { valid: false; reasons: string[]; detectedRisks: string[] };

export interface IPolicyEngine {
  evaluateAndAuthorize(
    taskId: string,
    request: OperationRequest,
    hooks?: {
      onAwaitingApproval?: (req: ApprovalRequest) => void;
      signal?: AbortSignal;
    },
  ): Promise<PolicyEvaluationResult>;
  revalidateAuthorized(authorized: AuthorizedOperation): RevalidationResult;
}

function canonicalStringify(value: unknown): string {
  if (value === null || typeof value !== "object") {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map((item) => canonicalStringify(item)).join(",")}]`;
  }
  const entries = Object.entries(value as Record<string, unknown>).sort(([a], [b]) =>
    a.localeCompare(b),
  );
  return `{${entries.map(([k, v]) => `${JSON.stringify(k)}:${canonicalStringify(v)}`).join(",")}}`;
}

export function computeAuthorizationDigest(params: {
  taskId: string;
  toolName: string;
  category: OperationRequest["category"];
  canonicalWorkingDirectory: string;
  input: Record<string, unknown>;
}): string {
  const payload = canonicalStringify({
    taskId: params.taskId,
    toolName: params.toolName,
    category: params.category,
    canonicalWorkingDirectory: params.canonicalWorkingDirectory,
    input: params.input,
  });
  return crypto.createHash("sha256").update(payload, "utf8").digest("hex");
}

export function isAuthorizedOperation(value: unknown): value is AuthorizedOperation {
  return (
    typeof value === "object" &&
    value !== null &&
    AUTHORIZED_OPERATION_BRAND in value &&
    (value as Record<symbol, unknown>)[AUTHORIZED_OPERATION_BRAND] === true
  );
}
