import type { z } from "zod";

export type PermissionLevel = "AUTO" | "CONDITIONAL" | "HUMAN_APPROVAL" | "DENIED";

export type TaskStatus =
  | "PENDING"
  | "AWAITING_APPROVAL"
  | "RUNNING"
  | "COMPLETED"
  | "FAILED"
  | "DENIED"
  | "CANCELLED"
  | "TIMED_OUT";

export type OperationCategory = "shell" | "file" | "git" | "system";

export type ExecutionStatus = "completed" | "failed" | "timed_out" | "cancelled";

export type ApprovalStatus = "not_required" | "approved" | "denied" | "timed_out";

export interface OperationRequest {
  toolName: string;
  category: OperationCategory;
  input: Record<string, unknown>;
  workingDirectory: string;
  actor: string;
  sessionId?: string;
}

export interface ExecutionResult {
  status: ExecutionStatus;
  exitCode: number | null;
  stdout: string;
  stderr: string;
  stdoutTruncated: boolean;
  stderrTruncated: boolean;
  durationMs: number;
  data?: Record<string, unknown>;
  errorMessage?: string;
}

export interface ToolExecutionContext {
  taskId: string;
  sessionId?: string;
  actor: string;
  workingDirectory: string;
  signal: AbortSignal;
  timeoutMs: number;
  maxOutputBytes: number;
}

export interface ToolDefinition<TInputSchema extends z.ZodType = z.ZodType> {
  name: string;
  description: string;
  category: OperationCategory;
  defaultPermission: PermissionLevel;
  inputSchema: TInputSchema;
  execute: (
    input: z.infer<TInputSchema>,
    context: ToolExecutionContext,
  ) => Promise<ExecutionResult>;
}

export interface TaskRecord {
  id: string;
  sessionId: string | null;
  actor: string;
  toolName: string;
  category: OperationCategory;
  workingDirectory: string;
  status: TaskStatus;
  policyLevel: PermissionLevel | null;
  approvalStatus: ApprovalStatus;
  exitCode: number | null;
  durationMs: number | null;
  errorSummary: string | null;
  createdAt: string;
  updatedAt: string;
}

export interface AuditEventRecord {
  id: string;
  timestampUtc: string;
  sessionId: string | null;
  taskId: string;
  actor: string;
  operation: string;
  category: OperationCategory;
  sanitizedInput: string;
  workingDirectory: string;
  policyLevel: PermissionLevel;
  policyDecision: PermissionLevel;
  approvalStatus: ApprovalStatus;
  approvedBy: string | null;
  exitCode: number | null;
  durationMs: number | null;
  status: TaskStatus;
  errorSummary: string | null;
}
