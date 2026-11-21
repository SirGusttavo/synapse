import crypto from "node:crypto";
import type { Logger } from "pino";
import type { SynapseEventBus } from "../../core/events.js";
import type {
  ApprovalStatus,
  AuditEventRecord,
  OperationCategory,
  PermissionLevel,
  TaskStatus,
} from "../../core/types.js";
import type { AuditQueryFilter, IAuditRepository } from "../../storage/index.js";
import { redactText, redactValue } from "../security/redactor.js";

export interface RecordAuditInput {
  sessionId?: string | null;
  taskId: string;
  actor: string;
  operation: string;
  category: OperationCategory;
  input: Record<string, unknown>;
  workingDirectory: string;
  policyLevel: PermissionLevel;
  policyDecision: PermissionLevel;
  approvalStatus: ApprovalStatus;
  approvedBy?: string | null;
  exitCode?: number | null;
  durationMs?: number | null;
  status: TaskStatus;
  errorSummary?: string | null;
}

export interface IAuditLogger {
  record(entry: RecordAuditInput): AuditEventRecord;
  query(filter?: AuditQueryFilter): AuditEventRecord[];
}

export class AuditService implements IAuditLogger {
  private readonly repository: IAuditRepository;
  private readonly logger: Logger;
  private readonly eventBus?: SynapseEventBus;

  constructor(options: {
    repository: IAuditRepository;
    logger: Logger;
    eventBus?: SynapseEventBus;
  }) {
    this.repository = options.repository;
    this.logger = options.logger;
    this.eventBus = options.eventBus;
  }

  public record(entry: RecordAuditInput): AuditEventRecord {
    const sanitizedInputObj = redactValue(entry.input);
    const sanitizedError = entry.errorSummary ? redactText(entry.errorSummary) : null;

    const record: AuditEventRecord = {
      id: crypto.randomUUID(),
      timestampUtc: new Date().toISOString(),
      sessionId: entry.sessionId ?? null,
      taskId: entry.taskId,
      actor: entry.actor,
      operation: entry.operation,
      category: entry.category,
      sanitizedInput: JSON.stringify(sanitizedInputObj),
      workingDirectory: entry.workingDirectory,
      policyLevel: entry.policyLevel,
      policyDecision: entry.policyDecision,
      approvalStatus: entry.approvalStatus,
      approvedBy: entry.approvedBy ?? null,
      exitCode: entry.exitCode ?? null,
      durationMs: entry.durationMs ?? null,
      status: entry.status,
      errorSummary: sanitizedError,
    };

    // Persist first; storage errors propagate explicitly (RNF-07)
    this.repository.append(record);

    this.logger.info(
      {
        auditId: record.id,
        taskId: record.taskId,
        actor: record.actor,
        operation: record.operation,
        category: record.category,
        policyLevel: record.policyLevel,
        policyDecision: record.policyDecision,
        approvalStatus: record.approvalStatus,
        status: record.status,
        exitCode: record.exitCode,
        durationMs: record.durationMs,
        workingDirectory: record.workingDirectory,
        errorSummary: record.errorSummary,
      },
      "audit_event_recorded",
    );

    this.eventBus?.emit("audit:recorded", record);

    return record;
  }

  public query(filter?: AuditQueryFilter): AuditEventRecord[] {
    return this.repository.query(filter);
  }
}
