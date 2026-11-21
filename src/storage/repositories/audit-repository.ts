import type { DatabaseSync, SQLInputValue } from "node:sqlite";
import { StorageError } from "../../core/errors.js";
import type {
  ApprovalStatus,
  AuditEventRecord,
  OperationCategory,
  PermissionLevel,
  TaskStatus,
} from "../../core/types.js";

export interface AuditQueryFilter {
  limit?: number;
  taskId?: string;
  status?: TaskStatus;
  operation?: string;
}

export interface IAuditRepository {
  append(event: AuditEventRecord): void;
  query(filter?: AuditQueryFilter): AuditEventRecord[];
}

interface AuditRow {
  id: string;
  timestamp_utc: string;
  session_id: string | null;
  task_id: string;
  actor: string;
  operation: string;
  category: string;
  sanitized_input: string;
  working_directory: string;
  policy_level: string;
  policy_decision: string;
  approval_status: string;
  approved_by: string | null;
  exit_code: number | null;
  duration_ms: number | null;
  status: string;
  error_summary: string | null;
}

function mapRowToAudit(row: AuditRow): AuditEventRecord {
  return {
    id: row.id,
    timestampUtc: row.timestamp_utc,
    sessionId: row.session_id,
    taskId: row.task_id,
    actor: row.actor,
    operation: row.operation,
    category: row.category as OperationCategory,
    sanitizedInput: row.sanitized_input,
    workingDirectory: row.working_directory,
    policyLevel: row.policy_level as PermissionLevel,
    policyDecision: row.policy_decision as PermissionLevel,
    approvalStatus: row.approval_status as ApprovalStatus,
    approvedBy: row.approved_by,
    exitCode: row.exit_code,
    durationMs: row.duration_ms,
    status: row.status as TaskStatus,
    errorSummary: row.error_summary,
  };
}

export class SqliteAuditRepository implements IAuditRepository {
  private readonly db: DatabaseSync;

  constructor(db: DatabaseSync) {
    this.db = db;
  }

  public append(event: AuditEventRecord): void {
    try {
      this.db
        .prepare(
          `INSERT INTO audit_events (
            id, timestamp_utc, session_id, task_id, actor, operation, category,
            sanitized_input, working_directory, policy_level, policy_decision,
            approval_status, approved_by, exit_code, duration_ms, status, error_summary
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        )
        .run(
          event.id,
          event.timestampUtc,
          event.sessionId,
          event.taskId,
          event.actor,
          event.operation,
          event.category,
          event.sanitizedInput,
          event.workingDirectory,
          event.policyLevel,
          event.policyDecision,
          event.approvalStatus,
          event.approvedBy,
          event.exitCode,
          event.durationMs,
          event.status,
          event.errorSummary,
        );
    } catch (error) {
      throw new StorageError(`Failed to append audit event ${event.id}`, {
        details: { eventId: event.id, taskId: event.taskId },
        cause: error,
      });
    }
  }

  public query(filter: AuditQueryFilter = {}): AuditEventRecord[] {
    try {
      const clauses: string[] = [];
      const params: SQLInputValue[] = [];

      if (filter.taskId) {
        clauses.push("task_id = ?");
        params.push(filter.taskId);
      }
      if (filter.status) {
        clauses.push("status = ?");
        params.push(filter.status);
      }
      if (filter.operation) {
        clauses.push("operation = ?");
        params.push(filter.operation);
      }

      const where = clauses.length > 0 ? `WHERE ${clauses.join(" AND ")}` : "";
      const limit = Math.max(1, Math.min(filter.limit ?? 50, 500));
      params.push(limit);

      const rows = this.db
        .prepare(`SELECT * FROM audit_events ${where} ORDER BY timestamp_utc DESC LIMIT ?`)
        .all(...params) as unknown as AuditRow[];

      return rows.map(mapRowToAudit);
    } catch (error) {
      throw new StorageError("Failed to query audit events", { cause: error });
    }
  }
}
