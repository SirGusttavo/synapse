import type { DatabaseSync } from "node:sqlite";
import { StorageError } from "../../core/errors.js";
import type {
  ApprovalStatus,
  OperationCategory,
  PermissionLevel,
  TaskRecord,
  TaskStatus,
} from "../../core/types.js";

export interface ITaskRepository {
  create(task: TaskRecord): void;
  update(task: TaskRecord): void;
  findById(id: string): TaskRecord | null;
  listRecent(limit?: number): TaskRecord[];
}

interface TaskRow {
  id: string;
  session_id: string | null;
  actor: string;
  tool_name: string;
  category: string;
  working_directory: string;
  status: string;
  policy_level: string | null;
  approval_status: string;
  exit_code: number | null;
  duration_ms: number | null;
  error_summary: string | null;
  created_at: string;
  updated_at: string;
}

function mapRowToTask(row: TaskRow): TaskRecord {
  return {
    id: row.id,
    sessionId: row.session_id,
    actor: row.actor,
    toolName: row.tool_name,
    category: row.category as OperationCategory,
    workingDirectory: row.working_directory,
    status: row.status as TaskStatus,
    policyLevel: row.policy_level as PermissionLevel | null,
    approvalStatus: row.approval_status as ApprovalStatus,
    exitCode: row.exit_code,
    durationMs: row.duration_ms,
    errorSummary: row.error_summary,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
  };
}

export class SqliteTaskRepository implements ITaskRepository {
  private readonly db: DatabaseSync;

  constructor(db: DatabaseSync) {
    this.db = db;
  }

  public create(task: TaskRecord): void {
    try {
      this.db
        .prepare(
          `INSERT INTO tasks (
            id, session_id, actor, tool_name, category, working_directory,
            status, policy_level, approval_status, exit_code, duration_ms,
            error_summary, created_at, updated_at
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        )
        .run(
          task.id,
          task.sessionId,
          task.actor,
          task.toolName,
          task.category,
          task.workingDirectory,
          task.status,
          task.policyLevel,
          task.approvalStatus,
          task.exitCode,
          task.durationMs,
          task.errorSummary,
          task.createdAt,
          task.updatedAt,
        );
    } catch (error) {
      throw new StorageError(`Failed to insert task ${task.id}`, {
        details: { taskId: task.id },
        cause: error,
      });
    }
  }

  public update(task: TaskRecord): void {
    try {
      this.db
        .prepare(
          `UPDATE tasks SET
            status = ?,
            policy_level = ?,
            approval_status = ?,
            exit_code = ?,
            duration_ms = ?,
            error_summary = ?,
            updated_at = ?
          WHERE id = ?`,
        )
        .run(
          task.status,
          task.policyLevel,
          task.approvalStatus,
          task.exitCode,
          task.durationMs,
          task.errorSummary,
          task.updatedAt,
          task.id,
        );
    } catch (error) {
      throw new StorageError(`Failed to update task ${task.id}`, {
        details: { taskId: task.id },
        cause: error,
      });
    }
  }

  public findById(id: string): TaskRecord | null {
    try {
      const row = this.db.prepare("SELECT * FROM tasks WHERE id = ?").get(id) as
        | TaskRow
        | undefined;
      return row ? mapRowToTask(row) : null;
    } catch (error) {
      throw new StorageError(`Failed to find task ${id}`, {
        details: { taskId: id },
        cause: error,
      });
    }
  }

  public listRecent(limit = 20): TaskRecord[] {
    try {
      const rows = this.db
        .prepare("SELECT * FROM tasks ORDER BY created_at DESC LIMIT ?")
        .all(limit) as unknown as TaskRow[];
      return rows.map(mapRowToTask);
    } catch (error) {
      throw new StorageError("Failed to list recent tasks", { cause: error });
    }
  }
}
