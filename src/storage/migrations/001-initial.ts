export interface Migration {
  version: number;
  name: string;
  sql: string;
}

export const MIGRATION_001_INITIAL: Migration = {
  version: 1,
  name: "initial_tasks_and_audit_events",
  sql: `
    CREATE TABLE IF NOT EXISTS tasks (
      id TEXT PRIMARY KEY,
      session_id TEXT,
      actor TEXT NOT NULL,
      tool_name TEXT NOT NULL,
      category TEXT NOT NULL,
      working_directory TEXT NOT NULL,
      status TEXT NOT NULL,
      policy_level TEXT,
      approval_status TEXT NOT NULL,
      exit_code INTEGER,
      duration_ms INTEGER,
      error_summary TEXT,
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL
    ) STRICT;

    CREATE INDEX IF NOT EXISTS idx_tasks_created_at ON tasks (created_at DESC);
    CREATE INDEX IF NOT EXISTS idx_tasks_status ON tasks (status);

    CREATE TABLE IF NOT EXISTS audit_events (
      id TEXT PRIMARY KEY,
      timestamp_utc TEXT NOT NULL,
      session_id TEXT,
      task_id TEXT NOT NULL,
      actor TEXT NOT NULL,
      operation TEXT NOT NULL,
      category TEXT NOT NULL,
      sanitized_input TEXT NOT NULL,
      working_directory TEXT NOT NULL,
      policy_level TEXT NOT NULL,
      policy_decision TEXT NOT NULL,
      approval_status TEXT NOT NULL,
      approved_by TEXT,
      exit_code INTEGER,
      duration_ms INTEGER,
      status TEXT NOT NULL,
      error_summary TEXT
    ) STRICT;

    CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_events (timestamp_utc DESC);
    CREATE INDEX IF NOT EXISTS idx_audit_task_id ON audit_events (task_id);
    CREATE INDEX IF NOT EXISTS idx_audit_status ON audit_events (status);
  `,
};

export const ALL_MIGRATIONS: readonly Migration[] = [MIGRATION_001_INITIAL];
