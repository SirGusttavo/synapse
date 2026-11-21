import fs from "node:fs";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import { StorageError } from "../core/errors.js";
import { ALL_MIGRATIONS, type Migration } from "./migrations/001-initial.js";

export class SynapseDatabase {
  public readonly db: DatabaseSync;
  public readonly dbPath: string;
  private closed = false;

  constructor(dbPath: string, migrations: readonly Migration[] = ALL_MIGRATIONS) {
    this.dbPath = dbPath;

    try {
      if (dbPath !== ":memory:") {
        fs.mkdirSync(path.dirname(dbPath), { recursive: true });
      }
      this.db = new DatabaseSync(dbPath);
      this.configurePragmas();
      this.runMigrations(migrations);
    } catch (error) {
      throw new StorageError(`Failed to initialize SQLite database at ${dbPath}`, {
        details: { dbPath },
        cause: error,
      });
    }
  }

  private configurePragmas(): void {
    this.db.exec("PRAGMA foreign_keys = ON;");
    if (this.dbPath !== ":memory:") {
      this.db.exec("PRAGMA journal_mode = WAL;");
    }
  }

  private runMigrations(migrations: readonly Migration[]): void {
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS schema_migrations (
        version INTEGER PRIMARY KEY,
        name TEXT NOT NULL,
        applied_at TEXT NOT NULL
      ) STRICT;
    `);

    const appliedRows = this.db.prepare("SELECT version FROM schema_migrations").all() as Array<{
      version: number;
    }>;
    const appliedVersions = new Set(appliedRows.map((row) => row.version));

    const insertMigration = this.db.prepare(
      "INSERT INTO schema_migrations (version, name, applied_at) VALUES (?, ?, ?)",
    );

    for (const migration of migrations) {
      if (appliedVersions.has(migration.version)) {
        continue;
      }

      this.db.exec("BEGIN");
      try {
        this.db.exec(migration.sql);
        insertMigration.run(migration.version, migration.name, new Date().toISOString());
        this.db.exec("COMMIT");
      } catch (error) {
        this.db.exec("ROLLBACK");
        throw new StorageError(`Migration ${migration.version} (${migration.name}) failed`, {
          details: { version: migration.version, name: migration.name },
          cause: error,
        });
      }
    }
  }

  public isClosed(): boolean {
    return this.closed;
  }

  public close(): void {
    if (!this.closed) {
      this.db.close();
      this.closed = true;
    }
  }
}
