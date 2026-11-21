import { describe, expect, it } from "vitest";
import {
  SqliteAuditRepository,
  SqliteTaskRepository,
  SynapseDatabase,
} from "../../src/storage/index.js";

describe("SynapseDatabase and repositories", () => {
  it("runs migrations idempotently and stores/queries tasks and audit events", () => {
    const database = new SynapseDatabase(":memory:");
    try {
      const taskRepo = new SqliteTaskRepository(database.db);
      const auditRepo = new SqliteAuditRepository(database.db);

      const now = new Date().toISOString();
      taskRepo.create({
        id: "task-1",
        sessionId: null,
        actor: "cli-user",
        toolName: "shell.exec",
        category: "shell",
        workingDirectory: "C:\\workspace",
        status: "PENDING",
        policyLevel: "AUTO",
        approvalStatus: "not_required",
        exitCode: null,
        durationMs: null,
        errorSummary: null,
        createdAt: now,
        updatedAt: now,
      });

      const found = taskRepo.findById("task-1");
      expect(found?.status).toBe("PENDING");
      if (!found) {
        throw new Error("Expected task-1 to exist");
      }

      taskRepo.update({
        ...found,
        status: "COMPLETED",
        exitCode: 0,
        durationMs: 42,
        updatedAt: new Date().toISOString(),
      });

      expect(taskRepo.findById("task-1")?.status).toBe("COMPLETED");
      expect(taskRepo.listRecent(10)).toHaveLength(1);

      auditRepo.append({
        id: "audit-1",
        timestampUtc: now,
        sessionId: null,
        taskId: "task-1",
        actor: "cli-user",
        operation: "shell.exec",
        category: "shell",
        sanitizedInput: JSON.stringify({ command: "Get-Location" }),
        workingDirectory: "C:\\workspace",
        policyLevel: "AUTO",
        policyDecision: "AUTO",
        approvalStatus: "not_required",
        approvedBy: null,
        exitCode: 0,
        durationMs: 42,
        status: "COMPLETED",
        errorSummary: null,
      });

      const events = auditRepo.query({ taskId: "task-1" });
      expect(events).toHaveLength(1);
      expect(events[0]?.operation).toBe("shell.exec");
      expect(events[0]?.exitCode).toBe(0);
    } finally {
      database.close();
    }
  });
});
