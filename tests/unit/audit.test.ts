import { Writable } from "node:stream";
import { describe, expect, it } from "vitest";
import { SynapseEventBus } from "../../src/core/events.js";
import { AuditService, createSynapseLogger } from "../../src/modules/audit/index.js";
import { SqliteAuditRepository, SynapseDatabase } from "../../src/storage/index.js";

describe("AuditService and Pino structured logging", () => {
  it("persists redacted audit events to SQLite and emits structured JSON logs without leaking secrets", () => {
    const db = new SynapseDatabase(":memory:");
    const logLines: string[] = [];
    const sink = new Writable({
      write(chunk, _enc, cb) {
        logLines.push(chunk.toString("utf8"));
        cb();
      },
    });

    try {
      const repo = new SqliteAuditRepository(db.db);
      const logger = createSynapseLogger({ level: "info", destination: sink });
      const bus = new SynapseEventBus();
      const emitted: string[] = [];
      bus.on("audit:recorded", (ev) => emitted.push(ev.id));

      const audit = new AuditService({ repository: repo, logger, eventBus: bus });

      const recorded = audit.record({
        taskId: "task-audit-1",
        actor: "cli-user",
        operation: "shell.exec",
        category: "shell",
        input: {
          command: "Write-Output ok",
          apiKey: "sk-ant-verysecretvalue12345",
        },
        workingDirectory: "C:\\workspace",
        policyLevel: "AUTO",
        policyDecision: "AUTO",
        approvalStatus: "not_required",
        exitCode: 0,
        durationMs: 15,
        status: "COMPLETED",
        errorSummary: "Failed with token=supersecret123",
      });

      expect(emitted).toEqual([recorded.id]);
      expect(recorded.sanitizedInput).not.toContain("sk-ant-verysecretvalue12345");
      expect(recorded.sanitizedInput).toContain("[REDACTED]");
      expect(recorded.errorSummary).not.toContain("supersecret123");

      const persisted = audit.query({ taskId: "task-audit-1" });
      expect(persisted).toHaveLength(1);
      expect(persisted[0]?.sanitizedInput).not.toContain("sk-ant-verysecretvalue12345");

      expect(logLines.length).toBeGreaterThan(0);
      const parsedLog = JSON.parse(logLines[0] ?? "{}") as Record<string, unknown>;
      expect(parsedLog.msg).toBe("audit_event_recorded");
      expect(parsedLog.taskId).toBe("task-audit-1");
      expect(JSON.stringify(parsedLog)).not.toContain("supersecret123");
    } finally {
      db.close();
    }
  });
});
