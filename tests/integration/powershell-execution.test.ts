import { describe, expect, it } from "vitest";
import { SecurityConfigSchema } from "../../src/config/index.js";
import { SynapseEventBus } from "../../src/core/events.js";
import { AuditService, createSynapseLogger } from "../../src/modules/audit/index.js";
import {
  ExecutionEngine,
  NodeProcessRunner,
  ToolRegistry,
} from "../../src/modules/execution-engine/index.js";
import {
  type ApprovalRequest,
  type IApprovalHandler,
  PolicyEngine,
} from "../../src/modules/security/index.js";
import {
  createShellExecTool,
  PowerShellAdapter,
  ShellManager,
} from "../../src/modules/shell-manager/index.js";
import { TaskManager } from "../../src/modules/task-manager/index.js";
import {
  SqliteAuditRepository,
  SqliteTaskRepository,
  SynapseDatabase,
} from "../../src/storage/index.js";

function createTestPipeline(options?: {
  approvalHandler?: IApprovalHandler;
  extraAllowedCommands?: string[];
}) {
  const db = new SynapseDatabase(":memory:");
  const bus = new SynapseEventBus();
  const logger = createSynapseLogger({ level: "silent" });
  const auditService = new AuditService({
    repository: new SqliteAuditRepository(db.db),
    logger,
    eventBus: bus,
  });

  const baseSecurity = SecurityConfigSchema.parse({});
  const securityConfig = {
    ...baseSecurity,
    allowedShellCommands: [
      ...baseSecurity.allowedShellCommands,
      ...(options?.extraAllowedCommands ?? []),
    ],
  };

  const policyEngine = new PolicyEngine({
    workspaceDir: process.cwd(),
    securityConfig,
    approvalHandler: options?.approvalHandler,
  });

  const processRunner = new NodeProcessRunner();
  const psAdapter = new PowerShellAdapter({ processRunner, preferred: "auto" });
  const shellManager = new ShellManager({
    processRunner,
    defaultAdapter: psAdapter,
    extraBlockedEnvPatterns: securityConfig.extraBlockedEnvPatterns,
  });

  const registry = new ToolRegistry();
  registry.register(createShellExecTool(shellManager));

  const executionEngine = new ExecutionEngine({
    registry,
    defaultTimeoutMs: 10_000,
    defaultMaxOutputBytes: 65_536,
  });

  const taskManager = new TaskManager({
    taskRepository: new SqliteTaskRepository(db.db),
    policyEngine,
    executionEngine,
    auditLogger: auditService,
    eventBus: bus,
  });

  return { db, auditService, processRunner, psAdapter, taskManager };
}

describe("Integration — PowerShellAdapter, NodeProcessRunner and TaskManager", () => {
  it("detects PowerShell on Windows and executes an allowlisted UTF-8 command end-to-end", async () => {
    const { db, auditService, psAdapter, taskManager } = createTestPipeline();

    try {
      const detected = await psAdapter.detect();
      expect(detected.available).toBe(true);
      expect(detected.version).toBeTruthy();

      const outcome = await taskManager.submitAndRun({
        toolName: "shell.exec",
        category: "shell",
        input: { command: "Write-Output 'SYNAPSE execução ação'" },
        workingDirectory: process.cwd(),
        actor: "integration-test",
      });

      expect(outcome.task.status).toBe("COMPLETED");
      expect(outcome.result?.exitCode).toBe(0);
      expect(outcome.result?.stdout.trim()).toBe("SYNAPSE execução ação");

      const audits = auditService.query({ taskId: outcome.task.id });
      expect(audits).toHaveLength(1);
      expect(audits[0]?.status).toBe("COMPLETED");
      expect(audits[0]?.policyDecision).toBe("AUTO");
    } finally {
      db.close();
    }
  });

  it("captures stderr and non-zero exit codes faithfully from PowerShell", async () => {
    const approveOnce: IApprovalHandler = {
      async requestApproval() {
        return { approved: true, approvedBy: "test-operator" };
      },
    };
    const { db, taskManager } = createTestPipeline({ approvalHandler: approveOnce });

    try {
      const outcome = await taskManager.submitAndRun({
        toolName: "shell.exec",
        category: "shell",
        input: {
          command: "[Console]::Error.WriteLine('err-output'); exit 7",
        },
        workingDirectory: process.cwd(),
        actor: "integration-test",
      });

      expect(outcome.task.status).toBe("FAILED");
      expect(outcome.task.approvalStatus).toBe("approved");
      expect(outcome.result?.exitCode).toBe(7);
      expect(outcome.result?.stderr).toContain("err-output");
    } finally {
      db.close();
    }
  });

  it("enforces timeout and terminates child process tree cleanly", async () => {
    const approveOnce: IApprovalHandler = {
      async requestApproval() {
        return { approved: true, approvedBy: "test-operator" };
      },
    };
    const { db, taskManager } = createTestPipeline({ approvalHandler: approveOnce });

    try {
      const outcome = await taskManager.submitAndRun(
        {
          toolName: "shell.exec",
          category: "shell",
          input: { command: "Start-Sleep -Seconds 15" },
          workingDirectory: process.cwd(),
          actor: "integration-test",
        },
        { timeoutMs: 800 },
      );

      expect(outcome.task.status).toBe("TIMED_OUT");
      expect(outcome.result?.status).toBe("timed_out");
      expect(outcome.result?.durationMs).toBeLessThan(8_000);
    } finally {
      db.close();
    }
  });

  it("truncates stdout at maxOutputBytes with explicit truncated flag", async () => {
    const { db, processRunner } = createTestPipeline();
    try {
      const res = await processRunner.run({
        executable: process.execPath,
        args: ["-e", "process.stdout.write('A'.repeat(5000))"],
        cwd: process.cwd(),
        timeoutMs: 5_000,
        maxOutputBytes: 1024,
      });

      expect(res.status).toBe("completed");
      expect(res.stdoutTruncated).toBe(true);
      expect(Buffer.byteLength(res.stdout, "utf8")).toBe(1024);
    } finally {
      db.close();
    }
  });

  it("never propagates sensitive environment variables to child processes", async () => {
    const { db, processRunner } = createTestPipeline();
    try {
      const res = await processRunner.run({
        executable: process.execPath,
        args: [
          "-e",
          "console.log(JSON.stringify({ key: process.env.ANTHROPIC_API_KEY ?? null, safe: process.env.SYNAPSE_SAFE_VAR ?? null }))",
        ],
        cwd: process.cwd(),
        timeoutMs: 5_000,
        maxOutputBytes: 4_096,
        env: {
          ...process.env,
          ANTHROPIC_API_KEY: "sk-ant-must-never-leak-to-child",
          SYNAPSE_SAFE_VAR: "visible-safe-value",
        },
      });

      expect(res.status).toBe("completed");
      const parsed = JSON.parse(res.stdout.trim()) as { key: string | null; safe: string | null };
      expect(parsed.key).toBeNull();
      expect(parsed.safe).toBe("visible-safe-value");
    } finally {
      db.close();
    }
  });

  it("blocks denied commands before execution and audits the denial", async () => {
    const seenApprovals: ApprovalRequest[] = [];
    const handler: IApprovalHandler = {
      async requestApproval(req) {
        seenApprovals.push(req);
        return { approved: true, approvedBy: "should-not-be-called" };
      },
    };
    const { db, auditService, taskManager } = createTestPipeline({ approvalHandler: handler });

    try {
      const outcome = await taskManager.submitAndRun({
        toolName: "shell.exec",
        category: "shell",
        input: { command: "git push --force origin main" },
        workingDirectory: process.cwd(),
        actor: "integration-test",
      });

      expect(seenApprovals).toHaveLength(0);
      expect(outcome.task.status).toBe("DENIED");
      expect(outcome.result).toBeNull();

      const audits = auditService.query({ taskId: outcome.task.id });
      expect(audits).toHaveLength(1);
      expect(audits[0]?.policyDecision).toBe("DENIED");
      expect(audits[0]?.status).toBe("DENIED");
    } finally {
      db.close();
    }
  });
});
