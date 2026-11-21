import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { SecurityConfigSchema } from "../../src/config/index.js";
import { AuditService, createSynapseLogger } from "../../src/modules/audit/index.js";
import { ExecutionEngine, ToolRegistry } from "../../src/modules/execution-engine/index.js";
import { createFileTools, FileManager } from "../../src/modules/file-manager/index.js";
import { type IApprovalHandler, PolicyEngine } from "../../src/modules/security/index.js";
import { TaskManager } from "../../src/modules/task-manager/index.js";
import {
  SqliteAuditRepository,
  SqliteTaskRepository,
  SynapseDatabase,
} from "../../src/storage/index.js";

const tempDirs: string[] = [];

function createTempDir(prefix = "synapse-fm-"): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), prefix));
  tempDirs.push(dir);
  return dir;
}

afterEach(() => {
  while (tempDirs.length > 0) {
    const dir = tempDirs.pop();
    if (dir && fs.existsSync(dir)) {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  }
});

function createFileTestHarness(
  workspaceDir: string,
  options?: { approvalHandler?: IApprovalHandler },
) {
  const db = new SynapseDatabase(":memory:");
  const securityConfig = SecurityConfigSchema.parse({});
  const policyEngine = new PolicyEngine({
    workspaceDir,
    securityConfig,
    approvalHandler: options?.approvalHandler,
  });

  const fileManager = new FileManager({ workspaceDir });
  const registry = new ToolRegistry();
  for (const tool of createFileTools(fileManager)) {
    registry.register(tool);
  }

  const executionEngine = new ExecutionEngine({
    registry,
    defaultTimeoutMs: 5_000,
    defaultMaxOutputBytes: 262_144,
  });

  const auditService = new AuditService({
    repository: new SqliteAuditRepository(db.db),
    logger: createSynapseLogger({ level: "silent" }),
  });

  const taskManager = new TaskManager({
    taskRepository: new SqliteTaskRepository(db.db),
    policyEngine,
    executionEngine,
    auditLogger: auditService,
  });

  return { db, taskManager, auditService };
}

describe("Integration — FileManager operations & PolicyEngine governance", () => {
  it("creates, reads, edits, lists and searches files within workspace automatically (AUTO)", async () => {
    const ws = createTempDir();
    // Plant a .env file to ensure list and search skip it automatically
    fs.writeFileSync(path.join(ws, ".env"), "SECRET_TOKEN=hidden_from_search\n", "utf8");

    const { db, taskManager } = createFileTestHarness(ws);
    try {
      // 1. Create file
      const createRes = await taskManager.submitAndRun({
        toolName: "file.create",
        category: "file",
        input: {
          path: "src/hello.ts",
          content: "export const greeting = 'Olá SYNAPSE';\nexport const version = 1;\n",
        },
        workingDirectory: ws,
        actor: "test-agent",
      });
      expect(createRes.task.status).toBe("COMPLETED");
      expect(createRes.task.policyLevel).toBe("AUTO");

      // 2. Read file with line slice
      const readRes = await taskManager.submitAndRun({
        toolName: "file.read",
        category: "file",
        input: { path: "src/hello.ts", startLine: 1, endLine: 1 },
        workingDirectory: ws,
        actor: "test-agent",
      });
      expect(readRes.task.status).toBe("COMPLETED");
      expect(readRes.result?.stdout).toBe("export const greeting = 'Olá SYNAPSE';");

      // 3. Edit file atomically
      const editRes = await taskManager.submitAndRun({
        toolName: "file.edit",
        category: "file",
        input: {
          path: "src/hello.ts",
          search: "version = 1",
          replace: "version = 2",
        },
        workingDirectory: ws,
        actor: "test-agent",
      });
      expect(editRes.task.status).toBe("COMPLETED");
      expect(fs.readFileSync(path.join(ws, "src", "hello.ts"), "utf8")).toContain("version = 2");

      // 4. List directory (must include src/hello.ts and hide .env)
      const listRes = await taskManager.submitAndRun({
        toolName: "file.list",
        category: "file",
        input: { path: ".", recursive: true },
        workingDirectory: ws,
        actor: "test-agent",
      });
      expect(listRes.task.status).toBe("COMPLETED");
      expect(listRes.result?.stdout).toContain("hello.ts");
      expect(listRes.result?.stdout).not.toContain(".env");

      // 5. Search content (must find version = 2 and never index .env)
      const searchRes = await taskManager.submitAndRun({
        toolName: "file.search",
        category: "file",
        input: { query: "version = 2" },
        workingDirectory: ws,
        actor: "test-agent",
      });
      expect(searchRes.task.status).toBe("COMPLETED");
      expect(searchRes.result?.stdout).toContain("hello.ts:2:");

      const secretSearch = await taskManager.submitAndRun({
        toolName: "file.search",
        category: "file",
        input: { query: "hidden_from_search" },
        workingDirectory: ws,
        actor: "test-agent",
      });
      expect(secretSearch.result?.stdout).toBe("");
    } finally {
      db.close();
    }
  });

  it("enforces CONDITIONAL approval for file.move and HUMAN_APPROVAL for file.delete (D-06)", async () => {
    const ws = createTempDir();
    fs.writeFileSync(path.join(ws, "a.txt"), "data", "utf8");

    // 1. Without interactive approval, move and delete must fail-closed (DENIED)
    const { db: dbDenied, taskManager: tmDenied } = createFileTestHarness(ws);
    try {
      const moveDenied = await tmDenied.submitAndRun({
        toolName: "file.move",
        category: "file",
        input: { from: "a.txt", to: "b.txt" },
        workingDirectory: ws,
        actor: "test-agent",
      });
      expect(moveDenied.task.status).toBe("DENIED");
      expect(moveDenied.task.policyLevel).toBe("CONDITIONAL");

      const delDenied = await tmDenied.submitAndRun({
        toolName: "file.delete",
        category: "file",
        input: { path: "a.txt" },
        workingDirectory: ws,
        actor: "test-agent",
      });
      expect(delDenied.task.status).toBe("DENIED");
      expect(delDenied.task.policyLevel).toBe("HUMAN_APPROVAL");
      expect(fs.existsSync(path.join(ws, "a.txt"))).toBe(true);
    } finally {
      dbDenied.close();
    }

    // 2. With human approval granted, move and delete succeed and are audited
    const approveHandler: IApprovalHandler = {
      async requestApproval() {
        return { approved: true, approvedBy: "human-reviewer" };
      },
    };
    const { db: dbOk, taskManager: tmOk } = createFileTestHarness(ws, {
      approvalHandler: approveHandler,
    });
    try {
      const moveOk = await tmOk.submitAndRun({
        toolName: "file.move",
        category: "file",
        input: { from: "a.txt", to: "b.txt" },
        workingDirectory: ws,
        actor: "test-agent",
      });
      expect(moveOk.task.status).toBe("COMPLETED");
      expect(fs.existsSync(path.join(ws, "b.txt"))).toBe(true);

      const delOk = await tmOk.submitAndRun({
        toolName: "file.delete",
        category: "file",
        input: { path: "b.txt" },
        workingDirectory: ws,
        actor: "test-agent",
      });
      expect(delOk.task.status).toBe("COMPLETED");
      expect(delOk.task.approvalStatus).toBe("approved");
      expect(fs.existsSync(path.join(ws, "b.txt"))).toBe(false);
    } finally {
      dbOk.close();
    }
  });

  it("blocks path traversal, NTFS junction escapes, sensitive files (.env, keys), .git tampering and binary reads", async () => {
    const ws = createTempDir("synapse-fm-sec-");
    const outside = createTempDir("synapse-fm-out-");
    fs.writeFileSync(path.join(ws, ".env"), "SECRET=123", "utf8");
    fs.mkdirSync(path.join(ws, ".git", "hooks"), { recursive: true });
    fs.writeFileSync(path.join(ws, "binary.bin"), Buffer.from([0x00, 0x01, 0x02, 0xff]));

    const junction = path.join(ws, "linked-out");
    fs.symlinkSync(outside, junction, "junction");

    const { db, taskManager } = createFileTestHarness(ws, {
      approvalHandler: {
        async requestApproval() {
          return { approved: true, approvedBy: "should-never-be-asked-for-denied" };
        },
      },
    });

    try {
      for (const badReq of [
        { toolName: "file.read", input: { path: "../outside.txt" } },
        { toolName: "file.create", input: { path: "linked-out/escape.txt", content: "x" } },
        { toolName: "file.read", input: { path: ".env" } },
        { toolName: "file.create", input: { path: ".env.local", content: "x" } },
        { toolName: "file.create", input: { path: "certs/server.key", content: "x" } },
        { toolName: "file.create", input: { path: ".git/hooks/pre-commit", content: "x" } },
        { toolName: "file.delete", input: { path: ".", recursive: true } },
      ]) {
        const res = await taskManager.submitAndRun({
          toolName: badReq.toolName,
          category: "file",
          input: badReq.input,
          workingDirectory: ws,
          actor: "adversary",
        });
        expect(res.task.status).toBe("DENIED");
      }

      // Binary read must fail gracefully without crashing
      const binRes = await taskManager.submitAndRun({
        toolName: "file.read",
        category: "file",
        input: { path: "binary.bin" },
        workingDirectory: ws,
        actor: "test-agent",
      });
      expect(binRes.task.status).toBe("FAILED");
      expect(binRes.result?.stderr).toContain("binary file");
    } finally {
      db.close();
    }
  });
});
