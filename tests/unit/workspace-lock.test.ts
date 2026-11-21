import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { z } from "zod";
import { SecurityConfigSchema } from "../../src/config/index.js";
import { PolicyDeniedError } from "../../src/core/errors.js";
import { AuditService, createSynapseLogger } from "../../src/modules/audit/index.js";
import { ExecutionEngine, ToolRegistry } from "../../src/modules/execution-engine/index.js";
import {
  AUTHORIZED_OPERATION_BRAND,
  type AuthorizedOperation,
  PolicyEngine,
} from "../../src/modules/security/index.js";
import { TaskManager, WorkspaceLock } from "../../src/modules/task-manager/index.js";
import {
  SqliteAuditRepository,
  SqliteTaskRepository,
  SynapseDatabase,
} from "../../src/storage/index.js";

const tempDirs: string[] = [];

function createTempDir(prefix = "synapse-lock-"): string {
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

describe("WorkspaceLock — Concurrency Scope & Fairness", () => {
  it("allows concurrent readers in the same workspace while serializing writers exclusively", async () => {
    const ws = createTempDir();
    const lock = new WorkspaceLock();
    const timeline: string[] = [];

    // Two concurrent readers should both acquire before either releases
    const r1 = await lock.acquire(ws, "read");
    const r2 = await lock.acquire(ws, "read");
    expect(lock.getDiagnostics(ws)).toEqual({
      activeReaders: 2,
      writerActive: false,
      queuedCount: 0,
    });

    // Queue a writer while readers hold the lock
    const writerPromise = lock.acquire(ws, "write").then((release) => {
      timeline.push("writer-acquired");
      return release;
    });

    // Queue a 3rd reader AFTER writer (FIFO fairness prevents writer starvation)
    const r3Promise = lock.acquire(ws, "read").then((release) => {
      timeline.push("reader3-acquired");
      return release;
    });

    expect(lock.getDiagnostics(ws).queuedCount).toBe(2);

    r1();
    r2();

    const releaseWriter = await writerPromise;
    expect(timeline).toEqual(["writer-acquired"]);
    expect(lock.getDiagnostics(ws).writerActive).toBe(true);

    releaseWriter();
    const releaseR3 = await r3Promise;
    expect(timeline).toEqual(["writer-acquired", "reader3-acquired"]);

    releaseR3();
    expect(lock.getDiagnostics(ws)).toEqual({
      activeReaders: 0,
      writerActive: false,
      queuedCount: 0,
    });
  });

  it("isolates different workspaces and supports AbortSignal cancellation while queued", async () => {
    const wsA = createTempDir("synapse-lock-a-");
    const wsB = createTempDir("synapse-lock-b-");
    const lock = new WorkspaceLock();

    const releaseA = await lock.acquire(wsA, "write");
    // wsB must acquire immediately despite wsA being locked
    const releaseB = await lock.acquire(wsB, "write");
    releaseB();

    const controller = new AbortController();
    const queuedPromise = lock.acquire(wsA, "write", controller.signal);
    controller.abort();

    await expect(queuedPromise).rejects.toThrow(/cancelled/i);

    releaseA();
    expect(lock.getDiagnostics(wsA).queuedCount).toBe(0);
  });

  it("serializes simultaneous mutating tasks in TaskManager without overlapping execution", async () => {
    const ws = createTempDir("synapse-tm-serial-");
    const db = new SynapseDatabase(":memory:");
    try {
      let inFlight = 0;
      let maxObservedConcurrent = 0;
      const executionOrder: string[] = [];

      const registry = new ToolRegistry();
      registry.register({
        name: "shell.exec",
        description: "delayed stub",
        category: "shell",
        defaultPermission: "AUTO",
        inputSchema: z.object({ command: z.string() }),
        async execute(input) {
          const { command } = input as { command: string };
          inFlight += 1;
          maxObservedConcurrent = Math.max(maxObservedConcurrent, inFlight);
          executionOrder.push(`start:${command}`);
          await new Promise((r) => setTimeout(r, 40));
          executionOrder.push(`end:${command}`);
          inFlight -= 1;
          return {
            status: "completed",
            exitCode: 0,
            stdout: command,
            stderr: "",
            stdoutTruncated: false,
            stderrTruncated: false,
            durationMs: 40,
          };
        },
      });

      const tm = new TaskManager({
        taskRepository: new SqliteTaskRepository(db.db),
        policyEngine: new PolicyEngine({
          workspaceDir: ws,
          securityConfig: SecurityConfigSchema.parse({}),
        }),
        executionEngine: new ExecutionEngine({
          registry,
          defaultTimeoutMs: 5_000,
          defaultMaxOutputBytes: 4_096,
        }),
        auditLogger: new AuditService({
          repository: new SqliteAuditRepository(db.db),
          logger: createSynapseLogger({ level: "silent" }),
        }),
      });

      const [o1, o2, o3] = await Promise.all([
        tm.submitAndRun({
          toolName: "shell.exec",
          category: "shell",
          input: { command: "Write-Output one" },
          workingDirectory: ws,
          actor: "t1",
        }),
        tm.submitAndRun({
          toolName: "shell.exec",
          category: "shell",
          input: { command: "Write-Output two" },
          workingDirectory: ws,
          actor: "t2",
        }),
        tm.submitAndRun({
          toolName: "shell.exec",
          category: "shell",
          input: { command: "Write-Output three" },
          workingDirectory: ws,
          actor: "t3",
        }),
      ]);

      expect(o1.task.status).toBe("COMPLETED");
      expect(o2.task.status).toBe("COMPLETED");
      expect(o3.task.status).toBe("COMPLETED");
      expect(maxObservedConcurrent).toBe(1);
      expect(executionOrder).toEqual([
        "start:Write-Output one",
        "end:Write-Output one",
        "start:Write-Output two",
        "end:Write-Output two",
        "start:Write-Output three",
        "end:Write-Output three",
      ]);
    } finally {
      db.close();
    }
  });
});

describe("Authorization Digest & Pre-Mutation Revalidation", () => {
  it("rejects mismatched SHA-256 inputDigest in ExecutionEngine and detects symlink TOCTOU during revalidation", async () => {
    const ws = createTempDir("synapse-reval-ws-");
    const outside = createTempDir("synapse-reval-out-");
    const sub = path.join(ws, "work");
    fs.mkdirSync(sub);

    const policy = new PolicyEngine({
      workspaceDir: ws,
      securityConfig: SecurityConfigSchema.parse({}),
    });

    const evalRes = await policy.evaluateAndAuthorize("t-reval", {
      toolName: "shell.exec",
      category: "shell",
      input: { command: "Get-Location" },
      workingDirectory: sub,
      actor: "tester",
    });

    expect(evalRes.allowed).toBe(true);
    if (!evalRes.allowed) {
      return;
    }

    // Valid immediately
    expect(policy.revalidateAuthorized(evalRes.authorized).valid).toBe(true);

    // Swap `sub` with an NTFS junction pointing outside the workspace BEFORE execution (TOCTOU!)
    fs.rmSync(sub, { recursive: true, force: true });
    fs.symlinkSync(outside, sub, "junction");

    const recheck = policy.revalidateAuthorized(evalRes.authorized);
    expect(recheck.valid).toBe(false);

    // Forged digest must be rejected by ExecutionEngine even if branded
    const tampered = {
      ...evalRes.authorized,
      [AUTHORIZED_OPERATION_BRAND]: true as const,
      inputDigest: "0".repeat(64),
    } as AuthorizedOperation;

    const engine = new ExecutionEngine({
      registry: new ToolRegistry(),
      defaultTimeoutMs: 5_000,
      defaultMaxOutputBytes: 4_096,
    });

    await expect(engine.executeAuthorized(tampered)).rejects.toThrow(PolicyDeniedError);
  });
});
