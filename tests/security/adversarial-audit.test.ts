import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { z } from "zod";
import { DEFAULT_ALLOWED_SHELL_COMMANDS, SecurityConfigSchema } from "../../src/config/index.js";
import { ExecutionError, PolicyDeniedError } from "../../src/core/errors.js";
import {
  ExecutionEngine,
  NodeProcessRunner,
  ToolRegistry,
} from "../../src/modules/execution-engine/index.js";
import {
  analyzeShellCommand,
  assertWorkingDirectoryAllowed,
  type IApprovalHandler,
  isPathWithinWorkspace,
  PolicyEngine,
  redactText,
  sanitizeEnvironment,
} from "../../src/modules/security/index.js";
import { PowerShellAdapter } from "../../src/modules/shell-manager/index.js";
import { TaskManager } from "../../src/modules/task-manager/index.js";
import { SqliteTaskRepository, SynapseDatabase } from "../../src/storage/index.js";

const tempDirs: string[] = [];

function createTempDir(prefix = "synapse-adv-"): string {
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

describe("Adversarial Audit — CommandAnalyzer bypass resistance", () => {
  it("blocks or escalates newline injection, subexpressions, scriptblocks, backtick obfuscation and call operators", () => {
    // Newline injection after allowlisted prefix
    const newlineRes = analyzeShellCommand(
      "Write-Output ok\nWhoami",
      DEFAULT_ALLOWED_SHELL_COMMANDS,
    );
    expect(newlineRes.level).toBe("CONDITIONAL");
    expect(newlineRes.detectedRisks).toContain("multiline_command");

    // Grouping / subexpression bypass
    const parensRes = analyzeShellCommand(
      "Write-Output (Get-Date)",
      DEFAULT_ALLOWED_SHELL_COMMANDS,
    );
    expect(parensRes.level).toBe("CONDITIONAL");

    // Scriptblock / call operator / dot-sourcing
    expect(
      analyzeShellCommand("Write-Output { Get-Date }", DEFAULT_ALLOWED_SHELL_COMMANDS).level,
    ).toBe("CONDITIONAL");
    expect(analyzeShellCommand("& 'node' -v", DEFAULT_ALLOWED_SHELL_COMMANDS).level).toBe(
      "CONDITIONAL",
    );
    expect(analyzeShellCommand(". ./script.ps1", DEFAULT_ALLOWED_SHELL_COMMANDS).level).toBe(
      "CONDITIONAL",
    );

    // Backtick obfuscation of denied cmdlets
    expect(
      analyzeShellCommand("I`n`v`o`k`e-Expression '1+1'", DEFAULT_ALLOWED_SHELL_COMMANDS).level,
    ).toBe("DENIED");
    expect(analyzeShellCommand("pwsh -e SQBFAFgA", DEFAULT_ALLOWED_SHELL_COMMANDS).level).toBe(
      "DENIED",
    );
    expect(
      analyzeShellCommand("[scriptblock]::Create('whoami')", DEFAULT_ALLOWED_SHELL_COMMANDS).level,
    ).toBe("DENIED");
    expect(
      analyzeShellCommand("Add-Type -TypeDefinition 'class X{}'", DEFAULT_ALLOWED_SHELL_COMMANDS)
        .level,
    ).toBe("DENIED");
  });

  it("blocks dangerous git flags/refspecs and escalates branch deletion and outside-workspace path args", () => {
    expect(
      analyzeShellCommand("git -C repo push --force origin main", DEFAULT_ALLOWED_SHELL_COMMANDS)
        .level,
    ).toBe("DENIED");
    expect(
      analyzeShellCommand("git push origin +main:main", DEFAULT_ALLOWED_SHELL_COMMANDS).level,
    ).toBe("DENIED");
    expect(
      analyzeShellCommand("git -c core.hooksPath=/tmp status", DEFAULT_ALLOWED_SHELL_COMMANDS)
        .level,
    ).toBe("DENIED");
    expect(analyzeShellCommand("git branch -D main", DEFAULT_ALLOWED_SHELL_COMMANDS).level).toBe(
      "HUMAN_APPROVAL",
    );
    expect(analyzeShellCommand("dir ..\\..", DEFAULT_ALLOWED_SHELL_COMMANDS).level).toBe(
      "CONDITIONAL",
    );
    expect(
      analyzeShellCommand("Get-ChildItem C:\\Windows", DEFAULT_ALLOWED_SHELL_COMMANDS).level,
    ).toBe("CONDITIONAL");
  });
});

describe("Adversarial Audit — WorkspaceGuard (UNC, NTFS Junctions, Null Bytes)", () => {
  it("blocks forward-slash UNC paths even when allowOutsideWorkspace is true, and blocks NTFS junction escape", () => {
    const ws = createTempDir("synapse-adv-ws-");
    const outside = createTempDir("synapse-adv-out-");

    expect(() => assertWorkingDirectoryAllowed(ws, "//server/share", true)).toThrow(
      PolicyDeniedError,
    );
    expect(() => assertWorkingDirectoryAllowed(ws, "\\\\?\\C:\\Windows", true)).toThrow(
      PolicyDeniedError,
    );
    expect(() => assertWorkingDirectoryAllowed(ws, "valid\0evil", false)).toThrow(
      PolicyDeniedError,
    );

    const junctionPath = path.join(ws, "escape-junction");
    fs.symlinkSync(outside, junctionPath, "junction");
    expect(isPathWithinWorkspace(ws, junctionPath)).toBe(false);
    expect(isPathWithinWorkspace(ws, path.join(junctionPath, "nested-new-file.txt"))).toBe(false);
  });
});

describe("Adversarial Audit — PolicyEngine & ExecutionEngine (Immutability, Replay, Default-Deny)", () => {
  it("prevents post-authorization input mutation (TOCTOU) and rejects replay of consumed authorizations", async () => {
    const ws = createTempDir("synapse-adv-pol-");
    const policy = new PolicyEngine({
      workspaceDir: ws,
      securityConfig: SecurityConfigSchema.parse({}),
    });

    const mutableReq = {
      toolName: "shell.exec",
      category: "shell" as const,
      input: { command: "Write-Output safe" },
      workingDirectory: ws,
      actor: "tester",
    };

    const evalRes = await policy.evaluateAndAuthorize("task-immut", mutableReq);
    expect(evalRes.allowed).toBe(true);
    if (!evalRes.allowed) {
      return;
    }

    // Mutate caller's original request object after approval
    mutableReq.input.command = "git push --force origin main";
    expect(evalRes.authorized.request.input.command).toBe("Write-Output safe");
    expect(Object.isFrozen(evalRes.authorized.request.input)).toBe(true);

    const registry = new ToolRegistry();
    registry.register({
      name: "shell.exec",
      description: "stub",
      category: "shell",
      defaultPermission: "AUTO",
      inputSchema: z.object({ command: z.string() }),
      async execute(input) {
        const { command } = input as { command: string };
        return {
          status: "completed",
          exitCode: 0,
          stdout: command,
          stderr: "",
          stdoutTruncated: false,
          stderrTruncated: false,
          durationMs: 1,
        };
      },
    });

    const engine = new ExecutionEngine({
      registry,
      defaultTimeoutMs: 5_000,
      defaultMaxOutputBytes: 4_096,
    });

    const first = await engine.executeAuthorized(evalRes.authorized);
    expect(first.stdout).toBe("Write-Output safe");

    // Second execution (replay) must be rejected
    await expect(engine.executeAuthorized(evalRes.authorized)).rejects.toThrow(PolicyDeniedError);
  });

  it("denies unmapped operations by default (RNF-01) and escalates outside-workspace ops to HUMAN_APPROVAL", async () => {
    const ws = createTempDir("synapse-adv-deny-");
    const outside = createTempDir("synapse-adv-outside-");

    const policy = new PolicyEngine({
      workspaceDir: ws,
      securityConfig: SecurityConfigSchema.parse({ allowOutsideWorkspace: true }),
    });

    const unknownRes = await policy.evaluateAndAuthorize("t-unknown", {
      toolName: "unknown.tool",
      category: "system",
      input: {},
      workingDirectory: ws,
      actor: "tester",
    });
    expect(unknownRes.allowed).toBe(false);
    if (!unknownRes.allowed) {
      expect(unknownRes.policyLevel).toBe("DENIED");
    }

    // Even an allowlisted AUTO command targeting outside workspace must escalate to HUMAN_APPROVAL
    const outsideRes = await policy.evaluateAndAuthorize("t-outside", {
      toolName: "shell.exec",
      category: "shell",
      input: { command: "Get-Location" },
      workingDirectory: outside,
      actor: "tester",
    });
    expect(outsideRes.allowed).toBe(false);
    if (!outsideRes.allowed) {
      expect(outsideRes.policyLevel).toBe("HUMAN_APPROVAL");
      expect(outsideRes.detectedRisks).toContain("outside_workspace");
    }
  });
});

describe("Adversarial Audit — Redactor & EnvSanitizer value scrubbing", () => {
  it("redacts composite env assignments and Base64 Bearer tokens ending in ==", () => {
    expect(redactText("ANTHROPIC_API_KEY=custom_secret_value_123")).toBe(
      "ANTHROPIC_API_KEY=[REDACTED]",
    );
    expect(redactText("GITHUB_TOKEN=custom_token_value_123")).toBe("GITHUB_TOKEN=[REDACTED]");
    expect(redactText("Authorization: Bearer abcdefgh1234==")).toBe("Authorization: [REDACTED]");
  });

  it("strips env vars with innocuous names when their values contain embedded secrets", () => {
    const sanitized = sanitizeEnvironment({
      SAFE_VAR: "hello",
      INNOCUOUS_NAME: "sk-ant-1234567890abcdef",
      DB_CONN: "postgres://admin:superpass@db.internal:5432/prod",
    });

    expect(sanitized.SAFE_VAR).toBe("hello");
    expect(sanitized.INNOCUOUS_NAME).toBeUndefined();
    expect(sanitized.DB_CONN).toBeUndefined();
  });
});

describe("Adversarial Audit — ProcessRunner, PowerShellAdapter & TaskManager resilience", () => {
  it("rejects null bytes and invalid timeout/maxOutputBytes in NodeProcessRunner", async () => {
    const runner = new NodeProcessRunner();

    await expect(
      runner.run({
        executable: "node\0evil",
        args: [],
        cwd: process.cwd(),
        timeoutMs: 1_000,
        maxOutputBytes: 1_024,
      }),
    ).rejects.toThrow(ExecutionError);

    await expect(
      runner.run({
        executable: process.execPath,
        args: ["ok\0bad"],
        cwd: process.cwd(),
        timeoutMs: 1_000,
        maxOutputBytes: 1_024,
      }),
    ).rejects.toThrow(ExecutionError);

    await expect(
      runner.run({
        executable: process.execPath,
        args: ["-v"],
        cwd: process.cwd(),
        timeoutMs: -1,
        maxOutputBytes: 1_024,
      }),
    ).rejects.toThrow(ExecutionError);
  });

  it("prevents PowerShell try/catch breakout, detects non-terminating errors and kills Windows grandchild trees", async () => {
    const runner = new NodeProcessRunner();
    const ps = new PowerShellAdapter({ processRunner: runner, preferred: "auto" });

    // 1. try/catch breakout must fail cleanly with ParseException (never execute ESCAPED)
    const breakoutInv = await ps.buildInvocation(
      "Write-Output 'ok' } catch {} ; Write-Output 'ESCAPED' ; try {",
    );
    const breakoutRes = await runner.run({
      executable: breakoutInv.executable,
      args: breakoutInv.args,
      cwd: process.cwd(),
      timeoutMs: 8_000,
      maxOutputBytes: 4_096,
    });
    expect(breakoutRes.status).toBe("failed");
    expect(breakoutRes.exitCode).toBe(1);
    expect(breakoutRes.stdout).not.toContain("ESCAPED");

    // 2. Non-terminating Write-Error followed by Write-Output must still fail (exitCode 1)
    const errInv = await ps.buildInvocation("Write-Error 'boom'; Write-Output 'after'");
    const errRes = await runner.run({
      executable: errInv.executable,
      args: errInv.args,
      cwd: process.cwd(),
      timeoutMs: 8_000,
      maxOutputBytes: 4_096,
    });
    expect(errRes.status).toBe("failed");
    expect(errRes.exitCode).toBe(1);
    expect(errRes.stderr).toContain("boom");

    // 3. Real Windows grandchild process must be terminated on timeout
    const treeInv = await ps.buildInvocation(
      "$p = Start-Process node -ArgumentList '-e','setTimeout(()=>{},30000)' -PassThru -WindowStyle Hidden; Write-Output $p.Id; Start-Sleep -Seconds 20",
    );
    const treeRes = await runner.run({
      executable: treeInv.executable,
      args: treeInv.args,
      cwd: process.cwd(),
      timeoutMs: 4_500,
      maxOutputBytes: 4_096,
    });
    expect(treeRes.status).toBe("timed_out");
    const grandchildPid = Number(treeRes.stdout.trim());
    expect(Number.isInteger(grandchildPid) && grandchildPid > 0).toBe(true);

    await new Promise((r) => setTimeout(r, 300));
    let stillAlive = false;
    try {
      process.kill(grandchildPid, 0);
      stillAlive = true;
      process.kill(grandchildPid, "SIGKILL");
    } catch {
      stillAlive = false;
    }
    expect(stillAlive).toBe(false);
  });

  it("prevents duplicate audit calls on storage failure and cancels tasks awaiting approval", async () => {
    const db = new SynapseDatabase(":memory:");
    try {
      const registry = new ToolRegistry();
      registry.register({
        name: "shell.exec",
        description: "stub",
        category: "shell",
        defaultPermission: "AUTO",
        inputSchema: z.object({ command: z.string() }),
        async execute() {
          return {
            status: "completed",
            exitCode: 0,
            stdout: "ok",
            stderr: "",
            stdoutTruncated: false,
            stderrTruncated: false,
            durationMs: 1,
          };
        },
      });

      // 1. Audit failure must propagate once without duplicate catch-block recording
      let auditAttempts = 0;
      const failingAudit = {
        record() {
          auditAttempts += 1;
          throw new Error("Simulated SQLite write failure");
        },
        query() {
          return [];
        },
      };

      const tmFail = new TaskManager({
        taskRepository: new SqliteTaskRepository(db.db),
        policyEngine: new PolicyEngine({
          workspaceDir: process.cwd(),
          securityConfig: SecurityConfigSchema.parse({}),
        }),
        executionEngine: new ExecutionEngine({
          registry,
          defaultTimeoutMs: 5_000,
          defaultMaxOutputBytes: 4_096,
        }),
        auditLogger: failingAudit,
      });

      await expect(
        tmFail.submitAndRun({
          toolName: "shell.exec",
          category: "shell",
          input: { command: "Write-Output ok" },
          workingDirectory: process.cwd(),
          actor: "tester",
        }),
      ).rejects.toThrow("Simulated SQLite write failure");
      expect(auditAttempts).toBe(1);

      // 2. Cancelling a task while AWAITING_APPROVAL aborts the approval prompt cleanly
      const recordedStatuses: string[] = [];
      const waitingApproval: IApprovalHandler = {
        requestApproval(_req, signal) {
          return new Promise((resolve) => {
            signal?.addEventListener(
              "abort",
              () => resolve({ approved: false, approvedBy: null, reason: "Aborted" }),
              { once: true },
            );
          });
        },
      };

      const tmCancel = new TaskManager({
        taskRepository: new SqliteTaskRepository(db.db),
        policyEngine: new PolicyEngine({
          workspaceDir: process.cwd(),
          securityConfig: SecurityConfigSchema.parse({}),
          approvalHandler: waitingApproval,
        }),
        executionEngine: new ExecutionEngine({
          registry,
          defaultTimeoutMs: 5_000,
          defaultMaxOutputBytes: 4_096,
        }),
        auditLogger: {
          record(entry) {
            recordedStatuses.push(entry.status);
            return {
              id: "a1",
              timestampUtc: new Date().toISOString(),
              sessionId: null,
              taskId: entry.taskId,
              actor: entry.actor,
              operation: entry.operation,
              category: entry.category,
              sanitizedInput: "{}",
              workingDirectory: entry.workingDirectory,
              policyLevel: entry.policyLevel,
              policyDecision: entry.policyDecision,
              approvalStatus: entry.approvalStatus,
              approvedBy: null,
              exitCode: null,
              durationMs: null,
              status: entry.status,
              errorSummary: entry.errorSummary ?? null,
            };
          },
          query() {
            return [];
          },
        },
      });

      const externalController = new AbortController();
      setTimeout(() => externalController.abort(), 50);

      const outcome = await tmCancel.submitAndRun(
        {
          toolName: "shell.exec",
          category: "shell",
          input: { command: "git push origin main" },
          workingDirectory: process.cwd(),
          actor: "tester",
        },
        { externalSignal: externalController.signal },
      );

      expect(outcome.task.status).toBe("CANCELLED");
      expect(recordedStatuses).toEqual(["CANCELLED"]);
    } finally {
      db.close();
    }
  });
});
