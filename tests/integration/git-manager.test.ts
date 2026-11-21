import { execFileSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { SecurityConfigSchema } from "../../src/config/index.js";
import { AuditService, createSynapseLogger } from "../../src/modules/audit/index.js";
import {
  ExecutionEngine,
  NodeProcessRunner,
  ToolRegistry,
} from "../../src/modules/execution-engine/index.js";
import { createGitTools, GitManager } from "../../src/modules/git-manager/index.js";
import { type IApprovalHandler, PolicyEngine } from "../../src/modules/security/index.js";
import { TaskManager } from "../../src/modules/task-manager/index.js";
import {
  SqliteAuditRepository,
  SqliteTaskRepository,
  SynapseDatabase,
} from "../../src/storage/index.js";

const tempDirs: string[] = [];

function createTempDir(prefix = "synapse-git-"): string {
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

function createGitTestHarness(
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

  const processRunner = new NodeProcessRunner();
  const gitManager = new GitManager({
    processRunner,
    workspaceDir,
  });

  const registry = new ToolRegistry();
  for (const tool of createGitTools(gitManager)) {
    registry.register(tool);
  }

  const executionEngine = new ExecutionEngine({
    registry,
    defaultTimeoutMs: 15_000,
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

describe("Integration — GitManager lifecycle, hook containment and security policy", () => {
  it("executes init, status, add, diff, commit (suppressing hooks!), log, branch, checkout, merge and tag", async () => {
    const ws = createTempDir("synapse-git-flow-");
    const approveAll: IApprovalHandler = {
      async requestApproval() {
        return { approved: true, approvedBy: "test-operator" };
      },
    };

    const { db, taskManager } = createGitTestHarness(ws, { approvalHandler: approveAll });

    try {
      // 1. git.init (CONDITIONAL -> approved)
      const initRes = await taskManager.submitAndRun({
        toolName: "git.init",
        category: "git",
        input: { initialBranch: "main" },
        workingDirectory: ws,
        actor: "test-agent",
      });
      expect(initRes.task.status).toBe("COMPLETED");
      expect(initRes.task.policyLevel).toBe("CONDITIONAL");

      // Configure local test user so commit works even in bare CI environments
      execFileSync("git", ["config", "user.name", "Test Bot"], { cwd: ws });
      execFileSync("git", ["config", "user.email", "test@example.com"], { cwd: ws });

      // Plant a malicious pre-commit hook that would create a marker file and exit 1 if hooks ran
      const hookMarker = path.join(ws, "hook-pwned.txt");
      const hookPath = path.join(ws, ".git", "hooks", "pre-commit");
      fs.mkdirSync(path.dirname(hookPath), { recursive: true });
      fs.writeFileSync(
        hookPath,
        `#!/bin/sh\necho PWNED > "${hookMarker.replace(/\\/g, "/")}"\nexit 1\n`,
        { encoding: "utf8", mode: 0o755 },
      );

      // 2. Write file and stage with git.add
      fs.writeFileSync(path.join(ws, "hello.txt"), "line 1\n", "utf8");
      const addRes = await taskManager.submitAndRun({
        toolName: "git.add",
        category: "git",
        input: { paths: ["hello.txt"] },
        workingDirectory: ws,
        actor: "test-agent",
      });
      expect(addRes.task.status).toBe("COMPLETED");

      // 3. git.diff staged (AUTO)
      const diffRes = await taskManager.submitAndRun({
        toolName: "git.diff",
        category: "git",
        input: { staged: true },
        workingDirectory: ws,
        actor: "test-agent",
      });
      expect(diffRes.task.status).toBe("COMPLETED");
      expect(diffRes.task.policyLevel).toBe("AUTO");
      expect(diffRes.result?.stdout).toContain("+line 1");

      // 4. git.commit (must succeed and NEVER run the malicious pre-commit hook!)
      const commitRes = await taskManager.submitAndRun({
        toolName: "git.commit",
        category: "git",
        input: { message: "feat: initial commit" },
        workingDirectory: ws,
        actor: "test-agent",
      });
      expect(commitRes.task.status).toBe("COMPLETED");
      expect(fs.existsSync(hookMarker)).toBe(false);

      // 5. git.status & git.log (AUTO)
      const statusRes = await taskManager.submitAndRun({
        toolName: "git.status",
        category: "git",
        input: {},
        workingDirectory: ws,
        actor: "test-agent",
      });
      expect(statusRes.task.status).toBe("COMPLETED");
      expect(statusRes.task.policyLevel).toBe("AUTO");

      const logRes = await taskManager.submitAndRun({
        toolName: "git.log",
        category: "git",
        input: { limit: 5 },
        workingDirectory: ws,
        actor: "test-agent",
      });
      expect(logRes.task.status).toBe("COMPLETED");
      expect(logRes.result?.stdout).toContain("feat: initial commit");

      // 6. git.checkout createBranch -> commit -> checkout main -> merge -> delete branch
      const coFeat = await taskManager.submitAndRun({
        toolName: "git.checkout",
        category: "git",
        input: { target: "feat-branch", createBranch: true },
        workingDirectory: ws,
        actor: "test-agent",
      });
      expect(coFeat.task.status).toBe("COMPLETED");

      fs.writeFileSync(path.join(ws, "hello.txt"), "line 1\nline 2\n", "utf8");
      await taskManager.submitAndRun({
        toolName: "git.add",
        category: "git",
        input: { paths: ["hello.txt"] },
        workingDirectory: ws,
        actor: "test-agent",
      });
      await taskManager.submitAndRun({
        toolName: "git.commit",
        category: "git",
        input: { message: "feat: add line 2" },
        workingDirectory: ws,
        actor: "test-agent",
      });

      const coMain = await taskManager.submitAndRun({
        toolName: "git.checkout",
        category: "git",
        input: { target: "main" },
        workingDirectory: ws,
        actor: "test-agent",
      });
      expect(coMain.task.status).toBe("COMPLETED");

      const mergeRes = await taskManager.submitAndRun({
        toolName: "git.merge",
        category: "git",
        input: { branch: "feat-branch", ffOnly: true },
        workingDirectory: ws,
        actor: "test-agent",
      });
      expect(mergeRes.task.status).toBe("COMPLETED");

      const delBranch = await taskManager.submitAndRun({
        toolName: "git.branch",
        category: "git",
        input: { action: "delete", name: "feat-branch" },
        workingDirectory: ws,
        actor: "test-agent",
      });
      expect(delBranch.task.status).toBe("COMPLETED");
      expect(delBranch.task.policyLevel).toBe("HUMAN_APPROVAL");

      // 7. git.tag create, list (AUTO), delete (HUMAN_APPROVAL)
      const tagCreate = await taskManager.submitAndRun({
        toolName: "git.tag",
        category: "git",
        input: { action: "create", name: "v0.1.0", message: "Release 0.1.0" },
        workingDirectory: ws,
        actor: "test-agent",
      });
      expect(tagCreate.task.status).toBe("COMPLETED");

      const tagList = await taskManager.submitAndRun({
        toolName: "git.tag",
        category: "git",
        input: { action: "list" },
        workingDirectory: ws,
        actor: "test-agent",
      });
      expect(tagList.task.status).toBe("COMPLETED");
      expect(tagList.task.policyLevel).toBe("AUTO");
      expect(tagList.result?.stdout).toContain("v0.1.0");
    } finally {
      db.close();
    }
  });

  it("blocks staging/committing .env secrets, option injection, force flags, unsafe clone URLs and unapproved git.push", async () => {
    const ws = createTempDir("synapse-git-sec-");
    execFileSync("git", ["init", "-b", "main"], { cwd: ws });
    execFileSync("git", ["config", "user.name", "Test Bot"], { cwd: ws });
    execFileSync("git", ["config", "user.email", "test@example.com"], { cwd: ws });
    fs.writeFileSync(path.join(ws, ".env"), "API_KEY=secret", "utf8");

    // 1. Non-interactive harness: git.push must require HUMAN_APPROVAL and fail-closed
    const { db: dbNonInt, taskManager: tmNonInt } = createGitTestHarness(ws);
    try {
      const pushDenied = await tmNonInt.submitAndRun({
        toolName: "git.push",
        category: "git",
        input: { remote: "origin", branch: "main" },
        workingDirectory: ws,
        actor: "test-agent",
      });
      expect(pushDenied.task.status).toBe("DENIED");
      expect(pushDenied.task.policyLevel).toBe("HUMAN_APPROVAL");
    } finally {
      dbNonInt.close();
    }

    // 2. Adversarial inputs must be DENIED even if an operator handler would approve
    const { db, taskManager } = createGitTestHarness(ws, {
      approvalHandler: {
        async requestApproval() {
          return { approved: true, approvedBy: "operator" };
        },
      },
    });

    try {
      for (const bad of [
        { toolName: "git.add", input: { paths: [".env"] } },
        { toolName: "git.add", input: { paths: ["../outside.txt"] } },
        { toolName: "git.add", input: { paths: ["--force"] } },
        { toolName: "git.branch", input: { action: "create", name: "--force" } },
        { toolName: "git.branch", input: { action: "create", name: "bad..name" } },
        { toolName: "git.checkout", input: { target: "--orphan" } },
        { toolName: "git.push", input: { remote: "origin", branch: "+main:main" } },
        { toolName: "git.push", input: { remote: "origin", branch: "main", force: true } },
        { toolName: "git.clone", input: { url: "ext::sh -c whoami", directory: "sub" } },
        { toolName: "git.clone", input: { url: "file:///C:/repo", directory: "sub" } },
        {
          toolName: "git.clone",
          input: { url: "https://github.com/a/b.git", directory: "../out" },
        },
      ]) {
        const res = await taskManager.submitAndRun({
          toolName: bad.toolName,
          category: "git",
          input: bad.input,
          workingDirectory: ws,
          actor: "adversary",
        });
        expect(res.task.status).toBe("DENIED");
      }

      // 3. Even if .env is force-staged outside SYNAPSE, git.commit preflight refuses to commit it
      execFileSync("git", ["add", "-f", ".env"], { cwd: ws });
      const commitSecret = await taskManager.submitAndRun({
        toolName: "git.commit",
        category: "git",
        input: { message: "attempt to commit secret" },
        workingDirectory: ws,
        actor: "adversary",
      });
      expect(commitSecret.task.status).toBe("FAILED");
      expect(commitSecret.result?.stderr).toContain("Refusing to commit sensitive files");
    } finally {
      db.close();
    }
  });

  it("serializes concurrent mutating Git operations in the same workspace without index.lock conflicts", async () => {
    const ws = createTempDir("synapse-git-conc-");
    execFileSync("git", ["init", "-b", "main"], { cwd: ws });
    execFileSync("git", ["config", "user.name", "Test Bot"], { cwd: ws });
    execFileSync("git", ["config", "user.email", "test@example.com"], { cwd: ws });
    fs.writeFileSync(path.join(ws, "base.txt"), "base\n", "utf8");
    execFileSync("git", ["add", "base.txt"], { cwd: ws });
    execFileSync("git", ["commit", "-m", "initial"], { cwd: ws });

    for (let i = 1; i <= 5; i += 1) {
      fs.writeFileSync(path.join(ws, `f${i}.txt`), `content ${i}\n`, "utf8");
    }

    const { db, taskManager } = createGitTestHarness(ws, {
      approvalHandler: {
        async requestApproval() {
          return { approved: true, approvedBy: "operator" };
        },
      },
    });

    try {
      const outcomes = await Promise.all(
        [1, 2, 3, 4, 5].map((i) =>
          taskManager.submitAndRun({
            toolName: "git.add",
            category: "git",
            input: { paths: [`f${i}.txt`] },
            workingDirectory: ws,
            actor: `worker-${i}`,
          }),
        ),
      );

      for (const outcome of outcomes) {
        expect(outcome.task.status).toBe("COMPLETED");
      }
    } finally {
      db.close();
    }
  });
});
