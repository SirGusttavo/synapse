import { execFileSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { createCliProgram } from "../../src/cli/program.js";
import { SynapseRuntime } from "../../src/core/runtime.js";
import {
  detectDangerousLocalConfigEntries,
  ensureControlledEmptyHooksDir,
} from "../../src/modules/git-manager/index.js";
import type { IApprovalHandler } from "../../src/modules/security/index.js";
import { DEFAULT_PROCESS_WORKSPACE_LOCK } from "../../src/modules/task-manager/index.js";

const tempDirs: string[] = [];

function createTempDir(prefix = "synapse-p2-sec-"): string {
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

const autoApprove: IApprovalHandler = {
  async requestApproval() {
    return { approved: true, approvedBy: "audit-operator" };
  },
};

describe("Phase 2 Supplementary Security Audit — 1. Git Hook Containment", () => {
  it("neutralizes hooks even when an untrusted repo plants .git/__synapse_disabled_hooks__ across commit, checkout, merge and push, and works in worktrees (.git as file)", async () => {
    const ws = createTempDir("synapse-hook-ws-");
    const bareRemote = createTempDir("synapse-hook-remote-");
    const worktreeDir = path.join(ws, "wt-sub");

    execFileSync("git", ["init", "--bare", "-b", "main"], { cwd: bareRemote });
    execFileSync("git", ["init", "-b", "main"], { cwd: ws });
    execFileSync("git", ["config", "user.name", "Audit Bot"], { cwd: ws });
    execFileSync("git", ["config", "user.email", "audit@example.com"], { cwd: ws });

    const markerFile = path.join(ws, "HOOK_PWNED_MARKER.txt");
    const hookPayload = `#!/bin/sh\necho PWNED >> "${markerFile.replace(/\\/g, "/")}"\nexit 1\n`;

    // Plant hooks in BOTH standard .git/hooks AND the old relative .git/__synapse_disabled_hooks__
    for (const dirName of ["hooks", "__synapse_disabled_hooks__"]) {
      const hDir = path.join(ws, ".git", dirName);
      fs.mkdirSync(hDir, { recursive: true });
      for (const hookName of [
        "pre-commit",
        "commit-msg",
        "post-commit",
        "post-checkout",
        "pre-merge-commit",
        "post-merge",
        "pre-rebase",
        "pre-push",
      ]) {
        fs.writeFileSync(path.join(hDir, hookName), hookPayload, { mode: 0o755 });
      }
    }

    // Verify controlled external empty hooks dir is outside workspace and empty
    const controlledHooksDir = ensureControlledEmptyHooksDir();
    expect(controlledHooksDir.startsWith(ws)).toBe(false);
    expect(fs.readdirSync(controlledHooksDir)).toHaveLength(0);

    const runtime = SynapseRuntime.create({
      workspaceDir: ws,
      inMemoryDb: true,
      approvalHandler: autoApprove,
      overrides: { logging: { level: "silent", pretty: false } },
    });

    try {
      // 1. Commit cycle
      fs.writeFileSync(path.join(ws, "a.txt"), "v1\n", "utf8");
      expect((await runtime.executeTool("git.add", "git", { paths: ["a.txt"] })).task.status).toBe(
        "COMPLETED",
      );
      expect(
        (await runtime.executeTool("git.commit", "git", { message: "feat: v1" })).task.status,
      ).toBe("COMPLETED");
      expect(fs.existsSync(markerFile)).toBe(false);

      // 2. Checkout & Merge cycle
      expect(
        (
          await runtime.executeTool("git.checkout", "git", {
            target: "side",
            createBranch: true,
          })
        ).task.status,
      ).toBe("COMPLETED");
      fs.writeFileSync(path.join(ws, "a.txt"), "v1\nv2\n", "utf8");
      await runtime.executeTool("git.add", "git", { paths: ["a.txt"] });
      await runtime.executeTool("git.commit", "git", { message: "feat: v2" });

      expect(
        (await runtime.executeTool("git.checkout", "git", { target: "main" })).task.status,
      ).toBe("COMPLETED");
      expect(
        (await runtime.executeTool("git.merge", "git", { branch: "side", noFf: true })).task.status,
      ).toBe("COMPLETED");
      expect(fs.existsSync(markerFile)).toBe(false);

      // 3. Push cycle (pre-push hook must be suppressed)
      execFileSync("git", ["remote", "add", "origin", bareRemote], { cwd: ws });
      expect(
        (
          await runtime.executeTool("git.push", "git", {
            remote: "origin",
            branch: "main",
            setUpstream: true,
          })
        ).task.status,
      ).toBe("COMPLETED");
      expect(fs.existsSync(markerFile)).toBe(false);

      // 4. Worktree where .git is a regular FILE ("gitdir: ...")
      execFileSync(
        "git",
        [
          "-c",
          `core.hooksPath=${controlledHooksDir}`,
          "worktree",
          "add",
          "-b",
          "wt-branch",
          worktreeDir,
          "main",
        ],
        { cwd: ws },
      );
      expect(fs.lstatSync(path.join(worktreeDir, ".git")).isFile()).toBe(true);

      fs.writeFileSync(path.join(worktreeDir, "wt.txt"), "from worktree\n", "utf8");
      expect(
        (await runtime.executeTool("git.add", "git", { paths: ["wt.txt"] }, { cwd: worktreeDir }))
          .task.status,
      ).toBe("COMPLETED");
      expect(
        (
          await runtime.executeTool(
            "git.commit",
            "git",
            { message: "feat: worktree commit" },
            { cwd: worktreeDir },
          )
        ).task.status,
      ).toBe("COMPLETED");
      expect(fs.existsSync(markerFile)).toBe(false);
    } finally {
      runtime.close();
    }
  });
});

describe("Phase 2 Supplementary Security Audit — 2. Git Configuration Injection", () => {
  it("allows system/global credential.helper and lfs while blocking dangerous local/worktree config keys", () => {
    const sampleScopedOutput = [
      "system\tcredential.helper=manager",
      "system\tfilter.lfs.clean=git-lfs clean -- %f",
      "global\tuser.name=Gustavo Rafael",
      "local\tcore.repositoryformatversion=0",
      "local\tfilter.evil.clean=sh -c evil",
      "local\tdiff.external=sh -c evil-diff",
      "local\tmerge.custom.driver=sh -c evil-merge",
      "local\tcore.sshcommand=sh -c evil-ssh",
      "local\tcredential.helper=sh -c steal-creds",
      "local\tcore.pager=sh -c evil-pager",
      "local\tcore.fsmonitor=sh -c evil-mon",
      "local\turl.https://evil.example/.insteadof=https://github.com/",
      "local\talias.status=!sh -c evil",
      "local\tinclude.path=../evil.gitconfig",
      "worktree\tremote.origin.uploadpack=sh -c evil-pack",
    ].join("\n");

    const violations = detectDangerousLocalConfigEntries(sampleScopedOutput);
    const keys = violations.map((v) => v.key);

    expect(keys).toEqual([
      "filter.evil.clean",
      "diff.external",
      "merge.custom.driver",
      "core.sshcommand",
      "credential.helper",
      "core.pager",
      "core.fsmonitor",
      "url.https://evil.example/.insteadof",
      "alias.status",
      "include.path",
      "remote.origin.uploadpack",
    ]);
  });

  it("prevents RCE from repository-local filter.clean + .gitattributes during git.add / git.status", async () => {
    const ws = createTempDir("synapse-git-cfg-rce-");
    execFileSync("git", ["init", "-b", "main"], { cwd: ws });
    execFileSync("git", ["config", "user.name", "Audit Bot"], { cwd: ws });
    execFileSync("git", ["config", "user.email", "audit@example.com"], { cwd: ws });

    const rceMarker = path.join(ws, "FILTER_RCE_MARKER.txt");
    execFileSync(
      "git",
      [
        "config",
        "--local",
        "filter.evil.clean",
        `sh -c "echo RCE > '${rceMarker.replace(/\\/g, "/")}' && cat"`,
      ],
      { cwd: ws },
    );
    fs.writeFileSync(path.join(ws, ".gitattributes"), "*.txt filter=evil\n", "utf8");
    fs.writeFileSync(path.join(ws, "payload.txt"), "hello\n", "utf8");

    const runtime = SynapseRuntime.create({
      workspaceDir: ws,
      inMemoryDb: true,
      approvalHandler: autoApprove,
      overrides: { logging: { level: "silent", pretty: false } },
    });

    try {
      const addRes = await runtime.executeTool("git.add", "git", { paths: ["payload.txt"] });
      expect(addRes.task.status).toBe("FAILED");
      expect(addRes.result?.stderr).toContain(
        "Blocked dangerous repository-local Git configuration",
      );
      expect(addRes.result?.stderr).toContain("filter.evil.clean");
      expect(fs.existsSync(rceMarker)).toBe(false);
    } finally {
      runtime.close();
    }
  });
});

describe("Phase 2 Supplementary Security Audit — 3. WorkspaceLock Multi-Runtime Scope", () => {
  it("coordinates concurrent mutations across multiple SynapseRuntime instances in the same Node.js process", async () => {
    const ws = createTempDir("synapse-multi-rt-");
    const rt1 = SynapseRuntime.create({
      workspaceDir: ws,
      inMemoryDb: true,
      overrides: { logging: { level: "silent", pretty: false } },
    });
    const rt2 = SynapseRuntime.create({
      workspaceDir: ws,
      inMemoryDb: true,
      overrides: { logging: { level: "silent", pretty: false } },
    });

    try {
      expect(rt1.taskManager.workspaceLock).toBe(DEFAULT_PROCESS_WORKSPACE_LOCK);
      expect(rt2.taskManager.workspaceLock).toBe(DEFAULT_PROCESS_WORKSPACE_LOCK);

      const [r1, r2] = await Promise.all([
        rt1.executeTool("file.create", "file", {
          path: "shared.txt",
          content: "v1",
          overwrite: true,
        }),
        rt2.executeTool("file.create", "file", {
          path: "shared.txt",
          content: "v2",
          overwrite: true,
        }),
      ]);

      expect(r1.task.status).toBe("COMPLETED");
      expect(r2.task.status).toBe("COMPLETED");
      expect(DEFAULT_PROCESS_WORKSPACE_LOCK.getDiagnostics(ws)).toEqual({
        activeReaders: 0,
        writerActive: false,
        queuedCount: 0,
      });
    } finally {
      rt1.close();
      rt2.close();
    }
  });
});

describe("Phase 2 Supplementary Security Audit — 4. Git CLI Coverage Parity", () => {
  it("exposes all 13 GitManager operations as CLI subcommands under 'synapse git'", () => {
    const { program } = createCliProgram();
    const gitCommand = program.commands.find((c) => c.name() === "git");
    expect(gitCommand).toBeDefined();

    const subcommandNames = (gitCommand?.commands ?? []).map((c) => c.name()).sort();
    expect(subcommandNames).toEqual(
      [
        "add",
        "branch",
        "checkout",
        "clone",
        "commit",
        "diff",
        "init",
        "log",
        "merge",
        "pull",
        "push",
        "status",
        "tag",
      ].sort(),
    );
  });
});

describe("Phase 2 Supplementary Security Audit — 5. FileManager NTFS Hardlinks & Reparse Chains", () => {
  it("blocks NTFS hardlink aliasing of .env and hides hardlinked files from list and search", async () => {
    const ws = createTempDir("synapse-hardlink-ws-");
    const envPath = path.join(ws, ".env");
    const aliasPath = path.join(ws, "innocent.txt");

    fs.writeFileSync(envPath, "ANTHROPIC_API_KEY=sk-ant-topsecretvalue123456\n", "utf8");
    fs.linkSync(envPath, aliasPath);

    const runtime = SynapseRuntime.create({
      workspaceDir: ws,
      inMemoryDb: true,
      approvalHandler: autoApprove,
      overrides: { logging: { level: "silent", pretty: false } },
    });

    try {
      // 1. Direct read of hardlink alias must be DENIED
      const readRes = await runtime.executeTool("file.read", "file", { path: "innocent.txt" });
      expect(readRes.task.status).toBe("DENIED");
      expect(readRes.deniedReasons?.join(" ")).toContain("hardlinked file");

      // 2. Edit of hardlink alias must be DENIED
      const editRes = await runtime.executeTool("file.edit", "file", {
        path: "innocent.txt",
        search: "ANTHROPIC",
        replace: "MODIFIED",
      });
      expect(editRes.task.status).toBe("DENIED");

      // 3. List and Search must omit the hardlinked file
      const listRes = await runtime.executeTool("file.list", "file", { path: "." });
      expect(listRes.result?.stdout).not.toContain("innocent.txt");

      const searchRes = await runtime.executeTool("file.search", "file", { query: "topsecret" });
      expect(searchRes.result?.stdout).toBe("");

      // 4. Approved file.delete CAN remove the hardlink entry without deleting .env
      const delRes = await runtime.executeTool("file.delete", "file", { path: "innocent.txt" });
      expect(delRes.task.status).toBe("COMPLETED");
      expect(fs.existsSync(aliasPath)).toBe(false);
      expect(fs.existsSync(envPath)).toBe(true);
    } finally {
      runtime.close();
    }
  });

  it("blocks NTFS junction traversal even when the junction points to another directory inside the workspace", async () => {
    const ws = createTempDir("synapse-in-junc-");
    const realDir = path.join(ws, "real-sub");
    const junctionDir = path.join(ws, "junction-sub");
    fs.mkdirSync(realDir, { recursive: true });
    fs.writeFileSync(path.join(realDir, "hello.txt"), "hello\n", "utf8");
    fs.symlinkSync(realDir, junctionDir, "junction");

    const runtime = SynapseRuntime.create({
      workspaceDir: ws,
      inMemoryDb: true,
      overrides: { logging: { level: "silent", pretty: false } },
    });

    try {
      // Reading via real path is AUTO / COMPLETED
      const realRead = await runtime.executeTool("file.read", "file", {
        path: "real-sub/hello.txt",
      });
      expect(realRead.task.status).toBe("COMPLETED");

      // Reading via NTFS junction path chain is DENIED (reparse_point_traversal)
      const juncRead = await runtime.executeTool("file.read", "file", {
        path: "junction-sub/hello.txt",
      });
      expect(juncRead.task.status).toBe("DENIED");
      expect(juncRead.deniedReasons?.join(" ")).toContain("symbolic link or NTFS junction");
    } finally {
      runtime.close();
    }
  });
});
