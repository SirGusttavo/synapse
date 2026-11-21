import { execFileSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { runCli } from "../../src/cli/program.js";
import type { IApprovalHandler } from "../../src/modules/security/index.js";

const tempDirs: string[] = [];

function createTempWorkspace(): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "synapse-cli-e2e-"));
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

describe("Integration — SYNAPSE CLI end-to-end (Shell, File Manager, Git Manager)", () => {
  it("executes authorized PowerShell commands, audits in SQLite, blocks denied commands and exposes status/config", async () => {
    const ws = createTempWorkspace();
    fs.writeFileSync(
      path.join(ws, ".env"),
      "OPENAI_API_KEY=sk-must-never-appear-in-output\n",
      "utf8",
    );

    // 1. Authorized execution via CLI
    let out1 = "";
    let err1 = "";
    const code1 = await runCli(
      [
        "node",
        "synapse",
        "exec",
        "Write-Output 'SYNAPSE CLI OK'",
        "-w",
        ws,
        "--log-level",
        "silent",
      ],
      {
        stdout: (t) => {
          out1 += t;
        },
        stderr: (t) => {
          err1 += t;
        },
      },
    );

    expect(code1).toBe(0);
    expect(out1.trim()).toBe("SYNAPSE CLI OK");
    expect(err1).toBe("");

    // 2. Blocked command via CLI
    let out2 = "";
    let err2 = "";
    const code2 = await runCli(
      [
        "node",
        "synapse",
        "exec",
        "git push --force origin main",
        "-w",
        ws,
        "--log-level",
        "silent",
      ],
      {
        stdout: (t) => {
          out2 += t;
        },
        stderr: (t) => {
          err2 += t;
        },
      },
    );

    expect(code2).toBe(126);
    expect(out2).toBe("");
    expect(err2).toContain("[DENIED]");

    // 3. Query audit trail via CLI
    let auditJson = "";
    const code3 = await runCli(["node", "synapse", "audit", "-w", ws, "--json"], {
      stdout: (t) => {
        auditJson += t;
      },
      stderr: () => {},
    });

    expect(code3).toBe(0);
    const events = JSON.parse(auditJson) as Array<{ status: string; operation: string }>;
    expect(events).toHaveLength(2);
    expect(events.map((e) => e.status).sort()).toEqual(["COMPLETED", "DENIED"]);

    // 4. Inspect status via CLI (all 21 tools registered!)
    let statusJson = "";
    const code4 = await runCli(["node", "synapse", "status", "-w", ws, "--json"], {
      stdout: (t) => {
        statusJson += t;
      },
      stderr: () => {},
    });

    expect(code4).toBe(0);
    const status = JSON.parse(statusJson) as {
      shell: { available: boolean };
      registeredTools: string[];
      singleFileDeletePermission: string;
    };
    expect(status.shell.available).toBe(true);
    expect(status.registeredTools).toHaveLength(21);
    expect(status.registeredTools).toContain("shell.exec");
    expect(status.registeredTools).toContain("file.create");
    expect(status.registeredTools).toContain("git.commit");
    expect(status.singleFileDeletePermission).toBe("HUMAN_APPROVAL");

    // 5. Inspect config via CLI (never leaks .env secrets)
    let configOut = "";
    const code5 = await runCli(["node", "synapse", "config", "-w", ws], {
      stdout: (t) => {
        configOut += t;
      },
      stderr: () => {},
    });

    expect(code5).toBe(0);
    expect(configOut).not.toContain("sk-must-never-appear-in-output");
    expect(JSON.parse(configOut)).toHaveProperty("workspaceDir");
  });

  it("executes typed file and git CLI subcommands without shell.exec", async () => {
    const ws = createTempWorkspace();
    const approveHandler: IApprovalHandler = {
      async requestApproval() {
        return { approved: true, approvedBy: "cli-test-operator" };
      },
    };

    const run = async (args: string[], approve = true) => {
      let stdout = "";
      let stderr = "";
      const code = await runCli(["node", "synapse", ...args, "-w", ws, "--log-level", "silent"], {
        stdout: (t) => {
          stdout += t;
        },
        stderr: (t) => {
          stderr += t;
        },
        approvalHandler: approve ? approveHandler : undefined,
      });
      return { code, stdout, stderr };
    };

    // 1. file create -> edit -> read -> search
    expect((await run(["file", "create", "notes.txt", "--content", "hello world\n"])).code).toBe(0);
    expect(
      (await run(["file", "edit", "notes.txt", "--search", "world", "--replace", "SYNAPSE"])).code,
    ).toBe(0);

    const readOut = await run(["file", "read", "notes.txt"]);
    expect(readOut.code).toBe(0);
    expect(readOut.stdout.trim()).toBe("hello SYNAPSE");

    const searchOut = await run(["file", "search", "SYNAPSE"]);
    expect(searchOut.code).toBe(0);
    expect(searchOut.stdout).toContain("notes.txt:1:");

    // 2. git init -> add -> commit -> status -> log
    expect((await run(["git", "init", "-b", "main"])).code).toBe(0);
    execFileSync("git", ["config", "user.name", "CLI Tester"], { cwd: ws });
    execFileSync("git", ["config", "user.email", "cli@example.com"], { cwd: ws });

    expect((await run(["git", "add", "notes.txt"])).code).toBe(0);
    expect((await run(["git", "commit", "-m", "docs: add notes"])).code).toBe(0);

    const logOut = await run(["git", "log", "-n", "1"]);
    expect(logOut.code).toBe(0);
    expect(logOut.stdout).toContain("docs: add notes");

    // 3. file delete without approval fails closed (exit 126), with approval succeeds (exit 0)
    expect((await run(["file", "delete", "notes.txt"], false)).code).toBe(126);
    expect((await run(["file", "delete", "notes.txt"], true)).code).toBe(0);
  });
});
