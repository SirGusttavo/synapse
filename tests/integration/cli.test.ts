import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { runCli } from "../../src/cli/program.js";

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

describe("Integration — SYNAPSE CLI end-to-end", () => {
  it("executes an authorized PowerShell command, audits it in SQLite, blocks denied commands and exposes status/config", async () => {
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

    // 4. Inspect status via CLI
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
    expect(status.registeredTools).toContain("shell.exec");
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
});
