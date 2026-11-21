import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { PolicyDeniedError } from "../../core/errors.js";
import type { IProcessRunner } from "../execution-engine/process-runner.js";
import { inspectWorkspacePath, isSensitiveFilePath } from "../security/workspace-guard.js";

const CONTROLLED_EMPTY_HOOKS_DIR = path.join(os.tmpdir(), "synapse-controlled-empty-hooks");

/**
 * Ensures an absolute, empty, SYNAPSE-controlled directory outside the workspace
 * exists and is free of symlinks/junctions or injected hook files.
 * Works uniformly for normal repositories, subdirectories and worktrees (.git as file).
 */
export function ensureControlledEmptyHooksDir(): string {
  if (fs.existsSync(CONTROLLED_EMPTY_HOOKS_DIR)) {
    const stat = fs.lstatSync(CONTROLLED_EMPTY_HOOKS_DIR);
    if (stat.isSymbolicLink() || !stat.isDirectory()) {
      fs.rmSync(CONTROLLED_EMPTY_HOOKS_DIR, { recursive: true, force: true });
      fs.mkdirSync(CONTROLLED_EMPTY_HOOKS_DIR, { recursive: true, mode: 0o700 });
    } else {
      for (const entry of fs.readdirSync(CONTROLLED_EMPTY_HOOKS_DIR)) {
        fs.rmSync(path.join(CONTROLLED_EMPTY_HOOKS_DIR, entry), { recursive: true, force: true });
      }
    }
  } else {
    fs.mkdirSync(CONTROLLED_EMPTY_HOOKS_DIR, { recursive: true, mode: 0o700 });
  }
  return CONTROLLED_EMPTY_HOOKS_DIR;
}

/**
 * Mandatory Git containment flags passed to every Git invocation:
 * - forces `core.hooksPath` to an absolute empty directory outside the workspace
 * - disables fsmonitor daemon execution
 * - disables interactive pagers and editors
 * - disables arbitrary command/local-filesystem transports (`ext::`, `file://`)
 */
export function buildSafeGitGlobalArgs(): string[] {
  const emptyHooksDir = ensureControlledEmptyHooksDir();
  return [
    "-c",
    `core.hooksPath=${emptyHooksDir}`,
    "-c",
    "core.fsmonitor=false",
    "-c",
    "core.pager=cat",
    "-c",
    "core.editor=false",
    "-c",
    "protocol.ext.allow=never",
    "-c",
    "protocol.file.allow=never",
  ];
}

/**
 * Local/worktree `.git/config` keys that can trigger arbitrary command execution,
 * credential exfiltration or transport hijacking when supplied by an untrusted repository.
 * Note: system and global scopes (e.g. Git Credential Manager, global Git LFS) remain allowed.
 */
const DANGEROUS_LOCAL_CONFIG_KEY_PATTERNS: ReadonlyArray<{
  pattern: RegExp;
  reason: string;
}> = [
  {
    pattern: /^filter\..+\.(?:clean|smudge|process)$/i,
    reason: "Repository-local filter driver (clean/smudge/process) can execute arbitrary commands",
  },
  {
    pattern: /^diff\.external$|^diff\..+\.(?:command|textconv)$/i,
    reason: "Repository-local external diff or textconv driver can execute arbitrary commands",
  },
  {
    pattern: /^merge\..+\.driver$/i,
    reason: "Repository-local custom merge driver can execute arbitrary commands",
  },
  {
    pattern: /^core\.(?:sshcommand|gitproxy|askpass|fsmonitor|hookspath|pager|editor)$/i,
    reason: "Repository-local core execution override is forbidden",
  },
  {
    pattern: /^credential(?:\..+)?\.helper$/i,
    reason: "Repository-local credential.helper override is forbidden (use system/global auth)",
  },
  {
    pattern: /^url\..+\.(?:insteadof|pushinsteadof)$/i,
    reason: "Repository-local URL rewrite (insteadOf / pushInsteadOf) is forbidden",
  },
  {
    pattern: /^remote\..+\.(?:uploadpack|receivepack|proxy|vcs)$/i,
    reason: "Repository-local remote transport command override is forbidden",
  },
  {
    pattern: /^alias\..+$/i,
    reason: "Repository-local Git aliases are forbidden",
  },
  {
    pattern: /^include\.path$|^includeif\..+\.path$/i,
    reason: "Repository-local config include directives are forbidden",
  },
  {
    pattern: /^protocol(?:\..+)?\.allow$/i,
    reason: "Repository-local protocol.allow override is forbidden",
  },
  {
    pattern: /^init\.templatedir$/i,
    reason: "Repository-local init.templateDir override is forbidden",
  },
  {
    pattern: /^gpg(?:\..+)?\.program$/i,
    reason: "Repository-local gpg.program override is forbidden",
  },
];

export interface DangerousGitConfigViolation {
  scope: "local" | "worktree";
  key: string;
  reason: string;
}

export function detectDangerousLocalConfigEntries(
  scopedConfigOutput: string,
): DangerousGitConfigViolation[] {
  const violations: DangerousGitConfigViolation[] = [];
  const lines = scopedConfigOutput.split(/\r?\n/);

  for (const rawLine of lines) {
    if (rawLine.trim().length === 0) {
      continue;
    }
    const tabIdx = rawLine.indexOf("\t");
    if (tabIdx <= 0) {
      continue;
    }
    const scope = rawLine.slice(0, tabIdx).trim().toLowerCase();
    if (scope !== "local" && scope !== "worktree") {
      continue;
    }

    const rest = rawLine.slice(tabIdx + 1);
    const eqIdx = rest.indexOf("=");
    const key = (eqIdx >= 0 ? rest.slice(0, eqIdx) : rest).trim().toLowerCase();

    for (const rule of DANGEROUS_LOCAL_CONFIG_KEY_PATTERNS) {
      if (rule.pattern.test(key)) {
        violations.push({
          scope,
          key,
          reason: rule.reason,
        });
        break;
      }
    }
  }

  return violations;
}

const INVALID_REF_CHARS = /[\0-\x20~^:?*[\\]|(?:\.\.)|(?:\.lock$)|(?:@\{)|(?:\/\/)/;

export function assertSafeGitRef(value: string, fieldLabel: string): void {
  const trimmed = value.trim();
  if (trimmed.length === 0 || trimmed !== value) {
    throw new PolicyDeniedError(
      `Invalid Git ${fieldLabel}: cannot be empty or padded with spaces`,
      {
        details: { field: fieldLabel, value },
      },
    );
  }
  if (trimmed.startsWith("-")) {
    throw new PolicyDeniedError(
      `Option injection blocked in Git ${fieldLabel}: cannot start with '-'`,
      { details: { field: fieldLabel, value } },
    );
  }
  if (trimmed.startsWith("+")) {
    throw new PolicyDeniedError(
      `Force refspec blocked in Git ${fieldLabel}: cannot start with '+'`,
      { details: { field: fieldLabel, value } },
    );
  }
  if (trimmed.startsWith("/") || trimmed.endsWith("/") || trimmed.endsWith(".")) {
    throw new PolicyDeniedError(`Invalid Git ${fieldLabel} format: ${value}`, {
      details: { field: fieldLabel, value },
    });
  }
  if (INVALID_REF_CHARS.test(trimmed)) {
    throw new PolicyDeniedError(`Invalid characters in Git ${fieldLabel}: ${value}`, {
      details: { field: fieldLabel, value },
    });
  }
}

export function assertSafeCloneUrl(url: string): void {
  const trimmed = url.trim();
  if (trimmed.length === 0 || trimmed.includes("\0") || trimmed.startsWith("-")) {
    throw new PolicyDeniedError("Invalid or unsafe Git clone URL", {
      details: { url },
    });
  }
  if (/^ext::/i.test(trimmed) || /^file:\/\//i.test(trimmed)) {
    throw new PolicyDeniedError("Blocked unsafe Git protocol in clone URL", {
      details: { url },
    });
  }
  const isHttps = /^https:\/\/[^\s/$.?#].[^\s]*$/i.test(trimmed);
  const isSshUrl = /^ssh:\/\/[^\s]+$/i.test(trimmed);
  const isScpLike = /^[A-Za-z0-9._-]+@[A-Za-z0-9._-]+:[^\s]+$/.test(trimmed);

  if (!isHttps && !isSshUrl && !isScpLike) {
    throw new PolicyDeniedError(
      "Git clone URL must use https:// or ssh:// (or git@host:repo syntax)",
      { details: { url } },
    );
  }
}

export function assertSafeGitPaths(
  workspaceDir: string,
  workingDirectory: string,
  paths: readonly string[],
  options: { allowOutsideWorkspace: boolean; forbidSensitive: boolean },
): void {
  for (const rawPath of paths) {
    if (rawPath.startsWith("-")) {
      throw new PolicyDeniedError(
        `Git path cannot start with '-' (use './${rawPath}' if referencing a file): ${rawPath}`,
        { details: { path: rawPath } },
      );
    }

    const info = inspectWorkspacePath(workspaceDir, workingDirectory, rawPath);
    if (!info.insideWorkspace && !options.allowOutsideWorkspace) {
      throw new PolicyDeniedError(`Git path escapes authorized workspace: ${rawPath}`, {
        details: { path: rawPath },
      });
    }
    if (options.forbidSensitive && info.isSensitive) {
      throw new PolicyDeniedError(
        `Staging or operating on sensitive credential file is blocked: ${rawPath}`,
        { details: { path: rawPath } },
      );
    }
    if (info.isInternalGit) {
      throw new PolicyDeniedError(`Git path cannot target internal .git directory: ${rawPath}`, {
        details: { path: rawPath },
      });
    }
  }
}

export interface GitRepositoryInspection {
  isRepo: boolean;
  currentBranch: string | null;
  isClean: boolean;
  hasConflicts: boolean;
  stagedFiles: string[];
  configViolations: DangerousGitConfigViolation[];
}

export async function inspectGitRepository(
  processRunner: IProcessRunner,
  cwd: string,
  signal?: AbortSignal,
): Promise<GitRepositoryInspection> {
  const safeGlobalArgs = buildSafeGitGlobalArgs();

  const revParse = await processRunner.run({
    executable: "git",
    args: [...safeGlobalArgs, "rev-parse", "--is-inside-work-tree"],
    cwd,
    timeoutMs: 5_000,
    maxOutputBytes: 4_096,
    signal,
  });

  if (revParse.status !== "completed" || revParse.stdout.trim() !== "true") {
    return {
      isRepo: false,
      currentBranch: null,
      isClean: false,
      hasConflicts: false,
      stagedFiles: [],
      configViolations: [],
    };
  }

  // Inspect repository-local and worktree config BEFORE running any command that touches index/working-tree
  const configRes = await processRunner.run({
    executable: "git",
    args: [...safeGlobalArgs, "config", "--list", "--show-scope"],
    cwd,
    timeoutMs: 5_000,
    maxOutputBytes: 65_536,
    signal,
  });

  const configViolations = detectDangerousLocalConfigEntries(configRes.stdout);
  if (configViolations.length > 0) {
    return {
      isRepo: true,
      currentBranch: null,
      isClean: false,
      hasConflicts: false,
      stagedFiles: [],
      configViolations,
    };
  }

  const branchRes = await processRunner.run({
    executable: "git",
    args: [...safeGlobalArgs, "symbolic-ref", "--short", "-q", "HEAD"],
    cwd,
    timeoutMs: 5_000,
    maxOutputBytes: 4_096,
    signal,
  });
  const currentBranch = branchRes.exitCode === 0 ? branchRes.stdout.trim() || null : null;

  const statusRes = await processRunner.run({
    executable: "git",
    args: [...safeGlobalArgs, "status", "--porcelain"],
    cwd,
    timeoutMs: 5_000,
    maxOutputBytes: 65_536,
    signal,
  });

  const statusLines = statusRes.stdout.split(/\r?\n/).filter((line) => line.trim().length > 0);
  const isClean = statusLines.length === 0;
  const hasConflicts = statusLines.some((line) => /^(?:UU|AA|DD|AU|UA|DU|UD)\s/.test(line));

  const stagedRes = await processRunner.run({
    executable: "git",
    args: [...safeGlobalArgs, "diff", "--no-ext-diff", "--no-textconv", "--cached", "--name-only"],
    cwd,
    timeoutMs: 5_000,
    maxOutputBytes: 65_536,
    signal,
  });

  const stagedFiles = stagedRes.stdout
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) => line.length > 0);

  return {
    isRepo: true,
    currentBranch,
    isClean,
    hasConflicts,
    stagedFiles,
    configViolations: [],
  };
}

export function findSensitiveStagedFiles(cwd: string, stagedFiles: readonly string[]): string[] {
  const sensitive: string[] = [];
  for (const rel of stagedFiles) {
    const fullPath = path.resolve(cwd, rel);
    if (isSensitiveFilePath(fullPath)) {
      sensitive.push(rel);
    }
  }
  return sensitive;
}
