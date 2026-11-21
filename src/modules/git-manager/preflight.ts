import path from "node:path";
import { PolicyDeniedError } from "../../core/errors.js";
import type { IProcessRunner } from "../execution-engine/process-runner.js";
import { inspectWorkspacePath, isSensitiveFilePath } from "../security/workspace-guard.js";

/**
 * Mandatory Git containment flags passed to every Git invocation:
 * - disables arbitrary repository hooks (.git/hooks/*)
 * - disables fsmonitor daemon execution
 * - disables git-remote-ext arbitrary command protocol
 */
export const SAFE_GIT_GLOBAL_ARGS: readonly string[] = [
  "-c",
  "core.hooksPath=.git/__synapse_disabled_hooks__",
  "-c",
  "core.fsmonitor=false",
  "-c",
  "protocol.ext.allow=never",
];

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
}

export async function inspectGitRepository(
  processRunner: IProcessRunner,
  cwd: string,
  signal?: AbortSignal,
): Promise<GitRepositoryInspection> {
  const revParse = await processRunner.run({
    executable: "git",
    args: [...SAFE_GIT_GLOBAL_ARGS, "rev-parse", "--is-inside-work-tree"],
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
    };
  }

  const branchRes = await processRunner.run({
    executable: "git",
    args: [...SAFE_GIT_GLOBAL_ARGS, " symbolic-ref", "--short", "-q", "HEAD"].map((s) => s.trim()),
    cwd,
    timeoutMs: 5_000,
    maxOutputBytes: 4_096,
    signal,
  });
  const currentBranch = branchRes.exitCode === 0 ? branchRes.stdout.trim() || null : null;

  const statusRes = await processRunner.run({
    executable: "git",
    args: [...SAFE_GIT_GLOBAL_ARGS, "status", "--porcelain"],
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
    args: [...SAFE_GIT_GLOBAL_ARGS, "diff", "--cached", "--name-only"],
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
