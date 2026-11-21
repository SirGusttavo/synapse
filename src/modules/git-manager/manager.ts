import fs from "node:fs";
import path from "node:path";
import type { ExecutionResult, ToolExecutionContext } from "../../core/types.js";
import type { IProcessRunner } from "../execution-engine/process-runner.js";
import { inspectWorkspacePath } from "../security/workspace-guard.js";
import {
  assertSafeCloneUrl,
  assertSafeGitPaths,
  assertSafeGitRef,
  findSensitiveStagedFiles,
  inspectGitRepository,
  SAFE_GIT_GLOBAL_ARGS,
} from "./preflight.js";
import type {
  GitAddInput,
  GitBranchInput,
  GitCheckoutInput,
  GitCloneInput,
  GitCommitInput,
  GitDiffInput,
  GitInitInput,
  GitLogInput,
  GitMergeInput,
  GitPullInput,
  GitPushInput,
  GitStatusInput,
  GitTagInput,
} from "./types.js";

export interface GitManagerOptions {
  processRunner: IProcessRunner;
  workspaceDir: string;
  allowOutsideWorkspace?: boolean;
  extraBlockedEnvPatterns?: readonly string[];
}

function preflightFailure(startedAt: number, message: string): ExecutionResult {
  return {
    status: "failed",
    exitCode: 1,
    stdout: "",
    stderr: message,
    stdoutTruncated: false,
    stderrTruncated: false,
    durationMs: Date.now() - startedAt,
    errorMessage: message,
  };
}

export class GitManager {
  private readonly processRunner: IProcessRunner;
  private readonly workspaceDir: string;
  private readonly allowOutsideWorkspace: boolean;
  private readonly extraBlockedEnvPatterns: readonly string[];

  constructor(options: GitManagerOptions) {
    this.processRunner = options.processRunner;
    this.workspaceDir = path.resolve(options.workspaceDir);
    this.allowOutsideWorkspace = options.allowOutsideWorkspace ?? false;
    this.extraBlockedEnvPatterns = options.extraBlockedEnvPatterns ?? [];
  }

  private async runGit(
    subArgs: string[],
    context: ToolExecutionContext,
    extraData?: Record<string, unknown>,
  ): Promise<ExecutionResult> {
    const res = await this.processRunner.run({
      executable: "git",
      args: [...SAFE_GIT_GLOBAL_ARGS, ...subArgs],
      cwd: context.workingDirectory,
      timeoutMs: context.timeoutMs,
      maxOutputBytes: context.maxOutputBytes,
      signal: context.signal,
      extraBlockedEnvPatterns: this.extraBlockedEnvPatterns,
    });

    return {
      ...res,
      data: {
        gitArgs: subArgs,
        ...extraData,
      },
    };
  }

  private async ensureValidRepo(
    startedAt: number,
    context: ToolExecutionContext,
  ): Promise<
    | { ok: true; state: Awaited<ReturnType<typeof inspectGitRepository>> }
    | { ok: false; result: ExecutionResult }
  > {
    const state = await inspectGitRepository(
      this.processRunner,
      context.workingDirectory,
      context.signal,
    );
    if (!state.isRepo) {
      return {
        ok: false,
        result: preflightFailure(
          startedAt,
          `Directory is not a valid Git repository: ${context.workingDirectory}`,
        ),
      };
    }
    return { ok: true, state };
  }

  public async status(
    _input: GitStatusInput,
    context: ToolExecutionContext,
  ): Promise<ExecutionResult> {
    const startedAt = Date.now();
    const check = await this.ensureValidRepo(startedAt, context);
    if (!check.ok) {
      return check.result;
    }

    return this.runGit(["status", "--short", "--branch"], context, {
      currentBranch: check.state.currentBranch,
      isClean: check.state.isClean,
    });
  }

  public async diff(input: GitDiffInput, context: ToolExecutionContext): Promise<ExecutionResult> {
    const startedAt = Date.now();
    const check = await this.ensureValidRepo(startedAt, context);
    if (!check.ok) {
      return check.result;
    }

    const args: string[] = ["diff"];
    if (input.staged) {
      args.push("--cached");
    }
    if (input.target) {
      assertSafeGitRef(input.target, "diff target");
      args.push(input.target);
    }
    if (input.paths && input.paths.length > 0) {
      assertSafeGitPaths(this.workspaceDir, context.workingDirectory, input.paths, {
        allowOutsideWorkspace: this.allowOutsideWorkspace,
        forbidSensitive: true,
      });
      args.push("--", ...input.paths);
    }

    return this.runGit(args, context);
  }

  public async log(input: GitLogInput, context: ToolExecutionContext): Promise<ExecutionResult> {
    const startedAt = Date.now();
    const check = await this.ensureValidRepo(startedAt, context);
    if (!check.ok) {
      return check.result;
    }

    const args: string[] = ["log", "--oneline", "--no-decorate", "-n", String(input.limit)];
    if (input.ref) {
      assertSafeGitRef(input.ref, "log ref");
      args.push(input.ref);
    }

    return this.runGit(args, context);
  }

  public async branch(
    input: GitBranchInput,
    context: ToolExecutionContext,
  ): Promise<ExecutionResult> {
    const startedAt = Date.now();
    const check = await this.ensureValidRepo(startedAt, context);
    if (!check.ok) {
      return check.result;
    }

    if (input.action === "list") {
      return this.runGit(["branch", "--list", "-a"], context, {
        currentBranch: check.state.currentBranch,
      });
    }

    if (!input.name) {
      return preflightFailure(startedAt, `Branch name is required for action '${input.action}'`);
    }
    assertSafeGitRef(input.name, "branch name");

    if (input.action === "create") {
      const args = ["branch", input.name];
      if (input.startPoint) {
        assertSafeGitRef(input.startPoint, "branch startPoint");
        args.push(input.startPoint);
      }
      return this.runGit(args, context);
    }

    // Safe delete (-d, never -D force delete!)
    if (check.state.currentBranch === input.name) {
      return preflightFailure(
        startedAt,
        `Cannot delete the currently checked out branch '${input.name}'`,
      );
    }
    return this.runGit(["branch", "-d", input.name], context);
  }

  public async tag(input: GitTagInput, context: ToolExecutionContext): Promise<ExecutionResult> {
    const startedAt = Date.now();
    const check = await this.ensureValidRepo(startedAt, context);
    if (!check.ok) {
      return check.result;
    }

    if (input.action === "list") {
      return this.runGit(["tag", "--list"], context);
    }

    if (!input.name) {
      return preflightFailure(startedAt, `Tag name is required for action '${input.action}'`);
    }
    assertSafeGitRef(input.name, "tag name");

    if (input.action === "create") {
      const args = ["tag"];
      if (input.message) {
        args.push("-a", input.name, "-m", input.message);
      } else {
        args.push(input.name);
      }
      if (input.target) {
        assertSafeGitRef(input.target, "tag target");
        args.push(input.target);
      }
      return this.runGit(args, context);
    }

    return this.runGit(["tag", "-d", input.name], context);
  }

  public async init(input: GitInitInput, context: ToolExecutionContext): Promise<ExecutionResult> {
    assertSafeGitRef(input.initialBranch, "initialBranch");
    return this.runGit(["init", "-b", input.initialBranch], context);
  }

  public async clone(
    input: GitCloneInput,
    context: ToolExecutionContext,
  ): Promise<ExecutionResult> {
    const startedAt = Date.now();
    assertSafeCloneUrl(input.url);

    const targetInfo = inspectWorkspacePath(
      this.workspaceDir,
      context.workingDirectory,
      input.directory,
    );
    if (!targetInfo.insideWorkspace && !this.allowOutsideWorkspace) {
      return preflightFailure(
        startedAt,
        `Clone destination escapes authorized workspace: ${input.directory}`,
      );
    }
    if (
      fs.existsSync(targetInfo.canonicalPath) &&
      fs.readdirSync(targetInfo.canonicalPath).length > 0
    ) {
      return preflightFailure(
        startedAt,
        `Clone destination already exists and is not empty: ${input.directory}`,
      );
    }

    const args: string[] = ["clone"];
    if (input.branch) {
      assertSafeGitRef(input.branch, "clone branch");
      args.push("--branch", input.branch);
    }
    if (input.depth !== undefined) {
      args.push("--depth", String(input.depth));
    }
    args.push("--", input.url, targetInfo.canonicalPath);

    return this.runGit(args, context);
  }

  public async checkout(
    input: GitCheckoutInput,
    context: ToolExecutionContext,
  ): Promise<ExecutionResult> {
    const startedAt = Date.now();
    const check = await this.ensureValidRepo(startedAt, context);
    if (!check.ok) {
      return check.result;
    }
    if (check.state.hasConflicts) {
      return preflightFailure(
        startedAt,
        "Cannot checkout while repository has unresolved merge conflicts",
      );
    }

    assertSafeGitRef(input.target, "checkout target");
    const args = input.createBranch
      ? ["checkout", "-b", input.target]
      : ["checkout", input.target, "--"];

    return this.runGit(args, context);
  }

  public async add(input: GitAddInput, context: ToolExecutionContext): Promise<ExecutionResult> {
    const startedAt = Date.now();
    const check = await this.ensureValidRepo(startedAt, context);
    if (!check.ok) {
      return check.result;
    }

    assertSafeGitPaths(this.workspaceDir, context.workingDirectory, input.paths, {
      allowOutsideWorkspace: this.allowOutsideWorkspace,
      forbidSensitive: true,
    });

    return this.runGit(["add", "--", ...input.paths], context);
  }

  public async commit(
    input: GitCommitInput,
    context: ToolExecutionContext,
  ): Promise<ExecutionResult> {
    const startedAt = Date.now();
    const check = await this.ensureValidRepo(startedAt, context);
    if (!check.ok) {
      return check.result;
    }
    if (check.state.hasConflicts) {
      return preflightFailure(
        startedAt,
        "Cannot commit while repository has unresolved merge conflicts",
      );
    }
    if (check.state.stagedFiles.length === 0) {
      return preflightFailure(startedAt, "Nothing staged to commit");
    }

    const sensitiveStaged = findSensitiveStagedFiles(
      context.workingDirectory,
      check.state.stagedFiles,
    );
    if (sensitiveStaged.length > 0) {
      return preflightFailure(
        startedAt,
        `Refusing to commit sensitive files staged in index: ${sensitiveStaged.join(", ")}`,
      );
    }

    return this.runGit(["commit", "-m", input.message], context, {
      stagedCount: check.state.stagedFiles.length,
    });
  }

  public async pull(input: GitPullInput, context: ToolExecutionContext): Promise<ExecutionResult> {
    const startedAt = Date.now();
    const check = await this.ensureValidRepo(startedAt, context);
    if (!check.ok) {
      return check.result;
    }
    if (check.state.hasConflicts) {
      return preflightFailure(
        startedAt,
        "Cannot pull while repository has unresolved merge conflicts",
      );
    }

    assertSafeGitRef(input.remote, "remote");
    const args: string[] = ["pull"];
    if (input.ffOnly) {
      args.push("--ff-only");
    }
    args.push(input.remote);
    if (input.branch) {
      assertSafeGitRef(input.branch, "branch");
      args.push(input.branch);
    }

    return this.runGit(args, context);
  }

  public async push(input: GitPushInput, context: ToolExecutionContext): Promise<ExecutionResult> {
    const startedAt = Date.now();
    const check = await this.ensureValidRepo(startedAt, context);
    if (!check.ok) {
      return check.result;
    }

    assertSafeGitRef(input.remote, "remote");
    const targetBranch = input.branch ?? check.state.currentBranch;
    if (!targetBranch) {
      return preflightFailure(
        startedAt,
        "Cannot push from detached HEAD without specifying an explicit branch",
      );
    }
    assertSafeGitRef(targetBranch, "branch");

    const args: string[] = ["push"];
    if (input.setUpstream) {
      args.push("-u");
    }
    args.push(input.remote, targetBranch);

    return this.runGit(args, context, {
      remote: input.remote,
      branch: targetBranch,
    });
  }

  public async merge(
    input: GitMergeInput,
    context: ToolExecutionContext,
  ): Promise<ExecutionResult> {
    const startedAt = Date.now();
    const check = await this.ensureValidRepo(startedAt, context);
    if (!check.ok) {
      return check.result;
    }
    if (check.state.hasConflicts) {
      return preflightFailure(
        startedAt,
        "Cannot merge while repository already has unresolved conflicts",
      );
    }

    assertSafeGitRef(input.branch, "merge branch");
    const args: string[] = ["merge"];
    if (input.noFf) {
      args.push("--no-ff");
    }
    if (input.ffOnly) {
      args.push("--ff-only");
    }
    if (input.message) {
      args.push("-m", input.message);
    }
    args.push(input.branch);

    return this.runGit(args, context);
  }
}
