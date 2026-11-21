import { Command } from "commander";
import type { LogLevel } from "../config/schema.js";
import { SynapseError } from "../core/errors.js";
import { SynapseRuntime } from "../core/runtime.js";
import type { OperationCategory, TaskStatus } from "../core/types.js";
import type { IApprovalHandler } from "../modules/security/index.js";
import { CliApprovalHandler } from "./prompts/cli-approval-handler.js";

export interface CliIo {
  stdout: (text: string) => void;
  stderr: (text: string) => void;
  approvalHandler?: IApprovalHandler;
}

const DEFAULT_IO: CliIo = {
  stdout: (text) => process.stdout.write(text),
  stderr: (text) => process.stderr.write(text),
};

interface CommonToolOptions {
  workspace?: string;
  config?: string;
  cwd?: string;
  logLevel?: LogLevel;
  json?: boolean;
}

function mapOutcomeExitCode(status: TaskStatus, exitCode: number | null): number {
  switch (status) {
    case "COMPLETED":
      return 0;
    case "DENIED":
      return 126;
    case "TIMED_OUT":
      return 124;
    case "CANCELLED":
      return 130;
    case "FAILED":
      return exitCode && exitCode !== 0 ? exitCode : 1;
    default:
      return 1;
  }
}

export function createCliProgram(io: CliIo = DEFAULT_IO): {
  program: Command;
  getExitCode: () => number;
} {
  let exitCode = 0;
  const setExitCode = (code: number) => {
    exitCode = code;
  };

  const executeRuntimeTool = async (
    toolName: string,
    category: OperationCategory,
    input: Record<string, unknown>,
    opts: CommonToolOptions & { timeoutMs?: number },
  ): Promise<void> => {
    const runtime = SynapseRuntime.create({
      workspaceDir: opts.workspace,
      configPath: opts.config,
      overrides: opts.logLevel ? { logging: { level: opts.logLevel, pretty: false } } : undefined,
      approvalHandler:
        io.approvalHandler ??
        ((cfg) => new CliApprovalHandler({ timeoutMs: cfg.security.approvalTimeoutMs })),
    });

    try {
      const outcome = await runtime.executeTool(toolName, category, input, {
        cwd: opts.cwd,
        timeoutMs: opts.timeoutMs,
        actor: "cli-operator",
      });

      const code = mapOutcomeExitCode(outcome.task.status, outcome.result?.exitCode ?? null);
      setExitCode(code);

      if (opts.json) {
        io.stdout(`${JSON.stringify(outcome, null, 2)}\n`);
        return;
      }

      if (outcome.task.status === "DENIED") {
        io.stderr(
          `[DENIED] Operacao bloqueada pela politica de seguranca (${outcome.task.policyLevel ?? "DENIED"}):\n` +
            `${(outcome.deniedReasons ?? []).map((r) => `  - ${r}`).join("\n")}\n`,
        );
        return;
      }

      if (outcome.result?.stdout) {
        io.stdout(outcome.result.stdout);
        if (!outcome.result.stdout.endsWith("\n")) {
          io.stdout("\n");
        }
      }
      if (outcome.result?.stderr) {
        io.stderr(outcome.result.stderr);
        if (!outcome.result.stderr.endsWith("\n")) {
          io.stderr("\n");
        }
      }
      if (outcome.task.status === "TIMED_OUT") {
        io.stderr(`[TIMED_OUT] ${outcome.result?.errorMessage ?? "Tempo limite excedido"}\n`);
      }
    } finally {
      runtime.close();
    }
  };

  const addCommonOptions = (cmd: Command): Command =>
    cmd
      .option("-w, --workspace <dir>", "Workspace root directory")
      .option("-c, --config <path>", "Path to JSON/JSONC configuration file")
      .option("--cwd <dir>", "Working directory inside workspace")
      .option("--log-level <level>", "Override Pino log level (info, debug, warn, error, silent)")
      .option("--json", "Output full structured JSON result");

  const program = new Command();
  program
    .name("synapse")
    .description("SYNAPSE — Universal AI Agent Execution & Orchestration Platform")
    .version("0.2.0")
    .exitOverride();

  addCommonOptions(
    program
      .command("exec")
      .description("Execute an authorized PowerShell command through Security Baseline & Audit")
      .argument("<command>", "PowerShell command to execute")
      .option("-t, --timeout <ms>", "Execution timeout in milliseconds"),
  ).action(async (command: string, opts: CommonToolOptions & { timeout?: string }) => {
    const timeoutMs = opts.timeout !== undefined ? Number(opts.timeout) : undefined;
    if (timeoutMs !== undefined && (!Number.isInteger(timeoutMs) || timeoutMs < 500)) {
      io.stderr("Erro: --timeout deve ser um inteiro >= 500 ms.\n");
      setExitCode(2);
      return;
    }

    await executeRuntimeTool(
      "shell.exec",
      "shell",
      {
        command,
        ...(timeoutMs !== undefined ? { timeoutMs } : {}),
      },
      { ...opts, timeoutMs },
    );
  });

  // --- Typed File Manager CLI subcommands ---
  const fileCmd = program
    .command("file")
    .description("Execute workspace-confined File Manager operations without shell.exec");

  addCommonOptions(
    fileCmd
      .command("list")
      .description("List files and directories inside workspace")
      .argument("[path]", "Relative directory path", ".")
      .option("-r, --recursive", "List recursively"),
  ).action(async (targetPath: string, opts: CommonToolOptions & { recursive?: boolean }) => {
    await executeRuntimeTool(
      "file.list",
      "file",
      { path: targetPath, recursive: Boolean(opts.recursive) },
      opts,
    );
  });

  addCommonOptions(
    fileCmd
      .command("read")
      .description("Read a UTF-8 file inside workspace")
      .argument("<path>", "Relative file path")
      .option("--start-line <n>", "1-based start line")
      .option("--end-line <n>", "1-based end line"),
  ).action(
    async (
      targetPath: string,
      opts: CommonToolOptions & { startLine?: string; endLine?: string },
    ) => {
      await executeRuntimeTool(
        "file.read",
        "file",
        {
          path: targetPath,
          ...(opts.startLine !== undefined ? { startLine: Number(opts.startLine) } : {}),
          ...(opts.endLine !== undefined ? { endLine: Number(opts.endLine) } : {}),
        },
        opts,
      );
    },
  );

  addCommonOptions(
    fileCmd
      .command("create")
      .description("Create a UTF-8 file atomically inside workspace")
      .argument("<path>", "Relative file path")
      .requiredOption("--content <text>", "File content to write")
      .option("--overwrite", "Allow overwriting an existing file"),
  ).action(
    async (
      targetPath: string,
      opts: CommonToolOptions & { content: string; overwrite?: boolean },
    ) => {
      await executeRuntimeTool(
        "file.create",
        "file",
        {
          path: targetPath,
          content: opts.content,
          overwrite: Boolean(opts.overwrite),
        },
        opts,
      );
    },
  );

  addCommonOptions(
    fileCmd
      .command("edit")
      .description("Edit a UTF-8 file atomically by exact search and replace")
      .argument("<path>", "Relative file path")
      .requiredOption("--search <text>", "Exact text to find")
      .requiredOption("--replace <text>", "Replacement text")
      .option("--replace-all", "Replace all occurrences"),
  ).action(
    async (
      targetPath: string,
      opts: CommonToolOptions & { search: string; replace: string; replaceAll?: boolean },
    ) => {
      await executeRuntimeTool(
        "file.edit",
        "file",
        {
          path: targetPath,
          search: opts.search,
          replace: opts.replace,
          replaceAll: Boolean(opts.replaceAll),
        },
        opts,
      );
    },
  );

  addCommonOptions(
    fileCmd
      .command("search")
      .description("Search text content across workspace files")
      .argument("<query>", "Search string or regular expression")
      .option("-p, --path <dir>", "Directory or file to search", ".")
      .option("--regex", "Treat query as regular expression")
      .option("--case-sensitive", "Perform case-sensitive search"),
  ).action(
    async (
      query: string,
      opts: CommonToolOptions & { path: string; regex?: boolean; caseSensitive?: boolean },
    ) => {
      await executeRuntimeTool(
        "file.search",
        "file",
        {
          query,
          path: opts.path,
          regex: Boolean(opts.regex),
          caseSensitive: Boolean(opts.caseSensitive),
        },
        opts,
      );
    },
  );

  addCommonOptions(
    fileCmd
      .command("move")
      .description("Move or rename a file within the workspace")
      .argument("<from>", "Source relative path")
      .argument("<to>", "Destination relative path")
      .option("--overwrite", "Allow overwriting destination"),
  ).action(async (from: string, to: string, opts: CommonToolOptions & { overwrite?: boolean }) => {
    await executeRuntimeTool(
      "file.move",
      "file",
      { from, to, overwrite: Boolean(opts.overwrite) },
      opts,
    );
  });

  addCommonOptions(
    fileCmd
      .command("delete")
      .description("Delete a file or directory within the workspace (requires human approval)")
      .argument("<path>", "Target relative path")
      .option("-r, --recursive", "Allow deleting a directory recursively"),
  ).action(async (targetPath: string, opts: CommonToolOptions & { recursive?: boolean }) => {
    await executeRuntimeTool(
      "file.delete",
      "file",
      { path: targetPath, recursive: Boolean(opts.recursive) },
      opts,
    );
  });

  // --- Typed Git Manager CLI subcommands ---
  const gitCmd = program
    .command("git")
    .description("Execute controlled Git operations with pre-flight checks and hook containment");

  addCommonOptions(
    gitCmd.command("status").description("Check working tree and branch status"),
  ).action(async (opts: CommonToolOptions) => {
    await executeRuntimeTool("git.status", "git", {}, opts);
  });

  addCommonOptions(
    gitCmd
      .command("diff")
      .description("Show unstaged or staged Git diff")
      .option("--staged", "Show staged changes")
      .option("--target <ref>", "Compare against ref"),
  ).action(async (opts: CommonToolOptions & { staged?: boolean; target?: string }) => {
    await executeRuntimeTool(
      "git.diff",
      "git",
      {
        staged: Boolean(opts.staged),
        ...(opts.target ? { target: opts.target } : {}),
      },
      opts,
    );
  });

  addCommonOptions(
    gitCmd
      .command("log")
      .description("Show recent Git commits")
      .option("-n, --limit <count>", "Number of commits", "10")
      .option("--ref <ref>", "Target branch or ref"),
  ).action(async (opts: CommonToolOptions & { limit: string; ref?: string }) => {
    await executeRuntimeTool(
      "git.log",
      "git",
      {
        limit: Number(opts.limit),
        ...(opts.ref ? { ref: opts.ref } : {}),
      },
      opts,
    );
  });

  addCommonOptions(
    gitCmd
      .command("init")
      .description("Initialize a new Git repository in workspace")
      .option("-b, --branch <name>", "Initial branch name", "main"),
  ).action(async (opts: CommonToolOptions & { branch: string }) => {
    await executeRuntimeTool("git.init", "git", { initialBranch: opts.branch }, opts);
  });

  addCommonOptions(
    gitCmd
      .command("branch")
      .description("List, create or safely delete Git branches")
      .option("--action <action>", "Action: list, create, delete", "list")
      .option("--name <branch>", "Branch name for create/delete"),
  ).action(async (opts: CommonToolOptions & { action: string; name?: string }) => {
    await executeRuntimeTool(
      "git.branch",
      "git",
      {
        action: opts.action,
        ...(opts.name ? { name: opts.name } : {}),
      },
      opts,
    );
  });

  addCommonOptions(
    gitCmd
      .command("checkout")
      .description("Switch branches or create a new branch")
      .argument("<target>", "Branch name or commit ref")
      .option("-b, --create", "Create a new branch"),
  ).action(async (target: string, opts: CommonToolOptions & { create?: boolean }) => {
    await executeRuntimeTool(
      "git.checkout",
      "git",
      { target, createBranch: Boolean(opts.create) },
      opts,
    );
  });

  addCommonOptions(
    gitCmd
      .command("add")
      .description("Stage workspace files into Git index")
      .argument("<paths...>", "Relative file paths to stage"),
  ).action(async (paths: string[], opts: CommonToolOptions) => {
    await executeRuntimeTool("git.add", "git", { paths }, opts);
  });

  addCommonOptions(
    gitCmd
      .command("commit")
      .description("Create a Git commit after secret staging check")
      .requiredOption("-m, --message <msg>", "Commit message"),
  ).action(async (opts: CommonToolOptions & { message: string }) => {
    await executeRuntimeTool("git.commit", "git", { message: opts.message }, opts);
  });

  addCommonOptions(
    gitCmd
      .command("tag")
      .description("List, create or delete Git tags")
      .option("--action <action>", "Action: list, create, delete", "list")
      .option("--name <tag>", "Tag name")
      .option("-m, --message <msg>", "Annotated tag message"),
  ).action(
    async (opts: CommonToolOptions & { action: string; name?: string; message?: string }) => {
      await executeRuntimeTool(
        "git.tag",
        "git",
        {
          action: opts.action,
          ...(opts.name ? { name: opts.name } : {}),
          ...(opts.message ? { message: opts.message } : {}),
        },
        opts,
      );
    },
  );

  addCommonOptions(
    gitCmd
      .command("push")
      .description("Publish commits to remote (always requires human approval)")
      .option("--remote <name>", "Remote name", "origin")
      .option("--branch <name>", "Branch name")
      .option("-u, --set-upstream", "Set upstream tracking branch"),
  ).action(
    async (
      opts: CommonToolOptions & { remote: string; branch?: string; setUpstream?: boolean },
    ) => {
      await executeRuntimeTool(
        "git.push",
        "git",
        {
          remote: opts.remote,
          ...(opts.branch ? { branch: opts.branch } : {}),
          setUpstream: Boolean(opts.setUpstream),
        },
        opts,
      );
    },
  );

  addCommonOptions(
    gitCmd
      .command("clone")
      .description("Clone a remote repository into a workspace subdirectory")
      .argument("<url>", "Repository URL (https:// or ssh://)")
      .argument("<directory>", "Target subdirectory inside workspace")
      .option("-b, --branch <name>", "Branch to checkout")
      .option("--depth <n>", "Shallow clone depth"),
  ).action(
    async (
      url: string,
      directory: string,
      opts: CommonToolOptions & { branch?: string; depth?: string },
    ) => {
      await executeRuntimeTool(
        "git.clone",
        "git",
        {
          url,
          directory,
          ...(opts.branch ? { branch: opts.branch } : {}),
          ...(opts.depth !== undefined ? { depth: Number(opts.depth) } : {}),
        },
        opts,
      );
    },
  );

  addCommonOptions(
    gitCmd
      .command("pull")
      .description("Pull changes from a remote repository (fast-forward only by default)")
      .option("--remote <name>", "Remote name", "origin")
      .option("--branch <name>", "Branch name")
      .option("--no-ff-only", "Allow non-fast-forward pull"),
  ).action(
    async (opts: CommonToolOptions & { remote: string; branch?: string; ffOnly?: boolean }) => {
      await executeRuntimeTool(
        "git.pull",
        "git",
        {
          remote: opts.remote,
          ...(opts.branch ? { branch: opts.branch } : {}),
          ffOnly: opts.ffOnly !== false,
        },
        opts,
      );
    },
  );

  addCommonOptions(
    gitCmd
      .command("merge")
      .description("Merge a branch into the current branch")
      .argument("<branch>", "Branch name to merge")
      .option("--no-ff", "Create a merge commit even on fast-forward")
      .option("--ff-only", "Refuse merge unless fast-forward")
      .option("-m, --message <msg>", "Custom merge commit message"),
  ).action(
    async (
      branch: string,
      opts: CommonToolOptions & { ff?: boolean; ffOnly?: boolean; message?: string },
    ) => {
      await executeRuntimeTool(
        "git.merge",
        "git",
        {
          branch,
          noFf: opts.ff === false,
          ffOnly: Boolean(opts.ffOnly),
          ...(opts.message ? { message: opts.message } : {}),
        },
        opts,
      );
    },
  );

  program
    .command("status")
    .description("Inspect SYNAPSE runtime environment, shell detection and security baseline")
    .option("-w, --workspace <dir>", "Workspace root directory")
    .option("-c, --config <path>", "Path to JSON/JSONC configuration file")
    .option("--json", "Output structured JSON")
    .action(async (opts: { workspace?: string; config?: string; json?: boolean }) => {
      const runtime = SynapseRuntime.create({
        workspaceDir: opts.workspace,
        configPath: opts.config,
        overrides: { logging: { level: "silent", pretty: false } },
      });

      try {
        const status = await runtime.getSystemStatus();
        if (opts.json) {
          io.stdout(`${JSON.stringify(status, null, 2)}\n`);
          return;
        }

        io.stdout(
          `${[
            "SYNAPSE Core Status",
            `  Workspace:       ${status.workspaceDir}`,
            `  Config File:     ${status.configFilePath ?? "(defaults)"}`,
            `  SQLite DB:       ${status.dbPath}`,
            `  Security Mode:   ${status.securityMode} (file.delete=${status.singleFileDeletePermission})`,
            `  Shell Detected:  ${status.shell.available ? `${status.shell.executable} (${status.shell.version ?? "unknown"})` : "unavailable"}`,
            `  Tools (${String(status.registeredTools.length)}):      ${status.registeredTools.join(", ")}`,
            `  Recent Tasks:    ${status.recentTasksCount}`,
          ].join("\n")}\n`,
        );
      } finally {
        runtime.close();
      }
    });

  program
    .command("audit")
    .description("Query persisted audit log events from local SQLite")
    .option("-w, --workspace <dir>", "Workspace root directory")
    .option("-c, --config <path>", "Path to JSON/JSONC configuration file")
    .option("-n, --limit <count>", "Maximum events to return", "20")
    .option("--status <status>", "Filter by task status (COMPLETED, FAILED, DENIED, TIMED_OUT)")
    .option("--task <id>", "Filter by task ID")
    .option("--json", "Output structured JSON")
    .action(
      (opts: {
        workspace?: string;
        config?: string;
        limit: string;
        status?: TaskStatus;
        task?: string;
        json?: boolean;
      }) => {
        const limit = Number(opts.limit);
        if (!Number.isInteger(limit) || limit < 1) {
          io.stderr("Erro: --limit deve ser um inteiro >= 1.\n");
          setExitCode(2);
          return;
        }

        const runtime = SynapseRuntime.create({
          workspaceDir: opts.workspace,
          configPath: opts.config,
          overrides: { logging: { level: "silent", pretty: false } },
        });

        try {
          const events = runtime.queryAudit({
            limit,
            status: opts.status,
            taskId: opts.task,
          });

          if (opts.json) {
            io.stdout(`${JSON.stringify(events, null, 2)}\n`);
            return;
          }

          if (events.length === 0) {
            io.stdout("Nenhum evento de auditoria registrado.\n");
            return;
          }

          for (const ev of events) {
            io.stdout(
              `${ev.timestampUtc} | ${ev.status.padEnd(9)} | ${ev.policyDecision.padEnd(14)} | exit=${String(ev.exitCode ?? "-").padEnd(3)} | ${ev.operation} | ${ev.sanitizedInput}\n`,
            );
          }
        } finally {
          runtime.close();
        }
      },
    );

  program
    .command("config")
    .description("Display effective validated SYNAPSE configuration (secrets excluded)")
    .option("-w, --workspace <dir>", "Workspace root directory")
    .option("-c, --config <path>", "Path to JSON/JSONC configuration file")
    .action((opts: { workspace?: string; config?: string }) => {
      const runtime = SynapseRuntime.create({
        workspaceDir: opts.workspace,
        configPath: opts.config,
        overrides: { logging: { level: "silent", pretty: false } },
      });

      try {
        io.stdout(`${JSON.stringify(runtime.config, null, 2)}\n`);
      } finally {
        runtime.close();
      }
    });

  return {
    program,
    getExitCode: () => exitCode,
  };
}

export async function runCli(argv: string[], io: CliIo = DEFAULT_IO): Promise<number> {
  const { program, getExitCode } = createCliProgram(io);
  try {
    await program.parseAsync(argv);
    return getExitCode();
  } catch (error) {
    if (error instanceof SynapseError) {
      io.stderr(`[${error.code}] ${error.message}\n`);
      return 1;
    }
    if (
      typeof error === "object" &&
      error !== null &&
      "exitCode" in error &&
      typeof (error as { exitCode: unknown }).exitCode === "number"
    ) {
      return (error as { exitCode: number }).exitCode;
    }
    const message = error instanceof Error ? error.message : String(error);
    io.stderr(`[UNEXPECTED_ERROR] ${message}\n`);
    return 1;
  }
}
