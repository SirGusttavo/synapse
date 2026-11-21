import { Command } from "commander";
import type { LogLevel } from "../config/schema.js";
import { SynapseError } from "../core/errors.js";
import { SynapseRuntime } from "../core/runtime.js";
import type { TaskStatus } from "../core/types.js";
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

  const program = new Command();
  program
    .name("synapse")
    .description("SYNAPSE — Universal AI Agent Execution & Orchestration Platform (Phase 1 Core)")
    .version("0.1.0")
    .exitOverride();

  program
    .command("exec")
    .description("Execute an authorized PowerShell command through Security Baseline & Audit")
    .argument("<command>", "PowerShell command to execute")
    .option("-w, --workspace <dir>", "Workspace root directory")
    .option("-c, --config <path>", "Path to JSON/JSONC configuration file")
    .option("--cwd <dir>", "Working directory inside workspace")
    .option("-t, --timeout <ms>", "Execution timeout in milliseconds")
    .option("--log-level <level>", "Override Pino log level (info, debug, warn, error, silent)")
    .option("--json", "Output full structured JSON result")
    .action(
      async (
        command: string,
        opts: {
          workspace?: string;
          config?: string;
          cwd?: string;
          timeout?: string;
          logLevel?: LogLevel;
          json?: boolean;
        },
      ) => {
        const timeoutMs = opts.timeout !== undefined ? Number(opts.timeout) : undefined;
        if (timeoutMs !== undefined && (!Number.isInteger(timeoutMs) || timeoutMs < 500)) {
          io.stderr("Erro: --timeout deve ser um inteiro >= 500 ms.\n");
          setExitCode(2);
          return;
        }

        const runtime = SynapseRuntime.create({
          workspaceDir: opts.workspace,
          configPath: opts.config,
          overrides: opts.logLevel
            ? { logging: { level: opts.logLevel, pretty: false } }
            : undefined,
          approvalHandler: io.approvalHandler ?? new CliApprovalHandler(),
        });

        try {
          const outcome = await runtime.executeShellCommand(command, {
            cwd: opts.cwd,
            timeoutMs,
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
            `  Tools:           ${status.registeredTools.join(", ")}`,
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
