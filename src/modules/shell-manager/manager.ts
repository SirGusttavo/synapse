import { z } from "zod";
import { ShellError } from "../../core/errors.js";
import type { ExecutionResult, ToolDefinition, ToolExecutionContext } from "../../core/types.js";
import type { IProcessRunner } from "../execution-engine/process-runner.js";
import type { IShellAdapter, ShellDetectionResult } from "./types.js";

export const ShellExecInputSchema = z
  .object({
    command: z.string().min(1, "Command cannot be empty"),
    shell: z.string().min(1).optional(),
    timeoutMs: z.number().int().min(500).max(600_000).optional(),
  })
  .strict();

export type ShellExecInput = z.infer<typeof ShellExecInputSchema>;

export interface ShellManagerOptions {
  processRunner: IProcessRunner;
  defaultAdapter: IShellAdapter;
  extraBlockedEnvPatterns?: readonly string[];
}

export class ShellManager {
  private readonly processRunner: IProcessRunner;
  private readonly adapters = new Map<string, IShellAdapter>();
  private readonly defaultAdapterId: string;
  private readonly extraBlockedEnvPatterns: readonly string[];

  constructor(options: ShellManagerOptions) {
    this.processRunner = options.processRunner;
    this.defaultAdapterId = options.defaultAdapter.id;
    this.extraBlockedEnvPatterns = options.extraBlockedEnvPatterns ?? [];
    this.adapters.set(options.defaultAdapter.id, options.defaultAdapter);
  }

  public registerAdapter(adapter: IShellAdapter): void {
    this.adapters.set(adapter.id, adapter);
  }

  public getAdapter(id?: string): IShellAdapter {
    const targetId = id ?? this.defaultAdapterId;
    const adapter = this.adapters.get(targetId);
    if (!adapter) {
      throw new ShellError(`Shell adapter '${targetId}' is not registered`, {
        details: { shellId: targetId },
      });
    }
    return adapter;
  }

  public async detectDefault(): Promise<ShellDetectionResult> {
    return this.getAdapter().detect();
  }

  public async executeCommand(
    input: ShellExecInput,
    context: ToolExecutionContext,
  ): Promise<ExecutionResult> {
    const adapter = this.getAdapter(input.shell);
    const invocation = await adapter.buildInvocation(input.command);

    const runResult = await this.processRunner.run({
      executable: invocation.executable,
      args: invocation.args,
      cwd: context.workingDirectory,
      timeoutMs: input.timeoutMs ?? context.timeoutMs,
      maxOutputBytes: context.maxOutputBytes,
      signal: context.signal,
      extraBlockedEnvPatterns: this.extraBlockedEnvPatterns,
    });

    return {
      ...runResult,
      data: {
        shell: adapter.id,
        executable: invocation.executable,
      },
    };
  }
}

export function createShellExecTool(
  shellManager: ShellManager,
): ToolDefinition<typeof ShellExecInputSchema> {
  return {
    name: "shell.exec",
    description: "Executes an authorized command in the configured local shell adapter",
    category: "shell",
    defaultPermission: "CONDITIONAL",
    inputSchema: ShellExecInputSchema,
    execute: (input, context) => shellManager.executeCommand(input, context),
  };
}
