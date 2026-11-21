import { ExecutionError, PolicyDeniedError, ValidationError } from "../../core/errors.js";
import type { ExecutionResult, ToolExecutionContext } from "../../core/types.js";
import { redactText } from "../security/redactor.js";
import {
  type AuthorizedOperation,
  computeAuthorizationDigest,
  isAuthorizedOperation,
} from "../security/types.js";
import type { ToolRegistry } from "./tool-registry.js";

export interface ExecutionEngineOptions {
  registry: ToolRegistry;
  defaultTimeoutMs: number;
  defaultMaxOutputBytes: number;
}

export interface ExecuteAuthorizedOptions {
  signal?: AbortSignal;
  timeoutMs?: number;
  maxOutputBytes?: number;
}

export class ExecutionEngine {
  private readonly registry: ToolRegistry;
  private readonly defaultTimeoutMs: number;
  private readonly defaultMaxOutputBytes: number;
  private readonly consumedAuthorizations = new WeakSet<AuthorizedOperation>();

  constructor(options: ExecutionEngineOptions) {
    this.registry = options.registry;
    this.defaultTimeoutMs = options.defaultTimeoutMs;
    this.defaultMaxOutputBytes = options.defaultMaxOutputBytes;
  }

  public async executeAuthorized(
    authorized: AuthorizedOperation,
    options: ExecuteAuthorizedOptions = {},
  ): Promise<ExecutionResult> {
    if (!isAuthorizedOperation(authorized)) {
      throw new PolicyDeniedError(
        "ExecutionEngine rejected an unauthorized operation (missing PolicyEngine authorization)",
      );
    }

    const expectedDigest = computeAuthorizationDigest({
      taskId: authorized.taskId,
      toolName: authorized.request.toolName,
      category: authorized.request.category,
      canonicalWorkingDirectory: authorized.canonicalWorkingDirectory,
      input: authorized.request.input,
    });
    if (expectedDigest !== authorized.inputDigest) {
      throw new PolicyDeniedError(
        "ExecutionEngine rejected authorization with mismatched parameter digest",
      );
    }

    if (this.consumedAuthorizations.has(authorized)) {
      throw new PolicyDeniedError(
        "ExecutionEngine rejected replay of an already-consumed authorization token",
      );
    }
    this.consumedAuthorizations.add(authorized);

    const tool = this.registry.get(authorized.request.toolName);
    if (!tool) {
      throw new ExecutionError(`Unknown tool '${authorized.request.toolName}'`, {
        details: { toolName: authorized.request.toolName },
      });
    }

    const parsed = tool.inputSchema.safeParse(authorized.request.input);
    if (!parsed.success) {
      throw new ValidationError(`Invalid parameters for tool '${authorized.request.toolName}'`, {
        details: { toolName: authorized.request.toolName, issues: parsed.error.issues },
      });
    }

    const controller = new AbortController();
    const signal = options.signal ?? controller.signal;

    const context: ToolExecutionContext = {
      taskId: authorized.taskId,
      sessionId: authorized.request.sessionId,
      actor: authorized.request.actor,
      workingDirectory: authorized.canonicalWorkingDirectory,
      signal,
      timeoutMs: options.timeoutMs ?? this.defaultTimeoutMs,
      maxOutputBytes: options.maxOutputBytes ?? this.defaultMaxOutputBytes,
    };

    const rawResult = await tool.execute(parsed.data, context);

    // Ensure captured outputs and errors are always redacted before leaving ExecutionEngine
    return {
      ...rawResult,
      stdout: redactText(rawResult.stdout),
      stderr: redactText(rawResult.stderr),
      errorMessage: rawResult.errorMessage ? redactText(rawResult.errorMessage) : undefined,
    };
  }
}
