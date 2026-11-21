import crypto from "node:crypto";
import type { SynapseEventBus } from "../../core/events.js";
import type {
  ExecutionResult,
  ExecutionStatus,
  OperationRequest,
  TaskRecord,
  TaskStatus,
} from "../../core/types.js";
import type { ITaskRepository } from "../../storage/index.js";
import type { IAuditLogger } from "../audit/index.js";
import type { ExecutionEngine } from "../execution-engine/index.js";
import type { IPolicyEngine } from "../security/index.js";
import { redactText } from "../security/redactor.js";
import { assertValidTaskTransition } from "./state-machine.js";
import {
  DEFAULT_PROCESS_WORKSPACE_LOCK,
  type LockMode,
  type WorkspaceLock,
} from "./workspace-lock.js";

export interface TaskManagerOptions {
  taskRepository: ITaskRepository;
  policyEngine: IPolicyEngine;
  executionEngine: ExecutionEngine;
  auditLogger: IAuditLogger;
  workspaceLock?: WorkspaceLock;
  eventBus?: SynapseEventBus;
}

export interface TaskRunOutcome {
  task: TaskRecord;
  result: ExecutionResult | null;
  deniedReasons?: string[];
}

function mapExecutionStatusToTaskStatus(status: ExecutionStatus): TaskStatus {
  switch (status) {
    case "completed":
      return "COMPLETED";
    case "failed":
      return "FAILED";
    case "timed_out":
      return "TIMED_OUT";
    case "cancelled":
      return "CANCELLED";
  }
}

export class TaskManager {
  private readonly taskRepository: ITaskRepository;
  private readonly policyEngine: IPolicyEngine;
  private readonly executionEngine: ExecutionEngine;
  private readonly auditLogger: IAuditLogger;
  public readonly workspaceLock: WorkspaceLock;
  private readonly eventBus?: SynapseEventBus;
  private readonly activeControllers = new Map<string, AbortController>();

  constructor(options: TaskManagerOptions) {
    this.taskRepository = options.taskRepository;
    this.policyEngine = options.policyEngine;
    this.executionEngine = options.executionEngine;
    this.auditLogger = options.auditLogger;
    this.workspaceLock = options.workspaceLock ?? DEFAULT_PROCESS_WORKSPACE_LOCK;
    this.eventBus = options.eventBus;
  }

  public getTask(taskId: string): TaskRecord | null {
    return this.taskRepository.findById(taskId);
  }

  public listRecentTasks(limit = 20): TaskRecord[] {
    return this.taskRepository.listRecent(limit);
  }

  public cancelTask(taskId: string): boolean {
    const controller = this.activeControllers.get(taskId);
    if (!controller) {
      return false;
    }
    controller.abort();
    return true;
  }

  public async submitAndRun(
    request: OperationRequest,
    options?: { timeoutMs?: number; maxOutputBytes?: number; externalSignal?: AbortSignal },
  ): Promise<TaskRunOutcome> {
    const taskId = crypto.randomUUID();
    const now = new Date().toISOString();

    let task: TaskRecord = {
      id: taskId,
      sessionId: request.sessionId ?? null,
      actor: request.actor,
      toolName: request.toolName,
      category: request.category,
      workingDirectory: request.workingDirectory,
      status: "PENDING",
      policyLevel: null,
      approvalStatus: "not_required",
      exitCode: null,
      durationMs: null,
      errorSummary: null,
      createdAt: now,
      updatedAt: now,
    };

    const controller = new AbortController();
    this.activeControllers.set(taskId, controller);

    const onExternalAbort = () => controller.abort();
    if (options?.externalSignal) {
      if (options.externalSignal.aborted) {
        controller.abort();
      } else {
        options.externalSignal.addEventListener("abort", onExternalAbort, { once: true });
      }
    }

    const updateTask = (patch: Partial<TaskRecord> & { status?: TaskStatus }): TaskRecord => {
      if (patch.status && patch.status !== task.status) {
        assertValidTaskTransition(task.status, patch.status);
      }
      task = {
        ...task,
        ...patch,
        updatedAt: new Date().toISOString(),
      };
      this.taskRepository.update(task);
      this.eventBus?.emit("task:updated", task);
      return task;
    };

    this.taskRepository.create(task);
    this.eventBus?.emit("task:created", task);

    let auditAttempted = false;

    try {
      const evaluation = await this.policyEngine.evaluateAndAuthorize(taskId, request, {
        signal: controller.signal,
        onAwaitingApproval: (approvalReq) => {
          updateTask({
            status: "AWAITING_APPROVAL",
            policyLevel: approvalReq.permissionLevel,
          });
        },
      });

      if (!evaluation.allowed) {
        const finalStatus: TaskStatus = controller.signal.aborted ? "CANCELLED" : "DENIED";
        const sanitizedReasons = evaluation.reasons.map((r) => redactText(r));
        const errorSummary = sanitizedReasons.join("; ");

        updateTask({
          status: finalStatus,
          policyLevel: evaluation.policyLevel,
          approvalStatus: evaluation.approvalStatus,
          errorSummary,
        });

        auditAttempted = true;
        this.auditLogger.record({
          sessionId: request.sessionId,
          taskId,
          actor: request.actor,
          operation: request.toolName,
          category: request.category,
          input: request.input,
          workingDirectory: request.workingDirectory,
          policyLevel: evaluation.policyLevel,
          policyDecision: "DENIED",
          approvalStatus: evaluation.approvalStatus,
          approvedBy: evaluation.approvedBy,
          status: finalStatus,
          errorSummary,
        });

        return {
          task,
          result: null,
          deniedReasons: sanitizedReasons,
        };
      }

      const { authorized } = evaluation;
      const lockMode: LockMode = authorized.mutating ? "write" : "read";

      let releaseLock: (() => void) | null = null;
      try {
        releaseLock = await this.workspaceLock.acquire(
          authorized.canonicalWorkingDirectory,
          lockMode,
          controller.signal,
        );
      } catch (lockError) {
        if (controller.signal.aborted) {
          const reason = "Task cancelled while waiting for workspace lock";
          updateTask({
            status: "CANCELLED",
            workingDirectory: authorized.canonicalWorkingDirectory,
            policyLevel: authorized.policyLevel,
            approvalStatus: authorized.approvalStatus,
            errorSummary: reason,
          });

          auditAttempted = true;
          this.auditLogger.record({
            sessionId: request.sessionId,
            taskId,
            actor: request.actor,
            operation: request.toolName,
            category: request.category,
            input: request.input,
            workingDirectory: authorized.canonicalWorkingDirectory,
            policyLevel: authorized.policyLevel,
            policyDecision: authorized.policyDecision,
            approvalStatus: authorized.approvalStatus,
            approvedBy: authorized.approvedBy,
            status: "CANCELLED",
            errorSummary: reason,
          });

          return { task, result: null, deniedReasons: [reason] };
        }
        throw lockError;
      }

      try {
        // Directive 9: Re-validate permissions immediately before executing any mutating operation
        if (authorized.mutating) {
          const revalidation = this.policyEngine.revalidateAuthorized(authorized);
          if (!revalidation.valid) {
            const sanitizedReasons = revalidation.reasons.map((r) => redactText(r));
            const errorSummary = sanitizedReasons.join("; ");

            updateTask({
              status: "DENIED",
              workingDirectory: authorized.canonicalWorkingDirectory,
              policyLevel: authorized.policyLevel,
              approvalStatus: authorized.approvalStatus,
              errorSummary,
            });

            auditAttempted = true;
            this.auditLogger.record({
              sessionId: request.sessionId,
              taskId,
              actor: request.actor,
              operation: request.toolName,
              category: request.category,
              input: request.input,
              workingDirectory: authorized.canonicalWorkingDirectory,
              policyLevel: authorized.policyLevel,
              policyDecision: "DENIED",
              approvalStatus: authorized.approvalStatus,
              approvedBy: authorized.approvedBy,
              status: "DENIED",
              errorSummary,
            });

            return {
              task,
              result: null,
              deniedReasons: sanitizedReasons,
            };
          }
        }

        updateTask({
          status: "RUNNING",
          workingDirectory: authorized.canonicalWorkingDirectory,
          policyLevel: authorized.policyLevel,
          approvalStatus: authorized.approvalStatus,
        });

        const result = await this.executionEngine.executeAuthorized(authorized, {
          signal: controller.signal,
          timeoutMs: options?.timeoutMs,
          maxOutputBytes: options?.maxOutputBytes,
        });

        const finalStatus = mapExecutionStatusToTaskStatus(result.status);
        const errorSummary =
          result.errorMessage ??
          (finalStatus === "FAILED"
            ? result.stderr.trim() || `Exited with code ${String(result.exitCode)}`
            : null);

        updateTask({
          status: finalStatus,
          exitCode: result.exitCode,
          durationMs: result.durationMs,
          errorSummary: errorSummary ? redactText(errorSummary.slice(0, 500)) : null,
        });

        auditAttempted = true;
        this.auditLogger.record({
          sessionId: request.sessionId,
          taskId,
          actor: request.actor,
          operation: request.toolName,
          category: request.category,
          input: request.input,
          workingDirectory: authorized.canonicalWorkingDirectory,
          policyLevel: authorized.policyLevel,
          policyDecision: authorized.policyDecision,
          approvalStatus: authorized.approvalStatus,
          approvedBy: authorized.approvedBy,
          exitCode: result.exitCode,
          durationMs: result.durationMs,
          status: finalStatus,
          errorSummary,
        });

        return { task, result };
      } finally {
        releaseLock?.();
      }
    } catch (error) {
      const rawMessage = error instanceof Error ? error.message : String(error);
      const sanitizedError = redactText(rawMessage);

      if (
        task.status === "PENDING" ||
        task.status === "AWAITING_APPROVAL" ||
        task.status === "RUNNING"
      ) {
        updateTask({
          status: "FAILED",
          errorSummary: sanitizedError,
        });
      }

      if (!auditAttempted) {
        auditAttempted = true;
        this.auditLogger.record({
          sessionId: request.sessionId,
          taskId,
          actor: request.actor,
          operation: request.toolName,
          category: request.category,
          input: request.input,
          workingDirectory: task.workingDirectory,
          policyLevel: task.policyLevel ?? "CONDITIONAL",
          policyDecision: task.policyLevel ?? "CONDITIONAL",
          approvalStatus: task.approvalStatus,
          status: "FAILED",
          errorSummary: sanitizedError,
        });
      }

      throw error;
    } finally {
      this.activeControllers.delete(taskId);
      if (options?.externalSignal) {
        options.externalSignal.removeEventListener("abort", onExternalAbort);
      }
    }
  }
}
