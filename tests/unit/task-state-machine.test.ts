import { describe, expect, it } from "vitest";
import { PolicyDeniedError, TaskError } from "../../src/core/errors.js";
import { ExecutionEngine, ToolRegistry } from "../../src/modules/execution-engine/index.js";
import type { AuthorizedOperation } from "../../src/modules/security/index.js";
import {
  assertValidTaskTransition,
  isValidTaskTransition,
} from "../../src/modules/task-manager/index.js";

describe("TaskManager state machine", () => {
  it("allows documented valid lifecycle transitions", () => {
    expect(isValidTaskTransition("PENDING", "RUNNING")).toBe(true);
    expect(isValidTaskTransition("PENDING", "AWAITING_APPROVAL")).toBe(true);
    expect(isValidTaskTransition("AWAITING_APPROVAL", "RUNNING")).toBe(true);
    expect(isValidTaskTransition("AWAITING_APPROVAL", "DENIED")).toBe(true);
    expect(isValidTaskTransition("RUNNING", "COMPLETED")).toBe(true);
    expect(isValidTaskTransition("RUNNING", "FAILED")).toBe(true);
    expect(isValidTaskTransition("RUNNING", "TIMED_OUT")).toBe(true);
    expect(isValidTaskTransition("RUNNING", "CANCELLED")).toBe(true);
  });

  it("rejects illegal transitions from terminal states", () => {
    expect(() => assertValidTaskTransition("COMPLETED", "RUNNING")).toThrow(TaskError);
    expect(() => assertValidTaskTransition("DENIED", "RUNNING")).toThrow(TaskError);
    expect(() => assertValidTaskTransition("PENDING", "COMPLETED")).toThrow(TaskError);
  });
});

describe("ExecutionEngine authorization boundary", () => {
  it("refuses forged objects that were not authorized by PolicyEngine", async () => {
    const engine = new ExecutionEngine({
      registry: new ToolRegistry(),
      defaultTimeoutMs: 5_000,
      defaultMaxOutputBytes: 64_000,
    });

    const forged = {
      taskId: "forged-1",
      request: {
        toolName: "shell.exec",
        category: "shell",
        input: { command: "Write-Output hi" },
        workingDirectory: process.cwd(),
        actor: "attacker",
      },
      canonicalWorkingDirectory: process.cwd(),
      policyLevel: "AUTO",
      policyDecision: "AUTO",
      approvalStatus: "not_required",
      approvedBy: null,
      reasons: [],
    } as unknown as AuthorizedOperation;

    await expect(engine.executeAuthorized(forged)).rejects.toThrow(PolicyDeniedError);
  });
});
