import { TaskError } from "../../core/errors.js";
import type { TaskStatus } from "../../core/types.js";

export const VALID_TASK_TRANSITIONS: Readonly<Record<TaskStatus, readonly TaskStatus[]>> = {
  PENDING: ["AWAITING_APPROVAL", "RUNNING", "DENIED", "CANCELLED", "FAILED"],
  AWAITING_APPROVAL: ["RUNNING", "DENIED", "CANCELLED", "FAILED"],
  RUNNING: ["COMPLETED", "FAILED", "TIMED_OUT", "CANCELLED"],
  COMPLETED: [],
  FAILED: [],
  DENIED: [],
  CANCELLED: [],
  TIMED_OUT: [],
};

export function isValidTaskTransition(from: TaskStatus, to: TaskStatus): boolean {
  return VALID_TASK_TRANSITIONS[from].includes(to);
}

export function assertValidTaskTransition(from: TaskStatus, to: TaskStatus): void {
  if (!isValidTaskTransition(from, to)) {
    throw new TaskError(`Invalid task state transition: ${from} -> ${to}`, {
      details: { from, to },
    });
  }
}
