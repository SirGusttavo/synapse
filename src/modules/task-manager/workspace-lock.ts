import fs from "node:fs";
import path from "node:path";
import { TaskError } from "../../core/errors.js";

export type LockMode = "read" | "write";

interface Waiter {
  mode: LockMode;
  settled: boolean;
  resolve: (release: () => void) => void;
  reject: (error: Error) => void;
  cleanupAbort?: () => void;
}

interface WorkspaceLockState {
  activeReaders: number;
  writerActive: boolean;
  queue: Waiter[];
}

function normalizeWorkspaceKey(workspaceDir: string): string {
  const resolved = path.resolve(workspaceDir);
  let canonical = resolved;
  try {
    if (fs.existsSync(resolved)) {
      canonical = fs.realpathSync(resolved);
    }
  } catch {
    canonical = resolved;
  }
  return process.platform === "win32" ? canonical.toLowerCase() : canonical;
}

/**
 * Fair FIFO Reader-Writer lock scoped per canonical workspace directory.
 *
 * Concurrency Scope & Guarantees:
 * 1. Tasks within the same `TaskManager` / `SynapseRuntime` instance: COORDINATED.
 * 2. Multiple `TaskManager` / `SynapseRuntime` instances within the SAME Node.js process:
 *    COORDINATED by default via `DEFAULT_PROCESS_WORKSPACE_LOCK`.
 * 3. Separate Node.js OS processes or external tools (IDEs, external terminals):
 *    NOT COORDINATED (this lock is strictly in-memory inside the Node.js process).
 */
export class WorkspaceLock {
  private readonly states = new Map<string, WorkspaceLockState>();

  private getOrCreateState(key: string): WorkspaceLockState {
    let state = this.states.get(key);
    if (!state) {
      state = { activeReaders: 0, writerActive: false, queue: [] };
      this.states.set(key, state);
    }
    return state;
  }

  private cleanupIfIdle(key: string, state: WorkspaceLockState): void {
    if (state.activeReaders === 0 && !state.writerActive && state.queue.length === 0) {
      this.states.delete(key);
    }
  }

  private createRelease(key: string, mode: LockMode): () => void {
    let released = false;
    return () => {
      if (released) {
        return;
      }
      released = true;

      const state = this.states.get(key);
      if (!state) {
        return;
      }

      if (mode === "write") {
        state.writerActive = false;
      } else {
        state.activeReaders = Math.max(0, state.activeReaders - 1);
      }

      this.drainQueue(key, state);
      this.cleanupIfIdle(key, state);
    };
  }

  private drainQueue(key: string, state: WorkspaceLockState): void {
    while (state.queue.length > 0) {
      const head = state.queue[0];
      if (!head) {
        break;
      }
      if (head.settled) {
        state.queue.shift();
        continue;
      }

      if (head.mode === "write") {
        if (state.writerActive || state.activeReaders > 0) {
          break;
        }
        state.queue.shift();
        state.writerActive = true;
        head.settled = true;
        head.cleanupAbort?.();
        head.resolve(this.createRelease(key, "write"));
        break;
      }

      // Reader at head: grant if no writer is currently active
      if (state.writerActive) {
        break;
      }
      state.queue.shift();
      state.activeReaders += 1;
      head.settled = true;
      head.cleanupAbort?.();
      head.resolve(this.createRelease(key, "read"));
    }
  }

  public async acquire(
    workspaceDir: string,
    mode: LockMode,
    signal?: AbortSignal,
  ): Promise<() => void> {
    if (signal?.aborted) {
      throw new TaskError("Task cancelled before acquiring workspace lock", {
        details: { workspaceDir, mode },
      });
    }

    const key = normalizeWorkspaceKey(workspaceDir);
    const state = this.getOrCreateState(key);

    // Fast path: grant immediately when no contention and queue is empty (preserves FIFO fairness)
    if (mode === "read" && !state.writerActive && state.queue.length === 0) {
      state.activeReaders += 1;
      return this.createRelease(key, "read");
    }

    if (
      mode === "write" &&
      !state.writerActive &&
      state.activeReaders === 0 &&
      state.queue.length === 0
    ) {
      state.writerActive = true;
      return this.createRelease(key, "write");
    }

    return new Promise<() => void>((resolve, reject) => {
      const waiter: Waiter = {
        mode,
        settled: false,
        resolve,
        reject,
      };

      if (signal) {
        const onAbort = () => {
          if (waiter.settled) {
            return;
          }
          waiter.settled = true;
          const idx = state.queue.indexOf(waiter);
          if (idx >= 0) {
            state.queue.splice(idx, 1);
          }
          this.drainQueue(key, state);
          this.cleanupIfIdle(key, state);
          reject(
            new TaskError("Task cancelled while waiting for workspace lock", {
              details: { workspaceDir, mode },
            }),
          );
        };
        signal.addEventListener("abort", onAbort, { once: true });
        waiter.cleanupAbort = () => signal.removeEventListener("abort", onAbort);
      }

      state.queue.push(waiter);
    });
  }

  public getDiagnostics(workspaceDir: string): {
    activeReaders: number;
    writerActive: boolean;
    queuedCount: number;
  } {
    const key = normalizeWorkspaceKey(workspaceDir);
    const state = this.states.get(key);
    if (!state) {
      return { activeReaders: 0, writerActive: false, queuedCount: 0 };
    }
    return {
      activeReaders: state.activeReaders,
      writerActive: state.writerActive,
      queuedCount: state.queue.length,
    };
  }
}

export const DEFAULT_PROCESS_WORKSPACE_LOCK = new WorkspaceLock();
