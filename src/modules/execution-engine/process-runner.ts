import { spawn } from "node:child_process";
import { ExecutionError } from "../../core/errors.js";
import type { ExecutionStatus } from "../../core/types.js";
import { sanitizeEnvironment } from "../security/env-sanitizer.js";

export interface ProcessRunOptions {
  executable: string;
  args: string[];
  cwd: string;
  timeoutMs: number;
  maxOutputBytes: number;
  signal?: AbortSignal;
  env?: NodeJS.ProcessEnv;
  extraBlockedEnvPatterns?: readonly string[];
}

export interface ProcessRunResult {
  status: ExecutionStatus;
  exitCode: number | null;
  stdout: string;
  stderr: string;
  stdoutTruncated: boolean;
  stderrTruncated: boolean;
  durationMs: number;
  errorMessage?: string;
}

export interface IProcessRunner {
  run(options: ProcessRunOptions): Promise<ProcessRunResult>;
}

interface BoundedCollector {
  chunks: Buffer[];
  bytes: number;
  truncated: boolean;
}

const POST_KILL_SETTLE_GRACE_MS = 2_000;

function validateRunOptions(options: ProcessRunOptions): void {
  if (typeof options.executable !== "string" || options.executable.trim().length === 0) {
    throw new ExecutionError("Process executable must be a non-empty string");
  }
  if (options.executable.includes("\0")) {
    throw new ExecutionError("Process executable contains invalid null byte");
  }
  for (const arg of options.args) {
    if (typeof arg !== "string" || arg.includes("\0")) {
      throw new ExecutionError("Process argument contains invalid value or null byte");
    }
  }
  if (!Number.isFinite(options.timeoutMs) || options.timeoutMs <= 0) {
    throw new ExecutionError("Process timeoutMs must be a positive finite number", {
      details: { timeoutMs: options.timeoutMs },
    });
  }
  if (!Number.isInteger(options.maxOutputBytes) || options.maxOutputBytes < 0) {
    throw new ExecutionError("Process maxOutputBytes must be a non-negative integer", {
      details: { maxOutputBytes: options.maxOutputBytes },
    });
  }
}

function appendBounded(collector: BoundedCollector, chunk: Buffer, limit: number): void {
  if (collector.truncated) {
    return;
  }
  const remaining = limit - collector.bytes;
  if (remaining <= 0) {
    collector.truncated = true;
    return;
  }
  if (chunk.length <= remaining) {
    collector.chunks.push(chunk);
    collector.bytes += chunk.length;
  } else {
    collector.chunks.push(chunk.subarray(0, remaining));
    collector.bytes += remaining;
    collector.truncated = true;
  }
}

function fallbackForceKill(pid: number): void {
  try {
    process.kill(pid, "SIGKILL");
  } catch {
    // Process already exited
  }
}

export function killProcessTree(pid: number | undefined): void {
  if (!pid || pid <= 0) {
    return;
  }

  if (process.platform === "win32") {
    try {
      const killer = spawn("taskkill.exe", ["/PID", String(pid), "/T", "/F"], {
        shell: false,
        windowsHide: true,
        stdio: "ignore",
      });
      killer.on("error", () => {
        fallbackForceKill(pid);
      });
      killer.on("close", (code) => {
        if (code !== 0) {
          fallbackForceKill(pid);
        }
      });
    } catch {
      fallbackForceKill(pid);
    }
    return;
  }

  fallbackForceKill(pid);
}

/**
 * Executes OS binaries strictly with `shell: false`, validated arguments, sanitized environments,
 * bounded stdout/stderr streaming, timeout enforcement and full process tree cleanup.
 */
export class NodeProcessRunner implements IProcessRunner {
  public async run(options: ProcessRunOptions): Promise<ProcessRunResult> {
    validateRunOptions(options);
    const startedAt = Date.now();

    if (options.signal?.aborted) {
      return {
        status: "cancelled",
        exitCode: null,
        stdout: "",
        stderr: "",
        stdoutTruncated: false,
        stderrTruncated: false,
        durationMs: 0,
        errorMessage: "Operation was cancelled before process start",
      };
    }

    const sanitizedEnv = sanitizeEnvironment(
      options.env ?? process.env,
      options.extraBlockedEnvPatterns ?? [],
    );

    return new Promise<ProcessRunResult>((resolve) => {
      let settled = false;
      let timedOut = false;
      let cancelled = false;
      let spawnErrorMessage: string | undefined;
      let terminationSignal: NodeJS.Signals | null = null;
      let forceSettleTimer: ReturnType<typeof setTimeout> | undefined;

      const stdoutCollector: BoundedCollector = { chunks: [], bytes: 0, truncated: false };
      const stderrCollector: BoundedCollector = { chunks: [], bytes: 0, truncated: false };

      const child = spawn(options.executable, options.args, {
        cwd: options.cwd,
        env: sanitizedEnv,
        shell: false,
        windowsHide: true,
        stdio: ["ignore", "pipe", "pipe"],
      });

      const finish = (exitCode: number | null) => {
        if (settled) {
          return;
        }
        settled = true;
        clearTimeout(timer);
        if (forceSettleTimer) {
          clearTimeout(forceSettleTimer);
        }
        if (options.signal) {
          options.signal.removeEventListener("abort", onAbort);
        }

        const durationMs = Date.now() - startedAt;
        const stdout = Buffer.concat(stdoutCollector.chunks).toString("utf8");
        const stderr = Buffer.concat(stderrCollector.chunks).toString("utf8");

        let status: ExecutionStatus;
        let errorMessage = spawnErrorMessage;

        if (cancelled) {
          status = "cancelled";
          errorMessage = errorMessage ?? "Process cancelled by abort signal";
        } else if (timedOut) {
          status = "timed_out";
          errorMessage = errorMessage ?? `Process exceeded timeout of ${options.timeoutMs}ms`;
        } else if (spawnErrorMessage || exitCode !== 0) {
          status = "failed";
          if (!errorMessage && terminationSignal) {
            errorMessage = `Process terminated by signal ${terminationSignal}`;
          }
        } else {
          status = "completed";
        }

        resolve({
          status,
          exitCode,
          stdout,
          stderr,
          stdoutTruncated: stdoutCollector.truncated,
          stderrTruncated: stderrCollector.truncated,
          durationMs,
          errorMessage,
        });
      };

      const terminateAndEnsureSettle = () => {
        killProcessTree(child.pid);
        if (!forceSettleTimer) {
          forceSettleTimer = setTimeout(() => {
            child.stdout?.destroy();
            child.stderr?.destroy();
            finish(null);
          }, POST_KILL_SETTLE_GRACE_MS);
        }
      };

      const onAbort = () => {
        if (settled) {
          return;
        }
        cancelled = true;
        terminateAndEnsureSettle();
      };

      if (options.signal) {
        options.signal.addEventListener("abort", onAbort, { once: true });
      }

      const timer = setTimeout(() => {
        if (settled) {
          return;
        }
        timedOut = true;
        terminateAndEnsureSettle();
      }, options.timeoutMs);

      child.stdout?.on("data", (chunk: Buffer) => {
        appendBounded(stdoutCollector, chunk, options.maxOutputBytes);
      });

      child.stderr?.on("data", (chunk: Buffer) => {
        appendBounded(stderrCollector, chunk, options.maxOutputBytes);
      });

      child.on("error", (err) => {
        spawnErrorMessage = err.message;
        finish(null);
      });

      child.on("close", (code, sig) => {
        terminationSignal = sig;
        finish(code);
      });
    });
  }
}
