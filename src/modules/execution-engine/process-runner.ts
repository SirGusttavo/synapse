import { spawn } from "node:child_process";
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
        try {
          process.kill(pid, "SIGKILL");
        } catch {
          // Process already exited
        }
      });
    } catch {
      try {
        process.kill(pid, "SIGKILL");
      } catch {
        // Process already exited
      }
    }
    return;
  }

  try {
    process.kill(pid, "SIGKILL");
  } catch {
    // Process already exited
  }
}

/**
 * Executes OS binaries strictly with `shell: false`, sanitized environments,
 * bounded stdout/stderr streaming, timeout enforcement and full process tree cleanup.
 */
export class NodeProcessRunner implements IProcessRunner {
  public async run(options: ProcessRunOptions): Promise<ProcessRunResult> {
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

      const onAbort = () => {
        if (settled) {
          return;
        }
        cancelled = true;
        killProcessTree(child.pid);
      };

      if (options.signal) {
        options.signal.addEventListener("abort", onAbort, { once: true });
      }

      const timer = setTimeout(() => {
        if (settled) {
          return;
        }
        timedOut = true;
        killProcessTree(child.pid);
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

      child.on("close", (code) => {
        finish(code);
      });
    });
  }
}
