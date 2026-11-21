import readline from "node:readline/promises";
import type { Readable, Writable } from "node:stream";
import type {
  ApprovalRequest,
  ApprovalResponse,
  IApprovalHandler,
} from "../../modules/security/index.js";

export interface CliApprovalHandlerOptions {
  input?: Readable & { isTTY?: boolean };
  output?: Writable;
  timeoutMs?: number | null;
}

/**
 * Interactive CLI approval handler. Fails closed when stdin is not an interactive TTY.
 */
export class CliApprovalHandler implements IApprovalHandler {
  private readonly input: Readable & { isTTY?: boolean };
  private readonly output: Writable;
  private readonly timeoutMs: number | null;

  constructor(options: CliApprovalHandlerOptions = {}) {
    this.input = options.input ?? process.stdin;
    this.output = options.output ?? process.stderr;
    this.timeoutMs = options.timeoutMs ?? null;
  }

  public async requestApproval(
    request: ApprovalRequest,
    externalSignal?: AbortSignal,
  ): Promise<ApprovalResponse> {
    if (externalSignal?.aborted) {
      return {
        approved: false,
        approvedBy: null,
        reason: "Operation cancelled before approval prompt",
      };
    }

    if (!this.input.isTTY) {
      return {
        approved: false,
        approvedBy: null,
        reason:
          "Interactive approval required, but stdin is not a TTY (fail-closed policy enforced)",
      };
    }

    const lines = [
      "",
      "=== SYNAPSE: APROVACAO NECESSARIA ===",
      `Tarefa:     ${request.taskId}`,
      `Nivel:      ${request.permissionLevel}`,
      `Ferramenta: ${request.toolName} (${request.category})`,
      `Diretorio:  ${request.workingDirectory}`,
      `Parametros: ${JSON.stringify(request.sanitizedInput)}`,
      `Motivos:    ${request.reasons.join(" | ")}`,
      request.detectedRisks.length > 0 ? `Riscos:     ${request.detectedRisks.join(", ")}` : "",
      "=====================================",
    ].filter((line) => line.length > 0);

    this.output.write(`${lines.join("\n")}\n`);

    const rl = readline.createInterface({
      input: this.input,
      output: this.output,
    });

    const controller = new AbortController();
    let timedOut = false;
    let timer: ReturnType<typeof setTimeout> | undefined;
    if (this.timeoutMs !== null) {
      timer = setTimeout(() => {
        timedOut = true;
        controller.abort();
      }, this.timeoutMs);
    }

    const onExternalAbort = () => controller.abort();
    externalSignal?.addEventListener("abort", onExternalAbort, { once: true });

    try {
      const answer = await rl.question("Aprovar operacao? [s/N]: ", {
        signal: controller.signal,
      });
      const normalized = answer.trim().toLowerCase();
      const approved =
        normalized === "s" || normalized === "sim" || normalized === "y" || normalized === "yes";

      return {
        approved,
        approvedBy: approved ? "cli-operator" : null,
        reason: approved ? undefined : "Negado pelo operador na CLI",
      };
    } catch {
      return {
        approved: false,
        approvedBy: null,
        timedOut,
        reason: timedOut
          ? "Tempo limite de aprovacao excedido (fail-closed)"
          : "Prompt de aprovacao interrompido (fail-closed)",
      };
    } finally {
      if (timer) {
        clearTimeout(timer);
      }
      externalSignal?.removeEventListener("abort", onExternalAbort);
      rl.close();
    }
  }
}
