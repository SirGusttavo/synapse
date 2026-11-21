import os from "node:os";
import type { PreferredShell } from "../../../config/schema.js";
import { ShellError } from "../../../core/errors.js";
import type { IProcessRunner } from "../../execution-engine/process-runner.js";
import type { IShellAdapter, ShellDetectionResult, ShellInvocation } from "../types.js";

export interface PowerShellAdapterOptions {
  processRunner: IProcessRunner;
  preferred?: PreferredShell;
  executionPolicy?: "Bypass" | "RemoteSigned" | "Default";
}

function buildWrappedPowerShellScript(command: string): string {
  // Pass command text as a pure Base64 data literal so user input can never syntactically
  // break out of the outer try/catch error-handling and UTF-8 bootstrap wrapper.
  const base64Command = Buffer.from(command, "utf8").toString("base64");

  return [
    "[Console]::InputEncoding = [Console]::OutputEncoding = $OutputEncoding = [System.Text.UTF8Encoding]::new($false)",
    "if (Get-Variable -Name PSStyle -ErrorAction SilentlyContinue) { $PSStyle.OutputRendering = 'PlainText' }",
    "$global:LASTEXITCODE = 0",
    "$Error.Clear()",
    `$__synapse_raw = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String('${base64Command}'))`,
    "try {",
    "  $__synapse_sb = [scriptblock]::Create($__synapse_raw)",
    "  . $__synapse_sb",
    "} catch {",
    "  [Console]::Error.WriteLine($_.Exception.Message)",
    "  exit 1",
    "}",
    "if ($null -ne $LASTEXITCODE -and $LASTEXITCODE -ne 0) { exit $LASTEXITCODE }",
    "if (-not $? -or $Error.Count -gt 0) { exit 1 }",
  ].join("\n");
}

export class PowerShellAdapter implements IShellAdapter {
  public readonly id = "powershell";
  public readonly displayName = "PowerShell (Windows)";

  private readonly processRunner: IProcessRunner;
  private readonly preferred: PreferredShell;
  private readonly executionPolicy: "Bypass" | "RemoteSigned" | "Default";
  private cachedDetection: ShellDetectionResult | null = null;

  constructor(options: PowerShellAdapterOptions) {
    this.processRunner = options.processRunner;
    this.preferred = options.preferred ?? "auto";
    this.executionPolicy = options.executionPolicy ?? "Bypass";
  }

  private getCandidates(): string[] {
    if (this.preferred === "pwsh") {
      return ["pwsh.exe"];
    }
    if (this.preferred === "powershell") {
      return ["powershell.exe"];
    }
    return ["pwsh.exe", "powershell.exe"];
  }

  public async detect(): Promise<ShellDetectionResult> {
    if (this.cachedDetection) {
      return this.cachedDetection;
    }

    for (const candidate of this.getCandidates()) {
      const probe = await this.processRunner.run({
        executable: candidate,
        args: ["-NoProfile", "-NonInteractive", "-Command", "$PSVersionTable.PSVersion.ToString()"],
        cwd: os.tmpdir(),
        timeoutMs: 5_000,
        maxOutputBytes: 4_096,
      });

      if (probe.status === "completed" && probe.exitCode === 0) {
        const result: ShellDetectionResult = {
          available: true,
          executable: candidate,
          version: probe.stdout.trim() || null,
        };
        this.cachedDetection = result;
        return result;
      }
    }

    return {
      available: false,
      executable: this.getCandidates()[0] ?? "pwsh.exe",
      version: null,
    };
  }

  public async buildInvocation(command: string): Promise<ShellInvocation> {
    const detected = await this.detect();
    if (!detected.available) {
      throw new ShellError(
        `No compatible PowerShell executable found (preferred=${this.preferred})`,
        { details: { preferred: this.preferred } },
      );
    }

    const args: string[] = ["-NoProfile", "-NonInteractive"];
    if (this.executionPolicy !== "Default") {
      args.push("-ExecutionPolicy", this.executionPolicy);
    }
    args.push("-Command", buildWrappedPowerShellScript(command));

    return {
      executable: detected.executable,
      args,
    };
  }
}
