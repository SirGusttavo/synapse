import { z } from "zod";

export const LogLevelSchema = z.enum([
  "fatal",
  "error",
  "warn",
  "info",
  "debug",
  "trace",
  "silent",
]);

export const PreferredShellSchema = z.enum(["auto", "pwsh", "powershell"]);

export const PowerShellExecutionPolicySchema = z.enum(["Bypass", "RemoteSigned", "Default"]);

export const PermissionLevelSchema = z.enum(["AUTO", "CONDITIONAL", "HUMAN_APPROVAL", "DENIED"]);

export const DEFAULT_ALLOWED_SHELL_COMMANDS: readonly string[] = [
  "Get-Location",
  "Get-ChildItem",
  "Get-Date",
  "Write-Output",
  "echo",
  "pwd",
  "ls",
  "dir",
  "node --version",
  "node -v",
  "npm --version",
  "npm -v",
  "npm test",
  "npm run test",
  "npm run build",
  "npm run typecheck",
  "npm run lint",
  "npm run verify",
  "npx vitest run",
  "npx tsc --noEmit",
  "npx biome check",
  "git status",
  "git log",
  "git diff",
  "git branch",
  "git tag",
];

export const LoggingConfigSchema = z
  .object({
    level: LogLevelSchema.default("info"),
    pretty: z.boolean().default(false),
  })
  .strict()
  .default({ level: "info", pretty: false });

export const ShellConfigSchema = z
  .object({
    preferred: PreferredShellSchema.default("auto"),
    timeoutMs: z.number().int().min(500).max(600_000).default(30_000),
    maxOutputBytes: z.number().int().min(1024).max(10_485_760).default(262_144),
    executionPolicy: PowerShellExecutionPolicySchema.default("Bypass"),
  })
  .strict()
  .default({
    preferred: "auto",
    timeoutMs: 30_000,
    maxOutputBytes: 262_144,
    executionPolicy: "Bypass",
  });

export const SecurityConfigSchema = z
  .object({
    mode: z.enum(["strict", "balanced"]).default("strict"),
    allowedShellCommands: z.array(z.string().min(1)).default([...DEFAULT_ALLOWED_SHELL_COMMANDS]),
    singleFileDeletePermission: PermissionLevelSchema.default("HUMAN_APPROVAL"),
    allowOutsideWorkspace: z.boolean().default(false),
    extraBlockedEnvPatterns: z.array(z.string().min(1)).default([]),
    approvalTimeoutMs: z.number().int().min(1_000).max(600_000).nullable().default(null),
  })
  .strict()
  .default({
    mode: "strict",
    allowedShellCommands: [...DEFAULT_ALLOWED_SHELL_COMMANDS],
    singleFileDeletePermission: "HUMAN_APPROVAL",
    allowOutsideWorkspace: false,
    extraBlockedEnvPatterns: [],
    approvalTimeoutMs: null,
  });

export const SynapseConfigInputSchema = z
  .object({
    workspaceDir: z.string().min(1).optional(),
    dataDir: z.string().min(1).optional(),
    dbPath: z.string().min(1).optional(),
    logging: LoggingConfigSchema.optional(),
    shell: ShellConfigSchema.optional(),
    security: SecurityConfigSchema.optional(),
  })
  .strict();

export const SynapseConfigSchema = z
  .object({
    workspaceDir: z.string().min(1),
    dataDir: z.string().min(1),
    dbPath: z.string().min(1),
    logging: LoggingConfigSchema,
    shell: ShellConfigSchema,
    security: SecurityConfigSchema,
  })
  .strict();

export type LogLevel = z.infer<typeof LogLevelSchema>;
export type PreferredShell = z.infer<typeof PreferredShellSchema>;
export type SynapseConfig = z.infer<typeof SynapseConfigSchema>;
export type SynapseConfigInput = z.input<typeof SynapseConfigInputSchema>;
