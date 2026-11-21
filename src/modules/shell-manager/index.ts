export {
  PowerShellAdapter,
  type PowerShellAdapterOptions,
} from "./adapters/powershell.adapter.js";
export {
  createShellExecTool,
  type ShellExecInput,
  ShellExecInputSchema,
  ShellManager,
  type ShellManagerOptions,
} from "./manager.js";
export type {
  IShellAdapter,
  ShellDetectionResult,
  ShellInvocation,
} from "./types.js";
