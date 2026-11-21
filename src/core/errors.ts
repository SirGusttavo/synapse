export type SynapseErrorCode =
  | "CONFIG_ERROR"
  | "VALIDATION_ERROR"
  | "POLICY_DENIED"
  | "APPROVAL_DENIED"
  | "EXECUTION_ERROR"
  | "SHELL_ERROR"
  | "STORAGE_ERROR"
  | "TASK_ERROR";

export class SynapseError extends Error {
  public readonly code: SynapseErrorCode;
  public readonly details?: Record<string, unknown>;

  constructor(
    code: SynapseErrorCode,
    message: string,
    options?: { details?: Record<string, unknown>; cause?: unknown },
  ) {
    super(message, { cause: options?.cause });
    this.name = new.target.name;
    this.code = code;
    this.details = options?.details;
  }
}

export class ConfigError extends SynapseError {
  constructor(message: string, options?: { details?: Record<string, unknown>; cause?: unknown }) {
    super("CONFIG_ERROR", message, options);
  }
}

export class ValidationError extends SynapseError {
  constructor(message: string, options?: { details?: Record<string, unknown>; cause?: unknown }) {
    super("VALIDATION_ERROR", message, options);
  }
}

export class PolicyDeniedError extends SynapseError {
  constructor(message: string, options?: { details?: Record<string, unknown>; cause?: unknown }) {
    super("POLICY_DENIED", message, options);
  }
}

export class ApprovalDeniedError extends SynapseError {
  constructor(message: string, options?: { details?: Record<string, unknown>; cause?: unknown }) {
    super("APPROVAL_DENIED", message, options);
  }
}

export class ExecutionError extends SynapseError {
  constructor(message: string, options?: { details?: Record<string, unknown>; cause?: unknown }) {
    super("EXECUTION_ERROR", message, options);
  }
}

export class ShellError extends SynapseError {
  constructor(message: string, options?: { details?: Record<string, unknown>; cause?: unknown }) {
    super("SHELL_ERROR", message, options);
  }
}

export class StorageError extends SynapseError {
  constructor(message: string, options?: { details?: Record<string, unknown>; cause?: unknown }) {
    super("STORAGE_ERROR", message, options);
  }
}

export class TaskError extends SynapseError {
  constructor(message: string, options?: { details?: Record<string, unknown>; cause?: unknown }) {
    super("TASK_ERROR", message, options);
  }
}
