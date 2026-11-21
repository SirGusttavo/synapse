import type { SynapseConfig } from "../../config/schema.js";
import { PolicyDeniedError } from "../../core/errors.js";
import type { ApprovalStatus, OperationRequest, PermissionLevel } from "../../core/types.js";
import {
  assertSafeCloneUrl,
  assertSafeGitPaths,
  assertSafeGitRef,
} from "../git-manager/preflight.js";
import { analyzeShellCommand } from "./command-analyzer.js";
import { redactValue } from "./redactor.js";
import {
  type ApprovalRequest,
  type ApprovalResponse,
  AUTHORIZED_OPERATION_BRAND,
  type AuthorizedOperation,
  computeAuthorizationDigest,
  type IApprovalHandler,
  type IPolicyEngine,
  isAuthorizedOperation,
  type PolicyEvaluationResult,
  type RevalidationResult,
} from "./types.js";
import { assertWorkingDirectoryAllowed, inspectWorkspacePath } from "./workspace-guard.js";

function deepFreeze<T>(value: T): T {
  if (value === null || typeof value !== "object") {
    return value;
  }
  Object.freeze(value);
  for (const nested of Object.values(value as Record<string, unknown>)) {
    if (nested !== null && typeof nested === "object" && !Object.isFrozen(nested)) {
      deepFreeze(nested);
    }
  }
  return value;
}

function snapshotRequest(request: OperationRequest): Readonly<OperationRequest> {
  return deepFreeze(structuredClone(request));
}

export function isMutatingOperation(request: Readonly<OperationRequest>): boolean {
  if (request.category === "file") {
    return (
      request.toolName !== "file.list" &&
      request.toolName !== "file.read" &&
      request.toolName !== "file.search"
    );
  }

  if (request.category === "git") {
    if (
      request.toolName === "git.status" ||
      request.toolName === "git.diff" ||
      request.toolName === "git.log"
    ) {
      return false;
    }
    if (request.toolName === "git.branch" || request.toolName === "git.tag") {
      return request.input.action !== undefined && request.input.action !== "list";
    }
    return true;
  }

  // Shell and system operations default conservatively to exclusive write lock
  return true;
}

/**
 * Default fail-closed approval handler used when no interactive operator is attached.
 */
export class NonInteractiveApprovalHandler implements IApprovalHandler {
  public async requestApproval(
    _request: ApprovalRequest,
    _signal?: AbortSignal,
  ): Promise<ApprovalResponse> {
    return {
      approved: false,
      approvedBy: null,
      reason: "Approval required but no interactive approval handler is available (fail-closed)",
    };
  }
}

export interface PolicyEngineOptions {
  workspaceDir: string;
  securityConfig: SynapseConfig["security"];
  approvalHandler?: IApprovalHandler;
}

export class PolicyEngine implements IPolicyEngine {
  private readonly workspaceDir: string;
  private readonly securityConfig: SynapseConfig["security"];
  private readonly approvalHandler: IApprovalHandler;

  constructor(options: PolicyEngineOptions) {
    this.workspaceDir = options.workspaceDir;
    this.securityConfig = options.securityConfig;
    this.approvalHandler = options.approvalHandler ?? new NonInteractiveApprovalHandler();
  }

  public async evaluateAndAuthorize(
    taskId: string,
    request: OperationRequest,
    hooks?: { onAwaitingApproval?: (req: ApprovalRequest) => void; signal?: AbortSignal },
  ): Promise<PolicyEvaluationResult> {
    const frozenRequest = snapshotRequest(request);

    let canonicalWorkingDirectory: string;
    let insideWorkspace: boolean;
    try {
      const validation = assertWorkingDirectoryAllowed(
        this.workspaceDir,
        frozenRequest.workingDirectory,
        this.securityConfig.allowOutsideWorkspace,
      );
      canonicalWorkingDirectory = validation.canonicalPath;
      insideWorkspace = validation.insideWorkspace;
    } catch (error) {
      const reason =
        error instanceof PolicyDeniedError
          ? error.message
          : "Working directory failed workspace boundary validation";
      return {
        allowed: false,
        policyLevel: "DENIED",
        policyDecision: "DENIED",
        approvalStatus: "not_required",
        approvedBy: null,
        reasons: [reason],
        detectedRisks: ["workspace_escape"],
      };
    }

    const classification = this.classifyOperation(
      frozenRequest,
      canonicalWorkingDirectory,
      insideWorkspace,
    );

    if (classification.level === "DENIED") {
      return {
        allowed: false,
        policyLevel: "DENIED",
        policyDecision: "DENIED",
        approvalStatus: "not_required",
        approvedBy: null,
        reasons: classification.reasons,
        detectedRisks: classification.detectedRisks,
      };
    }

    const mutating = isMutatingOperation(frozenRequest);
    const inputDigest = computeAuthorizationDigest({
      taskId,
      toolName: frozenRequest.toolName,
      category: frozenRequest.category,
      canonicalWorkingDirectory,
      input: frozenRequest.input,
    });

    if (classification.level === "AUTO") {
      const authorized: AuthorizedOperation = deepFreeze({
        [AUTHORIZED_OPERATION_BRAND]: true,
        taskId,
        request: frozenRequest,
        canonicalWorkingDirectory,
        policyLevel: "AUTO",
        policyDecision: "AUTO",
        approvalStatus: "not_required",
        approvedBy: null,
        reasons: [...classification.reasons],
        mutating,
        inputDigest,
      });
      return { allowed: true, authorized };
    }

    if (hooks?.signal?.aborted) {
      return {
        allowed: false,
        policyLevel: classification.level,
        policyDecision: "DENIED",
        approvalStatus: "denied",
        approvedBy: null,
        reasons: [...classification.reasons, "Operation cancelled before approval"],
        detectedRisks: classification.detectedRisks,
      };
    }

    const approvalRequest: ApprovalRequest = {
      taskId,
      actor: frozenRequest.actor,
      toolName: frozenRequest.toolName,
      category: frozenRequest.category,
      workingDirectory: canonicalWorkingDirectory,
      sanitizedInput: redactValue(frozenRequest.input) as Record<string, unknown>,
      permissionLevel: classification.level,
      reasons: classification.reasons,
      detectedRisks: classification.detectedRisks,
    };

    hooks?.onAwaitingApproval?.(approvalRequest);

    const response = await this.approvalHandler.requestApproval(approvalRequest, hooks?.signal);
    const approvalStatus: ApprovalStatus = response.approved
      ? "approved"
      : response.timedOut
        ? "timed_out"
        : "denied";

    if (!response.approved || hooks?.signal?.aborted) {
      const denialReasons = hooks?.signal?.aborted
        ? [...classification.reasons, "Operation cancelled during approval"]
        : response.reason
          ? [...classification.reasons, response.reason]
          : [...classification.reasons, "Operation denied by operator"];
      return {
        allowed: false,
        policyLevel: classification.level,
        policyDecision: "DENIED",
        approvalStatus: hooks?.signal?.aborted ? "denied" : approvalStatus,
        approvedBy: response.approvedBy,
        reasons: denialReasons,
        detectedRisks: classification.detectedRisks,
      };
    }

    const authorized: AuthorizedOperation = deepFreeze({
      [AUTHORIZED_OPERATION_BRAND]: true,
      taskId,
      request: frozenRequest,
      canonicalWorkingDirectory,
      policyLevel: classification.level,
      policyDecision: classification.level,
      approvalStatus: "approved",
      approvedBy: response.approvedBy ?? "human-operator",
      reasons: [...classification.reasons],
      mutating,
      inputDigest,
    });

    return { allowed: true, authorized };
  }

  /**
   * Re-validates an already-minted authorization immediately prior to executing
   * a mutating operation (after acquiring WorkspaceLock) to defeat TOCTOU / symlink swaps.
   */
  public revalidateAuthorized(authorized: AuthorizedOperation): RevalidationResult {
    if (!isAuthorizedOperation(authorized)) {
      return {
        valid: false,
        reasons: ["Authorization object is missing valid PolicyEngine brand"],
        detectedRisks: ["forged_authorization"],
      };
    }

    const expectedDigest = computeAuthorizationDigest({
      taskId: authorized.taskId,
      toolName: authorized.request.toolName,
      category: authorized.request.category,
      canonicalWorkingDirectory: authorized.canonicalWorkingDirectory,
      input: authorized.request.input,
    });
    if (expectedDigest !== authorized.inputDigest) {
      return {
        valid: false,
        reasons: ["Authorization parameter digest mismatch (possible tampering)"],
        detectedRisks: ["authorization_tampering"],
      };
    }

    let canonicalNow: string;
    let insideWorkspace: boolean;
    try {
      const validation = assertWorkingDirectoryAllowed(
        this.workspaceDir,
        authorized.request.workingDirectory,
        this.securityConfig.allowOutsideWorkspace,
      );
      canonicalNow = validation.canonicalPath;
      insideWorkspace = validation.insideWorkspace;
    } catch (error) {
      const reason =
        error instanceof PolicyDeniedError
          ? error.message
          : "Working directory no longer passes workspace boundary validation";
      return {
        valid: false,
        reasons: [reason],
        detectedRisks: ["workspace_escape_toctou"],
      };
    }

    const normA = process.platform === "win32" ? canonicalNow.toLowerCase() : canonicalNow;
    const normB =
      process.platform === "win32"
        ? authorized.canonicalWorkingDirectory.toLowerCase()
        : authorized.canonicalWorkingDirectory;

    if (normA !== normB) {
      return {
        valid: false,
        reasons: [
          `Working directory canonical target changed between authorization and execution (${authorized.canonicalWorkingDirectory} -> ${canonicalNow})`,
        ],
        detectedRisks: ["workspace_symlink_toctou"],
      };
    }

    const recheck = this.classifyOperation(authorized.request, canonicalNow, insideWorkspace);
    if (recheck.level === "DENIED") {
      return {
        valid: false,
        reasons: recheck.reasons,
        detectedRisks: recheck.detectedRisks,
      };
    }

    // If an AUTO or CONDITIONAL authorization escalated to a higher risk level (e.g., via symlink swap), reject!
    if (authorized.policyLevel === "AUTO" && recheck.level !== "AUTO") {
      return {
        valid: false,
        reasons: [
          "Operation risk level escalated since initial AUTO authorization",
          ...recheck.reasons,
        ],
        detectedRisks: [...recheck.detectedRisks, "policy_escalation_toctou"],
      };
    }
    if (authorized.policyLevel === "CONDITIONAL" && recheck.level === "HUMAN_APPROVAL") {
      return {
        valid: false,
        reasons: [
          "Operation risk level escalated from CONDITIONAL to HUMAN_APPROVAL before execution",
          ...recheck.reasons,
        ],
        detectedRisks: [...recheck.detectedRisks, "policy_escalation_toctou"],
      };
    }

    return { valid: true };
  }

  protected classifyOperation(
    request: Readonly<OperationRequest>,
    canonicalWorkingDirectory: string,
    insideWorkspace: boolean,
  ): {
    level: PermissionLevel;
    reasons: string[];
    detectedRisks: string[];
  } {
    let base: { level: PermissionLevel; reasons: string[]; detectedRisks: string[] };

    if (request.category === "shell" && request.toolName === "shell.exec") {
      const rawCommand = typeof request.input.command === "string" ? request.input.command : "";
      const analysis = analyzeShellCommand(rawCommand, this.securityConfig.allowedShellCommands);
      base = {
        level: analysis.level,
        reasons: analysis.reasons,
        detectedRisks: analysis.detectedRisks,
      };
    } else if (request.category === "file") {
      base = this.classifyFileOperation(request, canonicalWorkingDirectory);
    } else if (request.category === "git") {
      base = this.classifyGitOperation(request, canonicalWorkingDirectory);
    } else {
      // RNF-01: Strict deny-by-default for unmapped/unknown operations
      return {
        level: "DENIED",
        reasons: [`Unmapped operation '${request.toolName}' is denied by default policy`],
        detectedRisks: ["unmapped_operation"],
      };
    }

    // Operations outside workspace (when explicitly enabled by config) can never run as AUTO
    if (!insideWorkspace && base.level !== "DENIED") {
      return {
        level: "HUMAN_APPROVAL",
        reasons: [...base.reasons, "Operation targets directory outside workspace"],
        detectedRisks: [...base.detectedRisks, "outside_workspace"],
      };
    }

    return base;
  }

  private classifyGitOperation(
    request: Readonly<OperationRequest>,
    canonicalWorkingDirectory: string,
  ): {
    level: PermissionLevel;
    reasons: string[];
    detectedRisks: string[];
  } {
    const input = request.input;

    // Hard block any attempt to smuggle destructive flags via tool input
    if (input.force === true || input.hard === true || input.forceWithLease === true) {
      return {
        level: "DENIED",
        reasons: ["Destructive Git flags (force / hard) are blocked by default policy"],
        detectedRisks: ["git_destructive_flag"],
      };
    }

    try {
      switch (request.toolName) {
        case "git.status":
          return {
            level: "AUTO",
            reasons: ["git.status is a read-only operation within the workspace"],
            detectedRisks: [],
          };

        case "git.diff": {
          if (typeof input.target === "string") {
            assertSafeGitRef(input.target, "diff target");
          }
          if (Array.isArray(input.paths)) {
            const paths = input.paths.filter((p): p is string => typeof p === "string");
            assertSafeGitPaths(this.workspaceDir, canonicalWorkingDirectory, paths, {
              allowOutsideWorkspace: this.securityConfig.allowOutsideWorkspace,
              forbidSensitive: true,
            });
          }
          return {
            level: "AUTO",
            reasons: ["git.diff is a read-only operation within the workspace"],
            detectedRisks: [],
          };
        }

        case "git.log": {
          if (typeof input.ref === "string") {
            assertSafeGitRef(input.ref, "log ref");
          }
          return {
            level: "AUTO",
            reasons: ["git.log is a read-only operation within the workspace"],
            detectedRisks: [],
          };
        }

        case "git.branch": {
          const action = typeof input.action === "string" ? input.action : "list";
          if (action === "list") {
            return {
              level: "AUTO",
              reasons: ["Listing Git branches is a read-only operation"],
              detectedRisks: [],
            };
          }
          if (typeof input.name !== "string") {
            return {
              level: "DENIED",
              reasons: [`git.branch action '${action}' requires a valid branch name`],
              detectedRisks: ["invalid_git_ref"],
            };
          }
          assertSafeGitRef(input.name, "branch name");
          if (typeof input.startPoint === "string") {
            assertSafeGitRef(input.startPoint, "branch startPoint");
          }
          if (action === "create") {
            return {
              level: "CONDITIONAL",
              reasons: ["Creating a Git branch requires conditional validation"],
              detectedRisks: ["git_branch_create"],
            };
          }
          if (action === "delete") {
            return {
              level: "HUMAN_APPROVAL",
              reasons: ["Deleting a Git branch requires explicit human approval"],
              detectedRisks: ["git_branch_delete"],
            };
          }
          return {
            level: "DENIED",
            reasons: [`Unsupported git.branch action '${action}'`],
            detectedRisks: ["invalid_git_action"],
          };
        }

        case "git.tag": {
          const action = typeof input.action === "string" ? input.action : "list";
          if (action === "list") {
            return {
              level: "AUTO",
              reasons: ["Listing Git tags is a read-only operation"],
              detectedRisks: [],
            };
          }
          if (typeof input.name !== "string") {
            return {
              level: "DENIED",
              reasons: [`git.tag action '${action}' requires a valid tag name`],
              detectedRisks: ["invalid_git_ref"],
            };
          }
          assertSafeGitRef(input.name, "tag name");
          if (typeof input.target === "string") {
            assertSafeGitRef(input.target, "tag target");
          }
          if (action === "create") {
            return {
              level: "CONDITIONAL",
              reasons: ["Creating a Git tag requires conditional validation"],
              detectedRisks: ["git_tag_create"],
            };
          }
          if (action === "delete") {
            return {
              level: "HUMAN_APPROVAL",
              reasons: ["Deleting a Git tag requires explicit human approval"],
              detectedRisks: ["git_tag_delete"],
            };
          }
          return {
            level: "DENIED",
            reasons: [`Unsupported git.tag action '${action}'`],
            detectedRisks: ["invalid_git_action"],
          };
        }

        case "git.init": {
          const branch = typeof input.initialBranch === "string" ? input.initialBranch : "main";
          assertSafeGitRef(branch, "initialBranch");
          return {
            level: "CONDITIONAL",
            reasons: ["Initializing a Git repository requires conditional validation"],
            detectedRisks: ["git_init"],
          };
        }

        case "git.clone": {
          if (typeof input.url !== "string" || typeof input.directory !== "string") {
            return {
              level: "DENIED",
              reasons: ["git.clone requires valid 'url' and 'directory' strings"],
              detectedRisks: ["invalid_git_clone"],
            };
          }
          assertSafeCloneUrl(input.url);
          if (typeof input.branch === "string") {
            assertSafeGitRef(input.branch, "clone branch");
          }
          const dirInfo = inspectWorkspacePath(
            this.workspaceDir,
            canonicalWorkingDirectory,
            input.directory,
          );
          if (!dirInfo.insideWorkspace && !this.securityConfig.allowOutsideWorkspace) {
            return {
              level: "DENIED",
              reasons: [`Clone target directory escapes authorized workspace: ${input.directory}`],
              detectedRisks: ["workspace_escape"],
            };
          }
          return {
            level: dirInfo.insideWorkspace ? "CONDITIONAL" : "HUMAN_APPROVAL",
            reasons: ["Cloning a remote repository requires validation/approval"],
            detectedRisks: ["git_clone"],
          };
        }

        case "git.checkout": {
          if (typeof input.target !== "string") {
            return {
              level: "DENIED",
              reasons: ["git.checkout requires a valid target branch or ref"],
              detectedRisks: ["invalid_git_ref"],
            };
          }
          assertSafeGitRef(input.target, "checkout target");
          return {
            level: "CONDITIONAL",
            reasons: ["Switching branches with git.checkout requires conditional validation"],
            detectedRisks: ["git_checkout"],
          };
        }

        case "git.add": {
          if (!Array.isArray(input.paths) || input.paths.length === 0) {
            return {
              level: "DENIED",
              reasons: ["git.add requires a non-empty array of paths"],
              detectedRisks: ["invalid_git_paths"],
            };
          }
          const paths = input.paths.filter((p): p is string => typeof p === "string");
          if (paths.length !== input.paths.length) {
            return {
              level: "DENIED",
              reasons: ["All git.add paths must be strings"],
              detectedRisks: ["invalid_git_paths"],
            };
          }
          assertSafeGitPaths(this.workspaceDir, canonicalWorkingDirectory, paths, {
            allowOutsideWorkspace: this.securityConfig.allowOutsideWorkspace,
            forbidSensitive: true,
          });
          return {
            level: "CONDITIONAL",
            reasons: ["Staging files with git.add requires conditional validation"],
            detectedRisks: ["git_add"],
          };
        }

        case "git.commit": {
          if (typeof input.message !== "string" || input.message.trim().length === 0) {
            return {
              level: "DENIED",
              reasons: ["git.commit requires a non-empty commit message"],
              detectedRisks: ["invalid_commit_message"],
            };
          }
          return {
            level: "CONDITIONAL",
            reasons: ["Creating a Git commit requires conditional validation/approval"],
            detectedRisks: ["git_commit"],
          };
        }

        case "git.pull": {
          const remote = typeof input.remote === "string" ? input.remote : "origin";
          assertSafeGitRef(remote, "pull remote");
          if (typeof input.branch === "string") {
            assertSafeGitRef(input.branch, "pull branch");
          }
          return {
            level: "CONDITIONAL",
            reasons: ["Pulling changes from remote requires conditional validation/approval"],
            detectedRisks: ["git_pull"],
          };
        }

        case "git.push": {
          const remote = typeof input.remote === "string" ? input.remote : "origin";
          assertSafeGitRef(remote, "push remote");
          if (typeof input.branch === "string") {
            assertSafeGitRef(input.branch, "push branch");
          }
          return {
            level: "HUMAN_APPROVAL",
            reasons: ["Publishing commits with git.push requires explicit human approval"],
            detectedRisks: ["git_push"],
          };
        }

        case "git.merge": {
          if (typeof input.branch !== "string") {
            return {
              level: "DENIED",
              reasons: ["git.merge requires a valid branch name"],
              detectedRisks: ["invalid_git_ref"],
            };
          }
          assertSafeGitRef(input.branch, "merge branch");
          return {
            level: "CONDITIONAL",
            reasons: ["Merging a branch requires conditional validation/approval"],
            detectedRisks: ["git_merge"],
          };
        }

        default:
          return {
            level: "DENIED",
            reasons: [`Unmapped Git operation '${request.toolName}' is denied by default policy`],
            detectedRisks: ["unmapped_operation"],
          };
      }
    } catch (error) {
      const reason =
        error instanceof PolicyDeniedError ? error.message : "Git parameter validation failed";
      return {
        level: "DENIED",
        reasons: [reason],
        detectedRisks: ["git_policy_violation"],
      };
    }
  }

  private classifyFileOperation(
    request: Readonly<OperationRequest>,
    canonicalWorkingDirectory: string,
  ): {
    level: PermissionLevel;
    reasons: string[];
    detectedRisks: string[];
  } {
    const mutating = isMutatingOperation(request);
    const candidatePaths: string[] = [];

    if (request.toolName === "file.move") {
      if (typeof request.input.from !== "string" || typeof request.input.to !== "string") {
        return {
          level: "DENIED",
          reasons: ["file.move requires valid 'from' and 'to' string paths"],
          detectedRisks: ["invalid_file_path"],
        };
      }
      candidatePaths.push(request.input.from, request.input.to);
    } else if (request.toolName === "file.list" || request.toolName === "file.search") {
      const target = typeof request.input.path === "string" ? request.input.path : ".";
      candidatePaths.push(target);
    } else if (
      request.toolName === "file.read" ||
      request.toolName === "file.create" ||
      request.toolName === "file.edit" ||
      request.toolName === "file.delete"
    ) {
      if (typeof request.input.path !== "string" || request.input.path.trim().length === 0) {
        return {
          level: "DENIED",
          reasons: [`${request.toolName} requires a non-empty 'path' string`],
          detectedRisks: ["invalid_file_path"],
        };
      }
      candidatePaths.push(request.input.path);
    } else {
      return {
        level: "DENIED",
        reasons: [`Unmapped file operation '${request.toolName}' is denied by default policy`],
        detectedRisks: ["unmapped_operation"],
      };
    }

    let touchesOutsideWorkspace = false;
    let touchesSensitiveConfig = false;

    for (const rawPath of candidatePaths) {
      try {
        const info = inspectWorkspacePath(this.workspaceDir, canonicalWorkingDirectory, rawPath);

        if (!info.insideWorkspace) {
          if (!this.securityConfig.allowOutsideWorkspace) {
            return {
              level: "DENIED",
              reasons: [`File path escapes authorized workspace: ${rawPath}`],
              detectedRisks: ["workspace_escape"],
            };
          }
          touchesOutsideWorkspace = true;
        }

        if (info.isSensitive) {
          return {
            level: "DENIED",
            reasons: [`Access to sensitive credential/secret file is blocked: ${rawPath}`],
            detectedRisks: ["sensitive_file_access"],
          };
        }

        if (mutating && info.isInternalGit) {
          return {
            level: "DENIED",
            reasons: [`Direct mutation of internal .git directory is blocked: ${rawPath}`],
            detectedRisks: ["internal_git_mutation"],
          };
        }

        if (mutating && info.isWorkspaceRoot) {
          return {
            level: "DENIED",
            reasons: ["Mutating or deleting the workspace root directory is blocked"],
            detectedRisks: ["workspace_root_mutation"],
          };
        }

        if (mutating && info.isSensitiveConfig) {
          touchesSensitiveConfig = true;
        }
      } catch (error) {
        const message =
          error instanceof PolicyDeniedError ? error.message : `Invalid file path: ${rawPath}`;
        return {
          level: "DENIED",
          reasons: [message],
          detectedRisks: ["invalid_file_path"],
        };
      }
    }

    if (touchesOutsideWorkspace) {
      return {
        level: "HUMAN_APPROVAL",
        reasons: ["File operation targets a path outside the workspace"],
        detectedRisks: ["outside_workspace"],
      };
    }

    if (touchesSensitiveConfig) {
      return {
        level: "HUMAN_APPROVAL",
        reasons: ["Modifying SYNAPSE configuration or policy files requires human approval"],
        detectedRisks: ["sensitive_config_modification"],
      };
    }

    switch (request.toolName) {
      case "file.list":
      case "file.read":
      case "file.search":
      case "file.create":
      case "file.edit":
        return {
          level: "AUTO",
          reasons: [`${request.toolName} is permitted within the authorized workspace`],
          detectedRisks: [],
        };
      case "file.move":
        return {
          level: "CONDITIONAL",
          reasons: ["Moving or renaming files requires conditional validation/approval"],
          detectedRisks: ["file_move"],
        };
      case "file.delete": {
        const isRecursive = request.input.recursive === true;
        const level: PermissionLevel = isRecursive
          ? "HUMAN_APPROVAL"
          : this.securityConfig.singleFileDeletePermission;
        return {
          level,
          reasons: [
            isRecursive
              ? "Directory deletion requires explicit human approval"
              : "Single file deletion requires human approval by policy (D-06)",
          ],
          detectedRisks: [isRecursive ? "directory_deletion" : "file_deletion"],
        };
      }
      default:
        return {
          level: "DENIED",
          reasons: [`Unmapped file operation '${request.toolName}' is denied`],
          detectedRisks: ["unmapped_operation"],
        };
    }
  }
}
