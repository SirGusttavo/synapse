import type { DestinationStream, Logger } from "pino";
import { type LoadConfigOptions, loadConfig, type SynapseConfig } from "../config/index.js";
import { AuditService, createSynapseLogger } from "../modules/audit/index.js";
import {
  ExecutionEngine,
  type IProcessRunner,
  NodeProcessRunner,
  ToolRegistry,
} from "../modules/execution-engine/index.js";
import { createFileTools, FileManager } from "../modules/file-manager/index.js";
import { createGitTools, GitManager } from "../modules/git-manager/index.js";
import {
  type IApprovalHandler,
  NonInteractiveApprovalHandler,
  PolicyEngine,
} from "../modules/security/index.js";
import {
  createShellExecTool,
  PowerShellAdapter,
  type ShellDetectionResult,
  ShellManager,
} from "../modules/shell-manager/index.js";
import { TaskManager, type TaskRunOutcome } from "../modules/task-manager/index.js";
import {
  type AuditQueryFilter,
  SqliteAuditRepository,
  SqliteTaskRepository,
  SynapseDatabase,
} from "../storage/index.js";
import { SynapseEventBus } from "./events.js";
import type { AuditEventRecord, OperationCategory, TaskRecord } from "./types.js";

export interface CreateRuntimeOptions extends LoadConfigOptions {
  approvalHandler?: IApprovalHandler | ((config: SynapseConfig) => IApprovalHandler);
  processRunner?: IProcessRunner;
  logDestination?: DestinationStream;
  inMemoryDb?: boolean;
}

export interface SystemStatusReport {
  workspaceDir: string;
  configFilePath: string | null;
  dbPath: string;
  securityMode: SynapseConfig["security"]["mode"];
  singleFileDeletePermission: SynapseConfig["security"]["singleFileDeletePermission"];
  shell: ShellDetectionResult;
  registeredTools: string[];
  recentTasksCount: number;
}

export class SynapseRuntime {
  public readonly config: SynapseConfig;
  public readonly configFilePath: string | null;
  public readonly eventBus: SynapseEventBus;
  public readonly logger: Logger;
  public readonly auditService: AuditService;
  public readonly taskManager: TaskManager;
  public readonly shellManager: ShellManager;
  public readonly fileManager: FileManager;
  public readonly gitManager: GitManager;
  public readonly toolRegistry: ToolRegistry;

  private readonly database: SynapseDatabase;

  private constructor(params: {
    config: SynapseConfig;
    configFilePath: string | null;
    database: SynapseDatabase;
    eventBus: SynapseEventBus;
    logger: Logger;
    auditService: AuditService;
    taskManager: TaskManager;
    shellManager: ShellManager;
    fileManager: FileManager;
    gitManager: GitManager;
    toolRegistry: ToolRegistry;
  }) {
    this.config = params.config;
    this.configFilePath = params.configFilePath;
    this.database = params.database;
    this.eventBus = params.eventBus;
    this.logger = params.logger;
    this.auditService = params.auditService;
    this.taskManager = params.taskManager;
    this.shellManager = params.shellManager;
    this.fileManager = params.fileManager;
    this.gitManager = params.gitManager;
    this.toolRegistry = params.toolRegistry;
  }

  public static create(options: CreateRuntimeOptions = {}): SynapseRuntime {
    const loaded = loadConfig(options);
    const { config, configFilePath } = loaded;

    const dbPath = options.inMemoryDb ? ":memory:" : config.dbPath;
    const database = new SynapseDatabase(dbPath);
    const eventBus = new SynapseEventBus();
    const logger = createSynapseLogger({
      level: config.logging.level,
      pretty: config.logging.pretty,
      destination: options.logDestination,
    });

    const taskRepository = new SqliteTaskRepository(database.db);
    const auditRepository = new SqliteAuditRepository(database.db);

    const auditService = new AuditService({
      repository: auditRepository,
      logger,
      eventBus,
    });

    const resolvedApprovalHandler =
      typeof options.approvalHandler === "function"
        ? options.approvalHandler(config)
        : (options.approvalHandler ?? new NonInteractiveApprovalHandler());

    const policyEngine = new PolicyEngine({
      workspaceDir: config.workspaceDir,
      securityConfig: config.security,
      approvalHandler: resolvedApprovalHandler,
    });

    const processRunner = options.processRunner ?? new NodeProcessRunner();
    const powerShellAdapter = new PowerShellAdapter({
      processRunner,
      preferred: config.shell.preferred,
      executionPolicy: config.shell.executionPolicy,
    });

    const shellManager = new ShellManager({
      processRunner,
      defaultAdapter: powerShellAdapter,
      extraBlockedEnvPatterns: config.security.extraBlockedEnvPatterns,
    });

    const fileManager = new FileManager({
      workspaceDir: config.workspaceDir,
      allowOutsideWorkspace: config.security.allowOutsideWorkspace,
    });

    const gitManager = new GitManager({
      processRunner,
      workspaceDir: config.workspaceDir,
      allowOutsideWorkspace: config.security.allowOutsideWorkspace,
      extraBlockedEnvPatterns: config.security.extraBlockedEnvPatterns,
    });

    const toolRegistry = new ToolRegistry();
    toolRegistry.register(createShellExecTool(shellManager));
    for (const fileTool of createFileTools(fileManager)) {
      toolRegistry.register(fileTool);
    }
    for (const gitTool of createGitTools(gitManager)) {
      toolRegistry.register(gitTool);
    }

    const executionEngine = new ExecutionEngine({
      registry: toolRegistry,
      defaultTimeoutMs: config.shell.timeoutMs,
      defaultMaxOutputBytes: config.shell.maxOutputBytes,
    });

    const taskManager = new TaskManager({
      taskRepository,
      policyEngine,
      executionEngine,
      auditLogger: auditService,
      eventBus,
    });

    return new SynapseRuntime({
      config,
      configFilePath,
      database,
      eventBus,
      logger,
      auditService,
      taskManager,
      shellManager,
      fileManager,
      gitManager,
      toolRegistry,
    });
  }

  public async executeTool(
    toolName: string,
    category: OperationCategory,
    input: Record<string, unknown>,
    options?: {
      cwd?: string;
      timeoutMs?: number;
      actor?: string;
      sessionId?: string;
      signal?: AbortSignal;
    },
  ): Promise<TaskRunOutcome> {
    const workingDirectory = options?.cwd ?? this.config.workspaceDir;
    return this.taskManager.submitAndRun(
      {
        toolName,
        category,
        input,
        workingDirectory,
        actor: options?.actor ?? "cli-operator",
        sessionId: options?.sessionId,
      },
      {
        timeoutMs: options?.timeoutMs,
        externalSignal: options?.signal,
      },
    );
  }

  public async executeShellCommand(
    command: string,
    options?: {
      cwd?: string;
      timeoutMs?: number;
      actor?: string;
      sessionId?: string;
      signal?: AbortSignal;
    },
  ): Promise<TaskRunOutcome> {
    return this.executeTool(
      "shell.exec",
      "shell",
      {
        command,
        ...(options?.timeoutMs !== undefined ? { timeoutMs: options.timeoutMs } : {}),
      },
      options,
    );
  }

  public async getSystemStatus(): Promise<SystemStatusReport> {
    const shell = await this.shellManager.detectDefault();
    const recentTasks = this.taskManager.listRecentTasks(100);

    return {
      workspaceDir: this.config.workspaceDir,
      configFilePath: this.configFilePath,
      dbPath: this.database.dbPath,
      securityMode: this.config.security.mode,
      singleFileDeletePermission: this.config.security.singleFileDeletePermission,
      shell,
      registeredTools: this.toolRegistry.list().map((tool) => tool.name),
      recentTasksCount: recentTasks.length,
    };
  }

  public queryAudit(filter?: AuditQueryFilter): AuditEventRecord[] {
    return this.auditService.query(filter);
  }

  public listRecentTasks(limit = 20): TaskRecord[] {
    return this.taskManager.listRecentTasks(limit);
  }

  public close(): void {
    this.database.close();
  }
}
