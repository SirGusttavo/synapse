import type { DestinationStream, Logger } from "pino";
import { type LoadConfigOptions, loadConfig, type SynapseConfig } from "../config/index.js";
import { AuditService, createSynapseLogger } from "../modules/audit/index.js";
import {
  ExecutionEngine,
  type IProcessRunner,
  NodeProcessRunner,
  ToolRegistry,
} from "../modules/execution-engine/index.js";
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
import type { AuditEventRecord, TaskRecord } from "./types.js";

export interface CreateRuntimeOptions extends LoadConfigOptions {
  approvalHandler?: IApprovalHandler;
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

    const policyEngine = new PolicyEngine({
      workspaceDir: config.workspaceDir,
      securityConfig: config.security,
      approvalHandler: options.approvalHandler ?? new NonInteractiveApprovalHandler(),
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

    const toolRegistry = new ToolRegistry();
    toolRegistry.register(createShellExecTool(shellManager));

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
      toolRegistry,
    });
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
    const workingDirectory = options?.cwd ?? this.config.workspaceDir;
    return this.taskManager.submitAndRun(
      {
        toolName: "shell.exec",
        category: "shell",
        input: {
          command,
          ...(options?.timeoutMs !== undefined ? { timeoutMs: options.timeoutMs } : {}),
        },
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
