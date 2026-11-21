import fs from "node:fs";
import path from "node:path";
import { ConfigError } from "../core/errors.js";
import { loadLocalEnvFile } from "./env-loader.js";
import { parseJsonc } from "./jsonc.js";
import {
  type SynapseConfig,
  type SynapseConfigInput,
  SynapseConfigInputSchema,
  SynapseConfigSchema,
} from "./schema.js";

export interface LoadConfigOptions {
  workspaceDir?: string;
  configPath?: string;
  overrides?: SynapseConfigInput;
  processEnv?: NodeJS.ProcessEnv;
}

export interface LoadedConfigResult {
  config: SynapseConfig;
  configFilePath: string | null;
  loadedEnvKeys: string[];
}

const DEFAULT_CONFIG_CANDIDATES = [".synapse/config.jsonc", ".synapse/config.json"] as const;

function resolveConfigFile(workspaceDir: string, explicitPath?: string): string | null {
  if (explicitPath) {
    const resolved = path.resolve(workspaceDir, explicitPath);
    if (!fs.existsSync(resolved)) {
      throw new ConfigError(`Configuration file not found: ${resolved}`, {
        details: { configPath: resolved },
      });
    }
    return resolved;
  }

  for (const relativeCandidate of DEFAULT_CONFIG_CANDIDATES) {
    const candidate = path.resolve(workspaceDir, relativeCandidate);
    if (fs.existsSync(candidate) && fs.statSync(candidate).isFile()) {
      return candidate;
    }
  }

  return null;
}

function readEnvValue(
  key: string,
  processEnv: NodeJS.ProcessEnv,
  localEnv: Record<string, string>,
): string | undefined {
  const fromProcess = processEnv[key];
  if (fromProcess !== undefined && fromProcess !== "") {
    return fromProcess;
  }
  const fromLocal = localEnv[key];
  if (fromLocal !== undefined && fromLocal !== "") {
    return fromLocal;
  }
  return undefined;
}

export function loadConfig(options: LoadConfigOptions = {}): LoadedConfigResult {
  const processEnv = options.processEnv ?? process.env;
  const initialWorkspace = path.resolve(options.workspaceDir ?? process.cwd());
  const localEnv = loadLocalEnvFile(initialWorkspace);

  const envWorkspace = readEnvValue("SYNAPSE_WORKSPACE", processEnv, localEnv);
  const effectiveBaseWorkspace = options.workspaceDir
    ? initialWorkspace
    : envWorkspace
      ? path.resolve(initialWorkspace, envWorkspace)
      : initialWorkspace;

  const configFilePath = resolveConfigFile(effectiveBaseWorkspace, options.configPath);
  let fileInput: SynapseConfigInput = {};

  if (configFilePath) {
    const raw = fs.readFileSync(configFilePath, "utf8");
    const parsed = parseJsonc(raw, configFilePath);
    const validatedFile = SynapseConfigInputSchema.safeParse(parsed);
    if (!validatedFile.success) {
      throw new ConfigError(`Invalid configuration in ${configFilePath}`, {
        details: { issues: validatedFile.error.issues },
      });
    }
    fileInput = validatedFile.data;
  }

  const workspaceDir = path.resolve(
    options.overrides?.workspaceDir ?? fileInput.workspaceDir ?? effectiveBaseWorkspace,
  );
  const dataDir = path.resolve(
    workspaceDir,
    options.overrides?.dataDir ?? fileInput.dataDir ?? ".synapse",
  );
  const envDbPath = readEnvValue("SYNAPSE_DB_PATH", processEnv, localEnv);
  const dbPath = path.resolve(
    workspaceDir,
    options.overrides?.dbPath ?? envDbPath ?? fileInput.dbPath ?? path.join(dataDir, "synapse.db"),
  );

  const envLogLevel = readEnvValue("SYNAPSE_LOG_LEVEL", processEnv, localEnv);
  const envShell = readEnvValue("SYNAPSE_SHELL", processEnv, localEnv);

  const mergedCandidate = {
    workspaceDir,
    dataDir,
    dbPath,
    logging: {
      ...fileInput.logging,
      ...(envLogLevel ? { level: envLogLevel } : {}),
      ...options.overrides?.logging,
    },
    shell: {
      ...fileInput.shell,
      ...(envShell ? { preferred: envShell } : {}),
      ...options.overrides?.shell,
    },
    security: {
      ...fileInput.security,
      ...options.overrides?.security,
    },
  };

  const validated = SynapseConfigSchema.safeParse(mergedCandidate);
  if (!validated.success) {
    throw new ConfigError("Invalid SYNAPSE configuration", {
      details: { issues: validated.error.issues },
    });
  }

  return {
    config: validated.data,
    configFilePath,
    loadedEnvKeys: Object.keys(localEnv),
  };
}
