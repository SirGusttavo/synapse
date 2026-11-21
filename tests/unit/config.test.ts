import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { loadConfig, parseDotEnv, parseJsonc } from "../../src/config/index.js";
import { ConfigError } from "../../src/core/errors.js";

const tempDirs: string[] = [];

function createTempWorkspace(): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "synapse-config-test-"));
  tempDirs.push(dir);
  return dir;
}

afterEach(() => {
  while (tempDirs.length > 0) {
    const dir = tempDirs.pop();
    if (dir && fs.existsSync(dir)) {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  }
});

describe("parseJsonc", () => {
  it("parses JSONC with line comments, block comments, URLs inside strings and trailing commas", () => {
    const raw = `{
      // Single line comment
      "url": "https://example.com//not-a-comment",
      /* Multi-line
         block comment */
      "items": [1, 2, 3,],
    }`;

    const parsed = parseJsonc(raw, "test.jsonc");
    expect(parsed).toEqual({
      url: "https://example.com//not-a-comment",
      items: [1, 2, 3],
    });
  });

  it("throws ConfigError on invalid JSONC", () => {
    expect(() => parseJsonc("{ invalid }", "bad.jsonc")).toThrow(ConfigError);
  });
});

describe("parseDotEnv", () => {
  it("parses standard, quoted and commented .env lines without touching process.env", () => {
    const content = `
      # Comment line
      SYNAPSE_LOG_LEVEL=debug
      API_SECRET="sk-test-123456"
      SINGLE='hello world'
      INLINE=value # inline comment
      export EXPORTED_KEY=ok
    `;

    const parsed = parseDotEnv(content);
    expect(parsed).toEqual({
      SYNAPSE_LOG_LEVEL: "debug",
      API_SECRET: "sk-test-123456",
      SINGLE: "hello world",
      INLINE: "value",
      EXPORTED_KEY: "ok",
    });
    expect(process.env.API_SECRET).toBeUndefined();
  });
});

describe("loadConfig", () => {
  it("loads defaults with D-06 singleFileDeletePermission = HUMAN_APPROVAL", () => {
    const ws = createTempWorkspace();
    const { config, configFilePath } = loadConfig({ workspaceDir: ws, processEnv: {} });

    expect(configFilePath).toBeNull();
    expect(config.workspaceDir).toBe(path.resolve(ws));
    expect(config.security.singleFileDeletePermission).toBe("HUMAN_APPROVAL");
    expect(config.security.allowOutsideWorkspace).toBe(false);
    expect(config.shell.preferred).toBe("auto");
    expect(config.logging.level).toBe("info");
  });

  it("loads .synapse/config.jsonc and applies isolated .env overrides", () => {
    const ws = createTempWorkspace();
    fs.mkdirSync(path.join(ws, ".synapse"), { recursive: true });
    fs.writeFileSync(
      path.join(ws, ".synapse", "config.jsonc"),
      `{
        // Custom shell config
        "shell": {
          "preferred": "pwsh",
          "timeoutMs": 10000,
        },
        "logging": {
          "level": "warn",
          "pretty": false,
        },
      }`,
      "utf8",
    );
    fs.writeFileSync(
      path.join(ws, ".env"),
      "SYNAPSE_LOG_LEVEL=debug\nSECRET_TOKEN=must_stay_isolated\n",
      "utf8",
    );

    const { config, configFilePath, loadedEnvKeys } = loadConfig({
      workspaceDir: ws,
      processEnv: {},
    });

    expect(configFilePath).toBe(path.join(ws, ".synapse", "config.jsonc"));
    expect(config.shell.preferred).toBe("pwsh");
    expect(config.shell.timeoutMs).toBe(10_000);
    expect(config.logging.level).toBe("debug");
    expect(loadedEnvKeys).toContain("SECRET_TOKEN");
    expect(process.env.SECRET_TOKEN).toBeUndefined();
  });

  it("rejects unknown keys via strict Zod validation", () => {
    const ws = createTempWorkspace();
    fs.mkdirSync(path.join(ws, ".synapse"), { recursive: true });
    fs.writeFileSync(
      path.join(ws, ".synapse", "config.json"),
      JSON.stringify({ unknownField: true }),
      "utf8",
    );

    expect(() => loadConfig({ workspaceDir: ws, processEnv: {} })).toThrow(ConfigError);
  });
});
