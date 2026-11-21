import fs from "node:fs";
import path from "node:path";

/**
 * Parses a .env file into a plain key-value record without mutating process.env.
 * Keeping local secrets isolated prevents accidental inheritance by child processes (D-03).
 */
export function parseDotEnv(content: string): Record<string, string> {
  const result: Record<string, string> = {};
  const lines = content.split(/\r?\n/);

  for (const rawLine of lines) {
    const line = rawLine.trim();
    if (line.length === 0 || line.startsWith("#")) {
      continue;
    }

    const normalized = line.startsWith("export ") ? line.slice("export ".length).trim() : line;
    const eqIndex = normalized.indexOf("=");
    if (eqIndex <= 0) {
      continue;
    }

    const key = normalized.slice(0, eqIndex).trim();
    if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(key)) {
      continue;
    }

    let value = normalized.slice(eqIndex + 1).trim();
    if (
      (value.startsWith('"') && value.endsWith('"') && value.length >= 2) ||
      (value.startsWith("'") && value.endsWith("'") && value.length >= 2)
    ) {
      const quote = value[0];
      value = value.slice(1, -1);
      if (quote === '"') {
        value = value
          .replace(/\\n/g, "\n")
          .replace(/\\r/g, "\r")
          .replace(/\\t/g, "\t")
          .replace(/\\"/g, '"')
          .replace(/\\\\/g, "\\");
      }
    } else {
      const commentIdx = value.indexOf(" #");
      if (commentIdx >= 0) {
        value = value.slice(0, commentIdx).trim();
      }
    }

    result[key] = value;
  }

  return result;
}

export function loadLocalEnvFile(workspaceDir: string): Record<string, string> {
  const envPath = path.resolve(workspaceDir, ".env");
  if (!fs.existsSync(envPath)) {
    return {};
  }

  const stat = fs.statSync(envPath);
  if (!stat.isFile()) {
    return {};
  }

  const content = fs.readFileSync(envPath, "utf8");
  return parseDotEnv(content);
}
