const DEFAULT_BLOCKED_ENV_PATTERNS: readonly RegExp[] = [
  /API[_-]?KEY/i,
  /SECRET/i,
  /TOKEN/i,
  /PASSWORD/i,
  /PASSWD/i,
  /CREDENTIAL/i,
  /PRIVATE[_-]?KEY/i,
  /ACCESS[_-]?KEY/i,
  /AUTH/i,
  /COOKIE/i,
  /^ANTHROPIC_/i,
  /^OPENAI_/i,
  /^GEMINI_/i,
  /^GOOGLE_API_/i,
  /^GITHUB_/i,
  /^GH_/i,
  /^AWS_/i,
  /^AZURE_/i,
  /^GCP_/i,
  /^NPM_TOKEN$/i,
  /^SYNAPSE_.*(KEY|SECRET|TOKEN)/i,
];

function compileExtraPatterns(extraPatterns: readonly string[]): RegExp[] {
  const compiled: RegExp[] = [];
  for (const raw of extraPatterns) {
    const escaped = raw.replace(/[.+?^${}()|[\]\\]/g, "\\$&").replace(/\*/g, ".*");
    compiled.push(new RegExp(`^${escaped}$`, "i"));
  }
  return compiled;
}

export function isBlockedEnvKey(key: string, extraPatterns: readonly string[] = []): boolean {
  for (const pattern of DEFAULT_BLOCKED_ENV_PATTERNS) {
    if (pattern.test(key)) {
      return true;
    }
  }

  for (const extra of compileExtraPatterns(extraPatterns)) {
    if (extra.test(key)) {
      return true;
    }
  }

  return false;
}

/**
 * Produces a sanitized copy of environment variables for child processes,
 * stripping secrets, provider API keys, and tokens by default (D-03).
 */
export function sanitizeEnvironment(
  sourceEnv: NodeJS.ProcessEnv = process.env,
  extraBlockedPatterns: readonly string[] = [],
): NodeJS.ProcessEnv {
  const sanitized: NodeJS.ProcessEnv = {};

  for (const [key, value] of Object.entries(sourceEnv)) {
    if (value === undefined) {
      continue;
    }
    if (isBlockedEnvKey(key, extraBlockedPatterns)) {
      continue;
    }
    sanitized[key] = value;
  }

  // Prevent git or external tools from blocking indefinitely waiting on interactive auth prompts
  sanitized.GIT_TERMINAL_PROMPT = "0";

  return sanitized;
}
