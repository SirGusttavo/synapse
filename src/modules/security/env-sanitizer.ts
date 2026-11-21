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

const SENSITIVE_VALUE_PATTERNS: readonly RegExp[] = [
  /\bsk-ant-[A-Za-z0-9_-]{10,}/,
  /\bsk-[A-Za-z0-9_-]{16,}/,
  /\bghp_[A-Za-z0-9]{20,}/,
  /\bgithub_pat_[A-Za-z0-9_]{20,}/,
  /\bAIza[0-9A-Za-z_-]{20,}/,
  /\bAKIA[0-9A-Z]{16}\b/,
  /\bBearer\s+[A-Za-z0-9._~+/=-]{6,}/i,
  /[a-zA-Z][a-zA-Z0-9+.-]*:\/\/[^:\s/@]+:[^@\s/]+@/,
];

function compileExtraPatterns(extraPatterns: readonly string[]): RegExp[] {
  const compiled: RegExp[] = [];
  for (const raw of extraPatterns) {
    const escaped = raw.replace(/[.+?^${}()|[\]\\]/g, "\\$&").replace(/\*/g, ".*");
    compiled.push(new RegExp(`^${escaped}$`, "i"));
  }
  return compiled;
}

function hasSensitiveValue(value: string): boolean {
  for (const pattern of SENSITIVE_VALUE_PATTERNS) {
    if (pattern.test(value)) {
      return true;
    }
  }
  return false;
}

function matchesAnyPattern(key: string, patterns: readonly RegExp[]): boolean {
  for (const pattern of patterns) {
    if (pattern.test(key)) {
      return true;
    }
  }
  return false;
}

export function isBlockedEnvKey(key: string, extraPatterns: readonly string[] = []): boolean {
  if (matchesAnyPattern(key, DEFAULT_BLOCKED_ENV_PATTERNS)) {
    return true;
  }
  return matchesAnyPattern(key, compileExtraPatterns(extraPatterns));
}

/**
 * Produces a sanitized copy of environment variables for child processes,
 * stripping secrets by key pattern AND by embedded secret value patterns (D-03).
 */
export function sanitizeEnvironment(
  sourceEnv: NodeJS.ProcessEnv = process.env,
  extraBlockedPatterns: readonly string[] = [],
): NodeJS.ProcessEnv {
  const sanitized: NodeJS.ProcessEnv = {};
  const compiledExtra = compileExtraPatterns(extraBlockedPatterns);

  for (const [key, value] of Object.entries(sourceEnv)) {
    if (value === undefined) {
      continue;
    }
    if (
      matchesAnyPattern(key, DEFAULT_BLOCKED_ENV_PATTERNS) ||
      matchesAnyPattern(key, compiledExtra) ||
      hasSensitiveValue(value)
    ) {
      continue;
    }
    sanitized[key] = value;
  }

  // Prevent git or external tools from blocking indefinitely waiting on interactive auth prompts
  sanitized.GIT_TERMINAL_PROMPT = "0";

  return sanitized;
}
