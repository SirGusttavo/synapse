const REDACTED = "[REDACTED]";

const SENSITIVE_KEY_PATTERN =
  /(password|passwd|secret|token|api[_-]?key|authorization|cookie|credential|private[_-]?key|access[_-]?key|refresh[_-]?token)/i;

const SECRET_TEXT_PATTERNS: readonly RegExp[] = [
  /\bBearer\s+[A-Za-z0-9._~+/=-]{8,}\b/gi,
  /\bsk-ant-[A-Za-z0-9_-]{10,}\b/g,
  /\bsk-[A-Za-z0-9_-]{16,}\b/g,
  /\bghp_[A-Za-z0-9]{20,}\b/g,
  /\bgithub_pat_[A-Za-z0-9_]{20,}\b/g,
  /\bAIza[0-9A-Za-z_-]{20,}\b/g,
  /\bAKIA[0-9A-Z]{16}\b/g,
  /([a-zA-Z][a-zA-Z0-9+.-]*:\/\/[^:\s/@]+:)([^@\s/]+)(@)/g,
  /\b((?:password|passwd|secret|token|api[_-]?key)\s*[:=]\s*["']?)([^\s"';,&]+)(["']?)/gi,
];

export function redactText(text: string): string {
  let output = text;

  for (const pattern of SECRET_TEXT_PATTERNS) {
    output = output.replace(pattern, (...args: unknown[]) => {
      // Patterns with 3 capture groups preserve prefix/suffix (e.g. URL credentials or key=value)
      if (args.length >= 6 && typeof args[1] === "string" && typeof args[3] === "string") {
        return `${args[1]}${REDACTED}${args[3]}`;
      }
      return REDACTED;
    });
  }

  return output;
}

export function isSensitiveKey(key: string): boolean {
  return SENSITIVE_KEY_PATTERN.test(key);
}

export function redactValue(value: unknown, seen = new WeakSet<object>()): unknown {
  if (typeof value === "string") {
    return redactText(value);
  }
  if (value === null || typeof value !== "object") {
    return value;
  }
  if (seen.has(value)) {
    return "[CIRCULAR]";
  }
  seen.add(value);

  if (Array.isArray(value)) {
    return value.map((item) => redactValue(item, seen));
  }

  const record = value as Record<string, unknown>;
  const sanitized: Record<string, unknown> = {};

  for (const [key, nested] of Object.entries(record)) {
    if (isSensitiveKey(key)) {
      sanitized[key] = REDACTED;
    } else {
      sanitized[key] = redactValue(nested, seen);
    }
  }

  return sanitized;
}
