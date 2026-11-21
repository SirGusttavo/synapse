import { ConfigError } from "../core/errors.js";

/**
 * Strips // and /* *\/ comments and trailing commas from JSONC text
 * while preserving string literals and escape sequences intact.
 */
export function stripJsonComments(input: string): string {
  const withoutComments: string[] = [];
  let inString = false;
  let inLineComment = false;
  let inBlockComment = false;
  let i = 0;

  while (i < input.length) {
    const ch = input[i] ?? "";
    const next = input[i + 1] ?? "";

    if (inLineComment) {
      if (ch === "\n") {
        inLineComment = false;
        withoutComments.push(ch);
      }
      i += 1;
      continue;
    }

    if (inBlockComment) {
      if (ch === "*" && next === "/") {
        inBlockComment = false;
        i += 2;
      } else {
        if (ch === "\n") {
          withoutComments.push("\n");
        }
        i += 1;
      }
      continue;
    }

    if (inString) {
      withoutComments.push(ch);
      if (ch === "\\") {
        if (i + 1 < input.length) {
          withoutComments.push(next);
          i += 2;
          continue;
        }
      } else if (ch === '"') {
        inString = false;
      }
      i += 1;
      continue;
    }

    if (ch === '"') {
      inString = true;
      withoutComments.push(ch);
      i += 1;
      continue;
    }

    if (ch === "/" && next === "/") {
      inLineComment = true;
      i += 2;
      continue;
    }

    if (ch === "/" && next === "*") {
      inBlockComment = true;
      i += 2;
      continue;
    }

    withoutComments.push(ch);
    i += 1;
  }

  return stripTrailingCommas(withoutComments.join(""));
}

function stripTrailingCommas(input: string): string {
  const out: string[] = [];
  let inString = false;

  for (let i = 0; i < input.length; i += 1) {
    const ch = input[i] ?? "";

    if (inString) {
      out.push(ch);
      if (ch === "\\" && i + 1 < input.length) {
        out.push(input[i + 1] ?? "");
        i += 1;
      } else if (ch === '"') {
        inString = false;
      }
      continue;
    }

    if (ch === '"') {
      inString = true;
      out.push(ch);
      continue;
    }

    if (ch === ",") {
      let j = i + 1;
      while (j < input.length && /\s/.test(input[j] ?? "")) {
        j += 1;
      }
      const lookahead = input[j];
      if (lookahead === "}" || lookahead === "]") {
        continue;
      }
    }

    out.push(ch);
  }

  return out.join("");
}

export function parseJsonc(raw: string, sourceLabel = "config"): unknown {
  const cleaned = stripJsonComments(raw);
  try {
    return JSON.parse(cleaned) as unknown;
  } catch (error) {
    throw new ConfigError(`Failed to parse JSON/JSONC from ${sourceLabel}`, {
      details: { source: sourceLabel },
      cause: error,
    });
  }
}
