import fs from "node:fs";
import path from "node:path";
import { PolicyDeniedError } from "../../core/errors.js";

const SENSITIVE_BASENAME_PATTERNS: readonly RegExp[] = [
  /^\.env$/i,
  /^\.env\.(?!example$|sample$|template$).+/i,
  /\.pem$/i,
  /\.key$/i,
  /\.p12$/i,
  /\.pfx$/i,
  /^id_(rsa|ed25519|ecdsa|dsa)(\.pub)?$/i,
  /^\.npmrc$/i,
  /^\.netrc$/i,
];

const SENSITIVE_PATH_SEGMENTS = new Set([".ssh", ".gnupg", ".aws", ".azure"]);

function normalizeForComparison(filePath: string): string {
  const resolved = path.resolve(filePath);
  return process.platform === "win32" ? resolved.toLowerCase() : resolved;
}

function resolveCanonicalPath(targetPath: string): string {
  const resolved = path.resolve(targetPath);

  if (fs.existsSync(resolved)) {
    return fs.realpathSync(resolved);
  }

  // Walk up until an existing ancestor is found to defeat symlink escape on not-yet-created files
  const pendingSegments: string[] = [];
  let current = resolved;

  while (!fs.existsSync(current)) {
    const parent = path.dirname(current);
    if (parent === current) {
      return resolved;
    }
    pendingSegments.unshift(path.basename(current));
    current = parent;
  }

  const realAncestor = fs.realpathSync(current);
  return path.join(realAncestor, ...pendingSegments);
}

export function isSensitiveFilePath(targetPath: string): boolean {
  const normalized = path.resolve(targetPath);
  const base = path.basename(normalized);

  for (const pattern of SENSITIVE_BASENAME_PATTERNS) {
    if (pattern.test(base)) {
      return true;
    }
  }

  const segments = normalized.split(path.sep).map((s) => s.toLowerCase());
  return segments.some((segment) => SENSITIVE_PATH_SEGMENTS.has(segment));
}

export function isPathWithinWorkspace(workspaceDir: string, targetPath: string): boolean {
  if (targetPath.startsWith("\\\\")) {
    return false;
  }

  const canonicalWorkspace = normalizeForComparison(resolveCanonicalPath(workspaceDir));
  const canonicalTarget = normalizeForComparison(
    resolveCanonicalPath(path.resolve(workspaceDir, targetPath)),
  );

  if (canonicalTarget === canonicalWorkspace) {
    return true;
  }

  const prefix = canonicalWorkspace.endsWith(path.sep)
    ? canonicalWorkspace
    : `${canonicalWorkspace}${path.sep}`;

  return canonicalTarget.startsWith(prefix);
}

export function assertWorkingDirectoryAllowed(
  workspaceDir: string,
  candidateDir: string,
  allowOutsideWorkspace: boolean,
): string {
  if (candidateDir.startsWith("\\\\")) {
    throw new PolicyDeniedError("UNC network paths are blocked by workspace policy", {
      details: { candidateDir },
    });
  }

  const resolved = path.resolve(workspaceDir, candidateDir);
  const inside = isPathWithinWorkspace(workspaceDir, resolved);

  if (!inside && !allowOutsideWorkspace) {
    throw new PolicyDeniedError(`Working directory escapes authorized workspace: ${resolved}`, {
      details: { workspaceDir: path.resolve(workspaceDir), candidateDir: resolved },
    });
  }

  return resolveCanonicalPath(resolved);
}
