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

const SENSITIVE_CONFIG_PATTERNS: readonly RegExp[] = [
  /^\.synapse[\\/]+(?:config|policy)\.jsonc?$/i,
];

const UNC_OR_DEVICE_PREFIX = /^[/\\]{2}/;

function containsNullByte(value: string): boolean {
  return value.includes("\0");
}

function isUncOrDevicePath(rawPath: string, resolvedPath?: string): boolean {
  if (UNC_OR_DEVICE_PREFIX.test(rawPath)) {
    return true;
  }
  if (resolvedPath && UNC_OR_DEVICE_PREFIX.test(resolvedPath)) {
    return true;
  }
  return false;
}

function normalizeForComparison(filePath: string): string {
  const resolved = path.resolve(filePath);
  return process.platform === "win32" ? resolved.toLowerCase() : resolved;
}

export function resolveCanonicalPath(targetPath: string): string {
  const resolved = path.resolve(targetPath);

  if (fs.existsSync(resolved)) {
    return fs.realpathSync(resolved);
  }

  // Walk up until an existing ancestor is found to defeat symlink/junction escape on not-yet-created files
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

/**
 * Walks every existing path component from `workspaceDir` down to `targetPath`
 * using `fs.lstatSync` and detects any symbolic link or NTFS junction (`isSymbolicLink()`).
 */
export function hasReparsePointInPathChain(workspaceDir: string, targetPath: string): boolean {
  const resolvedWs = path.resolve(workspaceDir);
  const resolvedTarget = path.resolve(workspaceDir, targetPath);

  const rel = path.relative(resolvedWs, resolvedTarget);
  if (rel.startsWith("..") || path.isAbsolute(rel)) {
    try {
      return fs.existsSync(resolvedTarget) && fs.lstatSync(resolvedTarget).isSymbolicLink();
    } catch {
      return false;
    }
  }

  let current = resolvedWs;
  try {
    if (fs.existsSync(current) && fs.lstatSync(current).isSymbolicLink()) {
      return true;
    }
  } catch {
    return false;
  }

  if (rel.length === 0) {
    return false;
  }

  const parts = rel.split(path.sep).filter((p) => p.length > 0);
  for (const part of parts) {
    current = path.join(current, part);
    if (!fs.existsSync(current)) {
      break;
    }
    try {
      if (fs.lstatSync(current).isSymbolicLink()) {
        return true;
      }
    } catch {
      return true;
    }
  }

  return false;
}

/**
 * Detects whether an existing regular file has multiple hardlinks (`nlink > 1`),
 * which on NTFS can be used to alias `.env` or outside-workspace sensitive files.
 */
export function isHardlinkedFile(targetPath: string): boolean {
  try {
    const resolved = path.resolve(targetPath);
    if (!fs.existsSync(resolved)) {
      return false;
    }
    const stat = fs.lstatSync(resolved);
    return stat.isFile() && stat.nlink > 1;
  } catch {
    return false;
  }
}

function matchesSensitiveRules(filePath: string): boolean {
  const normalized = path.resolve(filePath);
  const base = path.basename(normalized);

  for (const pattern of SENSITIVE_BASENAME_PATTERNS) {
    if (pattern.test(base)) {
      return true;
    }
  }

  const segments = normalized.split(path.sep).map((s) => s.toLowerCase());
  return segments.some((segment) => SENSITIVE_PATH_SEGMENTS.has(segment));
}

export function isSensitiveFilePath(targetPath: string): boolean {
  if (containsNullByte(targetPath)) {
    return true;
  }
  if (matchesSensitiveRules(targetPath)) {
    return true;
  }
  try {
    const canonical = resolveCanonicalPath(targetPath);
    return matchesSensitiveRules(canonical);
  } catch {
    return false;
  }
}

export function isInternalGitPath(targetPath: string): boolean {
  const check = (p: string) =>
    path
      .resolve(p)
      .split(path.sep)
      .some((segment) => segment.toLowerCase() === ".git");

  if (check(targetPath)) {
    return true;
  }
  try {
    return check(resolveCanonicalPath(targetPath));
  } catch {
    return false;
  }
}

export function isSensitiveConfigPath(workspaceDir: string, targetPath: string): boolean {
  const canonicalWs = resolveCanonicalPath(workspaceDir);
  const canonicalTarget = resolveCanonicalPath(path.resolve(workspaceDir, targetPath));
  const rel = path.relative(canonicalWs, canonicalTarget);
  return SENSITIVE_CONFIG_PATTERNS.some((pattern) => pattern.test(rel));
}

export function isWorkspaceRootPath(workspaceDir: string, targetPath: string): boolean {
  const canonicalWs = normalizeForComparison(resolveCanonicalPath(workspaceDir));
  const canonicalTarget = normalizeForComparison(
    resolveCanonicalPath(path.resolve(workspaceDir, targetPath)),
  );
  return canonicalWs === canonicalTarget;
}

export function isPathWithinWorkspace(workspaceDir: string, targetPath: string): boolean {
  if (containsNullByte(workspaceDir) || containsNullByte(targetPath)) {
    return false;
  }
  const resolved = path.resolve(workspaceDir, targetPath);
  if (isUncOrDevicePath(targetPath, resolved)) {
    return false;
  }

  const canonicalWorkspace = normalizeForComparison(resolveCanonicalPath(workspaceDir));
  const canonicalTarget = normalizeForComparison(resolveCanonicalPath(resolved));

  if (canonicalTarget === canonicalWorkspace) {
    return true;
  }

  const prefix = canonicalWorkspace.endsWith(path.sep)
    ? canonicalWorkspace
    : `${canonicalWorkspace}${path.sep}`;

  return canonicalTarget.startsWith(prefix);
}

export interface WorkingDirectoryValidation {
  canonicalPath: string;
  insideWorkspace: boolean;
}

export function assertWorkingDirectoryAllowed(
  workspaceDir: string,
  candidateDir: string,
  allowOutsideWorkspace: boolean,
): WorkingDirectoryValidation {
  if (containsNullByte(candidateDir)) {
    throw new PolicyDeniedError("Working directory path contains invalid null byte", {
      details: { candidateDir },
    });
  }

  const resolved = path.resolve(workspaceDir, candidateDir);
  if (isUncOrDevicePath(candidateDir, resolved)) {
    throw new PolicyDeniedError("UNC and device paths are blocked by workspace policy", {
      details: { candidateDir, resolved },
    });
  }

  const insideWorkspace = isPathWithinWorkspace(workspaceDir, resolved);

  if (!insideWorkspace && !allowOutsideWorkspace) {
    throw new PolicyDeniedError(`Working directory escapes authorized workspace: ${resolved}`, {
      details: { workspaceDir: path.resolve(workspaceDir), candidateDir: resolved },
    });
  }

  return {
    canonicalPath: resolveCanonicalPath(resolved),
    insideWorkspace,
  };
}

export interface ResolvedWorkspacePath {
  canonicalPath: string;
  insideWorkspace: boolean;
  isSensitive: boolean;
  isInternalGit: boolean;
  isSensitiveConfig: boolean;
  isWorkspaceRoot: boolean;
  hasReparsePoint: boolean;
  isHardlinked: boolean;
}

export function inspectWorkspacePath(
  workspaceDir: string,
  baseDir: string,
  targetPath: string,
): ResolvedWorkspacePath {
  if (containsNullByte(targetPath)) {
    throw new PolicyDeniedError("Target path contains invalid null byte", {
      details: { targetPath },
    });
  }

  const resolved = path.resolve(baseDir, targetPath);
  if (isUncOrDevicePath(targetPath, resolved)) {
    throw new PolicyDeniedError("UNC and device paths are blocked by workspace policy", {
      details: { targetPath, resolved },
    });
  }

  const canonicalPath = resolveCanonicalPath(resolved);
  const insideWorkspace = isPathWithinWorkspace(workspaceDir, resolved);

  return {
    canonicalPath,
    insideWorkspace,
    isSensitive: isSensitiveFilePath(resolved),
    isInternalGit: isInternalGitPath(resolved),
    isSensitiveConfig: isSensitiveConfigPath(workspaceDir, resolved),
    isWorkspaceRoot: isWorkspaceRootPath(workspaceDir, resolved),
    hasReparsePoint: hasReparsePointInPathChain(workspaceDir, resolved),
    isHardlinked: isHardlinkedFile(resolved),
  };
}
