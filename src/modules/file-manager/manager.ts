import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { ExecutionError, PolicyDeniedError } from "../../core/errors.js";
import type { ExecutionResult, ToolExecutionContext } from "../../core/types.js";
import {
  inspectWorkspacePath,
  isHardlinkedFile,
  isInternalGitPath,
  isPathWithinWorkspace,
  isSensitiveFilePath,
} from "../security/workspace-guard.js";
import type {
  FileCreateInput,
  FileDeleteInput,
  FileEditInput,
  FileEntryInfo,
  FileListInput,
  FileMoveInput,
  FileReadInput,
  FileSearchInput,
  SearchMatch,
} from "./types.js";

const DEFAULT_SKIP_DIRS = new Set([".git", "node_modules"]);
const BINARY_SAMPLE_BYTES = 8_192;
const MAX_SEARCH_FILE_BYTES = 512_000;

export interface FileManagerOptions {
  workspaceDir: string;
  allowOutsideWorkspace?: boolean;
}

function isBinaryBuffer(buf: Buffer): boolean {
  const sampleLen = Math.min(buf.length, BINARY_SAMPLE_BYTES);
  for (let i = 0; i < sampleLen; i += 1) {
    if (buf[i] === 0) {
      return true;
    }
  }
  return false;
}

function writeFileAtomic(targetPath: string, content: string): void {
  const dir = path.dirname(targetPath);
  fs.mkdirSync(dir, { recursive: true });

  const tmpName = `.${path.basename(targetPath)}.synapse-tmp-${crypto.randomBytes(6).toString("hex")}`;
  const tmpPath = path.join(dir, tmpName);

  try {
    fs.writeFileSync(tmpPath, content, { encoding: "utf8", flag: "wx" });
    fs.renameSync(tmpPath, targetPath);
  } catch (error) {
    try {
      if (fs.existsSync(tmpPath)) {
        fs.unlinkSync(tmpPath);
      }
    } catch {
      // Best-effort cleanup
    }
    throw error;
  }
}

function failResult(startedAt: number, message: string): ExecutionResult {
  return {
    status: "failed",
    exitCode: 1,
    stdout: "",
    stderr: message,
    stdoutTruncated: false,
    stderrTruncated: false,
    durationMs: Date.now() - startedAt,
    errorMessage: message,
  };
}

function okResult(
  startedAt: number,
  stdout: string,
  data?: Record<string, unknown>,
  stdoutTruncated = false,
): ExecutionResult {
  return {
    status: "completed",
    exitCode: 0,
    stdout,
    stderr: "",
    stdoutTruncated,
    stderrTruncated: false,
    durationMs: Date.now() - startedAt,
    data,
  };
}

export class FileManager {
  private readonly workspaceDir: string;
  private readonly allowOutsideWorkspace: boolean;

  constructor(options: FileManagerOptions) {
    this.workspaceDir = path.resolve(options.workspaceDir);
    this.allowOutsideWorkspace = options.allowOutsideWorkspace ?? false;
  }

  private resolveSafePath(
    workingDirectory: string,
    targetPath: string,
    options: { mutating: boolean; forbidWorkspaceRoot?: boolean; allowHardlinkDelete?: boolean },
  ): string {
    const info = inspectWorkspacePath(this.workspaceDir, workingDirectory, targetPath);

    if (!info.insideWorkspace && !this.allowOutsideWorkspace) {
      throw new PolicyDeniedError(`Path escapes authorized workspace: ${targetPath}`, {
        details: { targetPath },
      });
    }
    if (info.hasReparsePoint) {
      throw new PolicyDeniedError(
        `Path traverses a symbolic link or NTFS junction inside the workspace: ${targetPath}`,
        { details: { targetPath } },
      );
    }
    if (info.isHardlinked && !options.allowHardlinkDelete) {
      throw new PolicyDeniedError(
        `Access to hardlinked file (nlink > 1) is blocked to prevent credential aliasing: ${targetPath}`,
        { details: { targetPath } },
      );
    }
    if (info.isSensitive) {
      throw new PolicyDeniedError(`Access to sensitive file is blocked: ${targetPath}`, {
        details: { targetPath },
      });
    }
    if (options.mutating && info.isInternalGit) {
      throw new PolicyDeniedError(
        `Direct mutation of internal .git path is blocked: ${targetPath}`,
        {
          details: { targetPath },
        },
      );
    }
    if (options.forbidWorkspaceRoot && info.isWorkspaceRoot) {
      throw new PolicyDeniedError("Operation on workspace root directory is blocked");
    }

    return info.canonicalPath;
  }

  public async listDirectory(
    input: FileListInput,
    context: ToolExecutionContext,
  ): Promise<ExecutionResult> {
    const startedAt = Date.now();
    const targetDir = this.resolveSafePath(context.workingDirectory, input.path, {
      mutating: false,
    });

    if (!fs.existsSync(targetDir)) {
      return failResult(startedAt, `Directory not found: ${input.path}`);
    }
    if (!fs.statSync(targetDir).isDirectory()) {
      return failResult(startedAt, `Target path is not a directory: ${input.path}`);
    }

    const entries: FileEntryInfo[] = [];
    let truncated = false;

    const walk = (dirPath: string, depth: number): void => {
      if (entries.length >= input.maxEntries) {
        truncated = true;
        return;
      }

      const dirents = fs.readdirSync(dirPath, { withFileTypes: true });
      dirents.sort((a, b) => a.name.localeCompare(b.name));

      for (const dirent of dirents) {
        if (entries.length >= input.maxEntries) {
          truncated = true;
          return;
        }
        if (dirent.isSymbolicLink()) {
          continue;
        }

        const fullPath = path.join(dirPath, dirent.name);
        if (!isPathWithinWorkspace(this.workspaceDir, fullPath) && !this.allowOutsideWorkspace) {
          continue;
        }
        if (isSensitiveFilePath(fullPath) || isHardlinkedFile(fullPath)) {
          continue;
        }

        const relPath = path.relative(context.workingDirectory, fullPath) || dirent.name;
        const type: FileEntryInfo["type"] = dirent.isDirectory()
          ? "directory"
          : dirent.isFile()
            ? "file"
            : "other";

        let sizeBytes: number | undefined;
        if (type === "file") {
          try {
            sizeBytes = fs.statSync(fullPath).size;
          } catch {
            sizeBytes = undefined;
          }
        }

        entries.push({ path: relPath, name: dirent.name, type, sizeBytes });

        if (
          input.recursive &&
          type === "directory" &&
          depth < input.maxDepth &&
          !DEFAULT_SKIP_DIRS.has(dirent.name)
        ) {
          walk(fullPath, depth + 1);
        }
      }
    };

    walk(targetDir, 1);

    const formatted = entries
      .map((e) => `${e.type === "directory" ? "[DIR] " : "[FILE]"} ${e.path}`)
      .join("\n");

    return okResult(startedAt, formatted, { entries, count: entries.length, truncated }, truncated);
  }

  public async readFile(
    input: FileReadInput,
    context: ToolExecutionContext,
  ): Promise<ExecutionResult> {
    const startedAt = Date.now();
    const targetFile = this.resolveSafePath(context.workingDirectory, input.path, {
      mutating: false,
    });

    if (!fs.existsSync(targetFile)) {
      return failResult(startedAt, `File not found: ${input.path}`);
    }

    const lstat = fs.lstatSync(targetFile);
    if (lstat.isSymbolicLink() || !lstat.isFile()) {
      return failResult(startedAt, `Target path is not a regular file: ${input.path}`);
    }
    if (lstat.nlink > 1) {
      throw new PolicyDeniedError(
        `Access to hardlinked file (nlink > 1) is blocked: ${input.path}`,
        { details: { path: input.path, nlink: lstat.nlink } },
      );
    }

    const effectiveMaxBytes = Math.min(input.maxBytes, context.maxOutputBytes);
    const fd = fs.openSync(targetFile, "r");
    let buffer: Buffer;
    let fileSize: number;
    let readSize: number;
    try {
      const fstat = fs.fstatSync(fd);
      if (!fstat.isFile() || fstat.nlink > 1) {
        throw new PolicyDeniedError(
          `Opened file handle failed regular-file/hardlink check: ${input.path}`,
          { details: { path: input.path, nlink: fstat.nlink } },
        );
      }
      fileSize = fstat.size;
      readSize = Math.min(fileSize, effectiveMaxBytes);
      buffer = Buffer.alloc(readSize);
      if (readSize > 0) {
        fs.readSync(fd, buffer, 0, readSize, 0);
      }
    } finally {
      fs.closeSync(fd);
    }

    if (isBinaryBuffer(buffer)) {
      return failResult(startedAt, `Refusing to read binary file as text: ${input.path}`);
    }

    let content = buffer.toString("utf8");
    const truncated = fileSize > effectiveMaxBytes;

    if (input.startLine !== undefined || input.endLine !== undefined) {
      const lines = content.split(/\r?\n/);
      const start = Math.max(1, input.startLine ?? 1);
      const end = Math.min(lines.length, input.endLine ?? lines.length);
      if (start > end && lines.length > 0) {
        return failResult(startedAt, `Invalid line range: startLine (${start}) > endLine (${end})`);
      }
      content = lines.slice(start - 1, end).join("\n");
    }

    return okResult(
      startedAt,
      content,
      {
        path: input.path,
        sizeBytes: fileSize,
        bytesRead: readSize,
        truncated,
      },
      truncated,
    );
  }

  public async createFile(
    input: FileCreateInput,
    context: ToolExecutionContext,
  ): Promise<ExecutionResult> {
    const startedAt = Date.now();
    const targetFile = this.resolveSafePath(context.workingDirectory, input.path, {
      mutating: true,
      forbidWorkspaceRoot: true,
    });

    if (fs.existsSync(targetFile) && !input.overwrite) {
      return failResult(
        startedAt,
        `File already exists (pass overwrite: true to replace): ${input.path}`,
      );
    }

    writeFileAtomic(targetFile, input.content);

    return okResult(startedAt, `Created ${input.path}`, {
      path: input.path,
      bytesWritten: Buffer.byteLength(input.content, "utf8"),
      overwritten: input.overwrite,
    });
  }

  public async editFile(
    input: FileEditInput,
    context: ToolExecutionContext,
  ): Promise<ExecutionResult> {
    const startedAt = Date.now();
    const targetFile = this.resolveSafePath(context.workingDirectory, input.path, {
      mutating: true,
      forbidWorkspaceRoot: true,
    });

    if (!fs.existsSync(targetFile)) {
      return failResult(startedAt, `File not found: ${input.path}`);
    }

    const stat = fs.statSync(targetFile);
    if (!stat.isFile()) {
      return failResult(startedAt, `Target path is not a regular file: ${input.path}`);
    }

    const rawBuffer = fs.readFileSync(targetFile);
    if (isBinaryBuffer(rawBuffer)) {
      return failResult(startedAt, `Refusing to edit binary file: ${input.path}`);
    }

    const original = rawBuffer.toString("utf8");
    const occurrences = original.split(input.search).length - 1;

    if (occurrences === 0) {
      return failResult(startedAt, `Search pattern not found in ${input.path}`);
    }
    if (occurrences > 1 && !input.replaceAll) {
      return failResult(
        startedAt,
        `Search pattern matched ${occurrences} times in ${input.path}; specify replaceAll: true or a more specific search string`,
      );
    }

    const updated = input.replaceAll
      ? original.split(input.search).join(input.replace)
      : original.replace(input.search, () => input.replace);

    writeFileAtomic(targetFile, updated);

    const replacements = input.replaceAll ? occurrences : 1;
    return okResult(startedAt, `Edited ${input.path} (${replacements} replacement(s))`, {
      path: input.path,
      replacements,
      bytesWritten: Buffer.byteLength(updated, "utf8"),
    });
  }

  public async searchContent(
    input: FileSearchInput,
    context: ToolExecutionContext,
  ): Promise<ExecutionResult> {
    const startedAt = Date.now();
    const rootPath = this.resolveSafePath(context.workingDirectory, input.path, {
      mutating: false,
    });

    if (!fs.existsSync(rootPath)) {
      return failResult(startedAt, `Search path not found: ${input.path}`);
    }

    let matcher: RegExp;
    try {
      const source = input.regex ? input.query : input.query.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
      matcher = new RegExp(source, input.caseSensitive ? "" : "i");
    } catch (error) {
      throw new ExecutionError("Invalid regular expression in file.search", {
        details: { query: input.query },
        cause: error,
      });
    }

    const matches: SearchMatch[] = [];
    let truncated = false;

    const searchFile = (filePath: string): void => {
      if (matches.length >= input.maxResults) {
        truncated = true;
        return;
      }
      if (
        isSensitiveFilePath(filePath) ||
        isInternalGitPath(filePath) ||
        isHardlinkedFile(filePath)
      ) {
        return;
      }

      let stat: fs.Stats;
      try {
        stat = fs.statSync(filePath);
      } catch {
        return;
      }
      if (!stat.isFile() || stat.size > MAX_SEARCH_FILE_BYTES) {
        return;
      }

      const buf = fs.readFileSync(filePath);
      if (isBinaryBuffer(buf)) {
        return;
      }

      const lines = buf.toString("utf8").split(/\r?\n/);
      const relPath = path.relative(context.workingDirectory, filePath) || path.basename(filePath);

      for (let i = 0; i < lines.length; i += 1) {
        const lineText = lines[i] ?? "";
        const m = matcher.exec(lineText);
        if (m) {
          matches.push({
            path: relPath,
            line: i + 1,
            column: m.index + 1,
            preview: lineText.slice(0, 200),
          });
          if (matches.length >= input.maxResults) {
            truncated = true;
            return;
          }
        }
      }
    };

    const walk = (current: string): void => {
      if (matches.length >= input.maxResults || context.signal.aborted) {
        return;
      }
      if (!isPathWithinWorkspace(this.workspaceDir, current) && !this.allowOutsideWorkspace) {
        return;
      }

      const stat = fs.lstatSync(current);
      if (stat.isSymbolicLink()) {
        return;
      }
      if (stat.isFile()) {
        searchFile(current);
        return;
      }
      if (!stat.isDirectory()) {
        return;
      }

      const dirents = fs.readdirSync(current, { withFileTypes: true });
      dirents.sort((a, b) => a.name.localeCompare(b.name));

      for (const dirent of dirents) {
        if (matches.length >= input.maxResults) {
          truncated = true;
          return;
        }
        if (dirent.isDirectory() && DEFAULT_SKIP_DIRS.has(dirent.name)) {
          continue;
        }
        if (dirent.isSymbolicLink()) {
          continue;
        }
        walk(path.join(current, dirent.name));
      }
    };

    walk(rootPath);

    const formatted = matches
      .map((m) => `${m.path}:${m.line}:${m.column}: ${m.preview}`)
      .join("\n");
    return okResult(startedAt, formatted, { matches, count: matches.length, truncated }, truncated);
  }

  public async moveFile(
    input: FileMoveInput,
    context: ToolExecutionContext,
  ): Promise<ExecutionResult> {
    const startedAt = Date.now();
    const fromPath = this.resolveSafePath(context.workingDirectory, input.from, {
      mutating: true,
      forbidWorkspaceRoot: true,
    });
    const toPath = this.resolveSafePath(context.workingDirectory, input.to, {
      mutating: true,
      forbidWorkspaceRoot: true,
    });

    if (!fs.existsSync(fromPath)) {
      return failResult(startedAt, `Source path not found: ${input.from}`);
    }
    if (fs.existsSync(toPath) && !input.overwrite) {
      return failResult(
        startedAt,
        `Destination already exists (pass overwrite: true to replace): ${input.to}`,
      );
    }

    fs.mkdirSync(path.dirname(toPath), { recursive: true });
    if (fs.existsSync(toPath) && input.overwrite) {
      fs.rmSync(toPath, { recursive: false, force: false });
    }
    fs.renameSync(fromPath, toPath);

    return okResult(startedAt, `Moved ${input.from} -> ${input.to}`, {
      from: input.from,
      to: input.to,
    });
  }

  public async deleteFile(
    input: FileDeleteInput,
    context: ToolExecutionContext,
  ): Promise<ExecutionResult> {
    const startedAt = Date.now();
    const targetPath = this.resolveSafePath(context.workingDirectory, input.path, {
      mutating: true,
      forbidWorkspaceRoot: true,
      allowHardlinkDelete: true,
    });

    if (!fs.existsSync(targetPath)) {
      return failResult(startedAt, `Target path not found: ${input.path}`);
    }

    const stat = fs.lstatSync(targetPath);
    if (stat.isDirectory()) {
      if (!input.recursive) {
        return failResult(
          startedAt,
          `Target is a directory; pass recursive: true to delete directories: ${input.path}`,
        );
      }
      fs.rmSync(targetPath, { recursive: true, force: false });
      return okResult(startedAt, `Deleted directory ${input.path}`, {
        path: input.path,
        type: "directory",
      });
    }

    fs.unlinkSync(targetPath);
    return okResult(startedAt, `Deleted file ${input.path}`, {
      path: input.path,
      type: "file",
    });
  }
}
