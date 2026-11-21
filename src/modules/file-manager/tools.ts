import type { ToolDefinition } from "../../core/types.js";
import type { FileManager } from "./manager.js";
import {
  FileCreateInputSchema,
  FileDeleteInputSchema,
  FileEditInputSchema,
  FileListInputSchema,
  FileMoveInputSchema,
  FileReadInputSchema,
  FileSearchInputSchema,
} from "./types.js";

export function createFileTools(fileManager: FileManager): ToolDefinition[] {
  return [
    {
      name: "file.list",
      description: "Lists files and directories within the authorized workspace",
      category: "file",
      defaultPermission: "AUTO",
      inputSchema: FileListInputSchema,
      execute: (input, context) =>
        fileManager.listDirectory(FileListInputSchema.parse(input), context),
    },
    {
      name: "file.read",
      description: "Reads a UTF-8 text file within the authorized workspace",
      category: "file",
      defaultPermission: "AUTO",
      inputSchema: FileReadInputSchema,
      execute: (input, context) => fileManager.readFile(FileReadInputSchema.parse(input), context),
    },
    {
      name: "file.create",
      description: "Creates a UTF-8 file atomically within the authorized workspace",
      category: "file",
      defaultPermission: "AUTO",
      inputSchema: FileCreateInputSchema,
      execute: (input, context) =>
        fileManager.createFile(FileCreateInputSchema.parse(input), context),
    },
    {
      name: "file.edit",
      description: "Edits an existing UTF-8 file atomically by exact search/replace",
      category: "file",
      defaultPermission: "AUTO",
      inputSchema: FileEditInputSchema,
      execute: (input, context) => fileManager.editFile(FileEditInputSchema.parse(input), context),
    },
    {
      name: "file.search",
      description: "Searches text content across files within the authorized workspace",
      category: "file",
      defaultPermission: "AUTO",
      inputSchema: FileSearchInputSchema,
      execute: (input, context) =>
        fileManager.searchContent(FileSearchInputSchema.parse(input), context),
    },
    {
      name: "file.move",
      description: "Moves or renames a file within the authorized workspace",
      category: "file",
      defaultPermission: "CONDITIONAL",
      inputSchema: FileMoveInputSchema,
      execute: (input, context) => fileManager.moveFile(FileMoveInputSchema.parse(input), context),
    },
    {
      name: "file.delete",
      description: "Deletes a file or directory with explicit human approval (D-06)",
      category: "file",
      defaultPermission: "HUMAN_APPROVAL",
      inputSchema: FileDeleteInputSchema,
      execute: (input, context) =>
        fileManager.deleteFile(FileDeleteInputSchema.parse(input), context),
    },
  ];
}
