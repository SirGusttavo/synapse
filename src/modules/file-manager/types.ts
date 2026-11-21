import { z } from "zod";

export const FileListInputSchema = z
  .object({
    path: z.string().min(1).default("."),
    recursive: z.boolean().default(false),
    maxDepth: z.number().int().min(1).max(10).default(2),
    maxEntries: z.number().int().min(1).max(500).default(200),
  })
  .strict();

export const FileReadInputSchema = z
  .object({
    path: z.string().min(1, "File path is required"),
    startLine: z.number().int().min(1).optional(),
    endLine: z.number().int().min(1).optional(),
    maxBytes: z.number().int().min(256).max(1_048_576).default(262_144),
  })
  .strict();

export const FileCreateInputSchema = z
  .object({
    path: z.string().min(1, "File path is required"),
    content: z.string(),
    overwrite: z.boolean().default(false),
  })
  .strict();

export const FileEditInputSchema = z
  .object({
    path: z.string().min(1, "File path is required"),
    search: z.string().min(1, "Search text cannot be empty"),
    replace: z.string(),
    replaceAll: z.boolean().default(false),
  })
  .strict();

export const FileSearchInputSchema = z
  .object({
    query: z.string().min(1, "Search query cannot be empty"),
    path: z.string().min(1).default("."),
    regex: z.boolean().default(false),
    caseSensitive: z.boolean().default(false),
    maxResults: z.number().int().min(1).max(200).default(50),
  })
  .strict();

export const FileMoveInputSchema = z
  .object({
    from: z.string().min(1, "Source path is required"),
    to: z.string().min(1, "Destination path is required"),
    overwrite: z.boolean().default(false),
  })
  .strict();

export const FileDeleteInputSchema = z
  .object({
    path: z.string().min(1, "Target path is required"),
    recursive: z.boolean().default(false),
  })
  .strict();

export type FileListInput = z.infer<typeof FileListInputSchema>;
export type FileReadInput = z.infer<typeof FileReadInputSchema>;
export type FileCreateInput = z.infer<typeof FileCreateInputSchema>;
export type FileEditInput = z.infer<typeof FileEditInputSchema>;
export type FileSearchInput = z.infer<typeof FileSearchInputSchema>;
export type FileMoveInput = z.infer<typeof FileMoveInputSchema>;
export type FileDeleteInput = z.infer<typeof FileDeleteInputSchema>;

export interface FileEntryInfo {
  path: string;
  name: string;
  type: "file" | "directory" | "other";
  sizeBytes?: number;
}

export interface SearchMatch {
  path: string;
  line: number;
  column: number;
  preview: string;
}
