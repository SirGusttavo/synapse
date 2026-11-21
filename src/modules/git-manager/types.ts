import { z } from "zod";

export const GitStatusInputSchema = z.object({}).strict();

export const GitDiffInputSchema = z
  .object({
    staged: z.boolean().default(false),
    target: z.string().min(1).optional(),
    paths: z.array(z.string().min(1)).max(100).optional(),
  })
  .strict();

export const GitLogInputSchema = z
  .object({
    limit: z.number().int().min(1).max(100).default(10),
    ref: z.string().min(1).optional(),
  })
  .strict();

export const GitBranchInputSchema = z
  .object({
    action: z.enum(["list", "create", "delete"]).default("list"),
    name: z.string().min(1).optional(),
    startPoint: z.string().min(1).optional(),
  })
  .strict();

export const GitTagInputSchema = z
  .object({
    action: z.enum(["list", "create", "delete"]).default("list"),
    name: z.string().min(1).optional(),
    message: z.string().min(1).optional(),
    target: z.string().min(1).optional(),
  })
  .strict();

export const GitInitInputSchema = z
  .object({
    initialBranch: z.string().min(1).default("main"),
  })
  .strict();

export const GitCloneInputSchema = z
  .object({
    url: z.string().min(1, "Repository URL is required"),
    directory: z.string().min(1, "Target directory is required"),
    branch: z.string().min(1).optional(),
    depth: z.number().int().min(1).max(1000).optional(),
  })
  .strict();

export const GitCheckoutInputSchema = z
  .object({
    target: z.string().min(1, "Target branch or ref is required"),
    createBranch: z.boolean().default(false),
  })
  .strict();

export const GitAddInputSchema = z
  .object({
    paths: z.array(z.string().min(1)).min(1, "At least one path is required").max(200),
  })
  .strict();

export const GitCommitInputSchema = z
  .object({
    message: z.string().min(1, "Commit message cannot be empty").max(4000),
  })
  .strict();

export const GitPullInputSchema = z
  .object({
    remote: z.string().min(1).default("origin"),
    branch: z.string().min(1).optional(),
    ffOnly: z.boolean().default(true),
  })
  .strict();

export const GitPushInputSchema = z
  .object({
    remote: z.string().min(1).default("origin"),
    branch: z.string().min(1).optional(),
    setUpstream: z.boolean().default(false),
  })
  .strict();

export const GitMergeInputSchema = z
  .object({
    branch: z.string().min(1, "Branch to merge is required"),
    noFf: z.boolean().default(false),
    ffOnly: z.boolean().default(false),
    message: z.string().min(1).max(2000).optional(),
  })
  .strict();

export type GitStatusInput = z.infer<typeof GitStatusInputSchema>;
export type GitDiffInput = z.infer<typeof GitDiffInputSchema>;
export type GitLogInput = z.infer<typeof GitLogInputSchema>;
export type GitBranchInput = z.infer<typeof GitBranchInputSchema>;
export type GitTagInput = z.infer<typeof GitTagInputSchema>;
export type GitInitInput = z.infer<typeof GitInitInputSchema>;
export type GitCloneInput = z.infer<typeof GitCloneInputSchema>;
export type GitCheckoutInput = z.infer<typeof GitCheckoutInputSchema>;
export type GitAddInput = z.infer<typeof GitAddInputSchema>;
export type GitCommitInput = z.infer<typeof GitCommitInputSchema>;
export type GitPullInput = z.infer<typeof GitPullInputSchema>;
export type GitPushInput = z.infer<typeof GitPushInputSchema>;
export type GitMergeInput = z.infer<typeof GitMergeInputSchema>;
