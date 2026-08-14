import { execFile } from "node:child_process";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);

export const GIT_STATUS_ADDED = "A";
export const GIT_STATUS_COPIED = "C";
export const GIT_STATUS_DELETED = "D";
export const GIT_STATUS_MODIFIED = "M";
export const GIT_STATUS_RENAMED = "R";
export const GIT_STATUS_TYPE_CHANGED = "T";

export type GitChangeStatus =
  | typeof GIT_STATUS_ADDED
  | typeof GIT_STATUS_COPIED
  | typeof GIT_STATUS_DELETED
  | typeof GIT_STATUS_MODIFIED
  | typeof GIT_STATUS_RENAMED
  | typeof GIT_STATUS_TYPE_CHANGED;

export interface GitChangedFile {
  /** Repository-relative POSIX path. */
  path: string;
  status: GitChangeStatus;
  /** For renames/copies: the previous path. */
  previousPath?: string;
}

async function git(
  repository: string,
  ...arguments_: string[]
): Promise<string> {
  const { stdout } = await execFileAsync(
    "git",
    ["-C", repository, ...arguments_],
    { maxBuffer: 64 * 1024 * 1024 },
  );
  return stdout;
}

export async function resolveGitRoot(repository: string): Promise<string> {
  return (await git(repository, "rev-parse", "--show-toplevel")).trim();
}

export async function resolveRevision(
  repository: string,
  revision: string,
): Promise<string> {
  return (await git(repository, "rev-parse", "--verify", `${revision}^{commit}`))
    .trim();
}

export async function remoteUrl(
  repository: string,
): Promise<string | undefined> {
  try {
    const url = (await git(repository, "remote", "get-url", "origin")).trim();
    return url.length === 0 ? undefined : url;
  } catch {
    return undefined;
  }
}

export interface DiffSpec {
  base: string;
  head: string;
  /** true = staged + unstaged changes against base, false = committed refs. */
  workingTree: boolean;
}

/**
 * Lists every changed file between the two refs (or between base and the
 * working tree). Deleted files are kept: the methodology requires reviewing
 * deletions at the baseline revision.
 */
export async function listChangedFiles(
  repository: string,
  spec: DiffSpec,
): Promise<GitChangedFile[]> {
  const range =
    spec.workingTree || spec.head === "WORKING_TREE"
      ? [spec.base]
      : [`${spec.base}...${spec.head}`];
  const output = await git(
    repository,
    "diff",
    "--name-status",
    "-z",
    "--diff-filter=ACMRDT",
    ...range,
  );
  return parseNameStatus(output);
}

export function parseNameStatus(output: string): GitChangedFile[] {
  const tokens = output.split("\0").filter((token) => token.length > 0);
  const files: GitChangedFile[] = [];
  let index = 0;
  while (index < tokens.length) {
    const status = tokens[index]!;
    const match = /^([ACDMRT])\d*$/u.exec(status);
    if (match === null) {
      throw new Error(`Unexpected git diff name-status token: ${status}`);
    }
    const letter = match[1]! as GitChangeStatus;
    if (letter === GIT_STATUS_RENAMED || letter === GIT_STATUS_COPIED) {
      const previousPath = tokens[index + 1];
      const path = tokens[index + 2];
      if (previousPath === undefined || path === undefined) {
        throw new Error(`Truncated git diff rename record: ${status}`);
      }
      files.push({ path, status: letter, previousPath });
      index += 3;
    } else {
      const path = tokens[index + 1];
      if (path === undefined) {
        throw new Error(`Truncated git diff record: ${status}`);
      }
      files.push({ path, status: letter });
      index += 2;
    }
  }
  return files;
}

export interface DiffHunk {
  path: string;
  startLine: number;
  endLine: number;
}

/** Extracts the changed line ranges per file from the unified diff. */
export async function diffHunks(
  repository: string,
  spec: DiffSpec,
): Promise<Map<string, DiffHunk[]>> {
  const range =
    spec.workingTree || spec.head === "WORKING_TREE"
      ? [spec.base]
      : [`${spec.base}...${spec.head}`];
  const output = await git(repository, "diff", "--unified=0", ...range);
  return parseUnifiedDiffHunks(output);
}

export function parseUnifiedDiffHunks(
  output: string,
): Map<string, DiffHunk[]> {
  const hunks = new Map<string, DiffHunk[]>();
  let path: string | null = null;
  for (const line of output.split("\n")) {
    const diffIndex = line.indexOf("+++ b/");
    if (diffIndex === 0) {
      path = line.slice(6);
      if (!hunks.has(path)) hunks.set(path, []);
      continue;
    }
    const hunk = /^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@/u.exec(line);
    if (hunk === null || path === null) continue;
    const start = Number(hunk[1]!);
    const count = hunk[2] === undefined ? 1 : Number(hunk[2]);
    hunks.get(path)!.push({ path, startLine: start, endLine: start + count - 1 });
  }
  return hunks;
}

/** Stable target identity for the exact diff under review. */
export async function diffTargetId(spec: DiffSpec, baseSha: string): Promise<string> {
  const { createHash } = await import("node:crypto");
  const canonical = spec.workingTree
    ? `working-tree:${baseSha}`
    : `diff:${baseSha}:${spec.head}`;
  return createHash("sha256").update(canonical).digest("hex").slice(0, 24);
}
