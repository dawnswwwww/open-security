import { execFile } from "node:child_process";
import { readdir, readFile, realpath } from "node:fs/promises";
import { isAbsolute, join, posix, resolve, sep } from "node:path";
import { promisify } from "node:util";
import { Type, type TSchema } from "@mariozechner/pi-ai";
import type { ToolDefinition } from "@mariozechner/pi-coding-agent";

/**
 * Infers execute params from the TypeBox schema; `ToolDefinition<any>` alone
 * collapses params to unknown because Static<any> resolves to unknown.
 */
function defineTool<TParams extends TSchema>(
  definition: ToolDefinition<TParams>,
): ToolDefinition<TParams> {
  return definition;
}

type AnyToolDefinition = ToolDefinition<any>;

/**
 * Read-only inspection tools shared by agent runtimes that execute tools
 * in-process (unlike the Claude Agent SDK, whose Read/Grep/Glob live in the
 * harness). Every tool is confined to the repository root and can only
 * inspect: the read-only policy holds by construction because no mutating
 * tool exists.
 */

export const MAX_READ_LINES = 2_000;
const MAX_READ_BYTES = 256 * 1024;
const MAX_GLOB_RESULTS = 200;
const WALK_ENTRY_CAP = 20_000;
const WALK_DEPTH = 16;
const DEFAULT_SEARCH_RESULTS = 50;
const MAX_SEARCH_RESULTS = 200;
const MAX_SEARCH_BYTES = 256 * 1024;
const MAX_GIT_BYTES = 256 * 1024;

/**
 * Lexically resolves `path` against `cwd` and returns the absolute path, or
 * null when the result would escape the repository root.
 */
export function resolveWithin(cwd: string, path: string): string | null {
  const absolute = isAbsolute(path) ? path : resolve(cwd, path);
  const root = resolve(cwd);
  if (absolute === root) return root;
  if (!absolute.startsWith(root + sep)) return null;
  return absolute;
}

/** Formats file content as line-numbered text, mirroring agent Read tools. */
export function formatNumberedLines(
  content: string,
  offset: number,
  limit: number,
): string {
  const lines = content.split("\n");
  const start = Math.min(offset, lines.length + 1);
  const end = Math.min(start + limit - 1, lines.length);
  const width = String(end).length;
  const numbered: string[] = [];
  for (let index = start; index <= end; index += 1) {
    numbered.push(`${String(index).padStart(width)}\t${lines[index - 1] ?? ""}`);
  }
  const notes: string[] = [];
  if (start > 1) notes.push(`(starting at line ${start})`);
  if (end < lines.length) notes.push(`(truncated at line ${end} of ${lines.length})`);
  return numbered.join("\n") + (notes.length === 0 ? "" : `\n${notes.join(" ")}`);
}

/**
 * Converts a glob pattern (`*`, `**`, `?`, `{a,b}`) into a RegExp matched
 * against `/`-separated paths relative to the repository root.
 */
export function globToRegExp(pattern: string): RegExp {
  let source = "";
  let index = 0;
  while (index < pattern.length) {
    const character = pattern[index]!;
    if (character === "*") {
      if (pattern[index + 1] === "*") {
        // `**/` also matches zero directories: `a/**/b` hits `a/b`.
        if (pattern[index + 2] === "/") {
          source += "(?:.*/)?";
          index += 3;
        } else {
          source += ".*";
          index += 2;
        }
      } else {
        source += "[^/]*";
        index += 1;
      }
    } else if (character === "?") {
      source += "[^/]";
      index += 1;
    } else if (character === "{") {
      const end = pattern.indexOf("}", index);
      if (end === -1) {
        source += "\\{";
        index += 1;
      } else {
        const alternatives = pattern
          .slice(index + 1, end)
          .split(",")
          .map((part) => part.replace(/[|\\.*+?^$(){}\[\]]/gu, "\\$&"))
          .join("|");
        source += `(?:${alternatives})`;
        index = end + 1;
      }
    } else if ("\\^$.|+()[]".includes(character)) {
      source += `\\${character}`;
      index += 1;
    } else {
      source += character;
      index += 1;
    }
  }
  return new RegExp(`^${source}$`, "u");
}

/** Rejects git refs that could be mistaken for options or shell syntax. */
export function validateGitRef(ref: string): boolean {
  return /^[A-Za-z0-9][A-Za-z0-9._/@+-]*$/u.test(ref) && !ref.includes("..");
}

/** Repo-relative display paths must stay inside the repository. */
export function normalizeRepoPath(path: string): string | null {
  const normalized = posix.normalize(path.replaceAll("\\", "/"));
  if (normalized.startsWith("/") || normalized === ".." || normalized.startsWith("../")) {
    return null;
  }
  return normalized;
}

interface WalkEntry {
  path: string;
  depth: number;
}

/**
 * Breadth-first walk of the repository, skipping hidden entries and symlinked
 * directories (symlinks may point outside the tree and are a read-only
 * scanner's escape hatch). Bounded by entry count and depth so degenerate
 * trees cannot stall a scan phase.
 */
export async function* walkRepository(
  cwd: string,
): AsyncGenerator<WalkEntry, void, void> {
  const queue: WalkEntry[] = [{ path: ".", depth: 0 }];
  let visited = 0;
  while (queue.length > 0) {
    const entry = queue.shift()!;
    const directory = entry.path === "." ? cwd : join(cwd, entry.path);
    let names;
    try {
      names = await readdir(directory, { withFileTypes: true });
    } catch {
      continue;
    }
    for (const name of names) {
      if (name.name.startsWith(".")) continue;
      visited += 1;
      if (visited > WALK_ENTRY_CAP) return;
      if (entry.depth >= WALK_DEPTH) continue;
      const relative = entry.path === "." ? name.name : `${entry.path}/${name.name}`;
      yield { path: relative, depth: entry.depth };
      if (name.isDirectory() && !name.isSymbolicLink()) {
        queue.push({ path: relative, depth: entry.depth + 1 });
      }
    }
  }
}

const execFileAsync = promisify(execFile);

let ripgrepAvailable: Promise<boolean> | undefined;

function isRipgrepAvailable(): Promise<boolean> {
  ripgrepAvailable ??= execFileAsync("rg", ["--version"])
    .then(() => true)
    .catch(() => false);
  return ripgrepAvailable;
}

export interface SearchHit {
  path: string;
  line: number;
  text: string;
}

/** Pure-JS search fallback for environments without ripgrep. */
export async function searchWithWalker(
  cwd: string,
  query: string,
  glob: RegExp | undefined,
  maxResults: number,
): Promise<SearchHit[]> {
  let regexp: RegExp;
  try {
    regexp = new RegExp(query, "u");
  } catch {
    const escaped = query.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&");
    regexp = new RegExp(escaped, "u");
  }
  const hits: SearchHit[] = [];
  for await (const entry of walkRepository(cwd)) {
    if (glob !== undefined && !glob.test(entry.path)) continue;
    const absolute = resolveWithin(cwd, entry.path);
    if (absolute === null) continue;
    let content;
    try {
      const buffer = await readFile(absolute);
      if (buffer.includes(0)) continue; // binary
      content = buffer.toString("utf8");
    } catch {
      continue;
    }
    const lines = content.split("\n");
    for (let index = 0; index < lines.length; index += 1) {
      if (regexp.test(lines[index]!)) {
        hits.push({ path: entry.path, line: index + 1, text: lines[index]! });
        if (hits.length >= maxResults) return hits;
      }
    }
  }
  return hits;
}

function formatSearchHits(hits: readonly SearchHit[]): string {
  return hits.map((hit) => `${hit.path}:${hit.line}: ${hit.text}`).join("\n");
}

/**
 * Confines a resolved path to the real repository root. Symlinks inside the
 * tree that point outside are rejected: the scanner must never follow a link
 * out of the repository it was pointed at.
 */
export async function assertRealPathWithin(cwd: string, absolute: string): Promise<void> {
  const [realRoot, realPath] = await Promise.all([realpath(cwd), realpath(absolute)]);
  if (realPath !== realRoot && !realPath.startsWith(realRoot + sep)) {
    throw new Error(`Path escapes the repository root: ${absolute}`);
  }
}

function textResult(text: string) {
  return { content: [{ type: "text" as const, text }], details: {} };
}

/** Builds the four read-only tools bound to a repository root. */
export function readOnlyToolDefinitions(cwd: string): AnyToolDefinition[] {
  return [
    defineTool({
      name: "read_file",
      label: "Read file",
      description:
        "Read a text file from the repository under scan. Returns numbered lines. " +
        `Reads at most ${MAX_READ_LINES} lines per call; use offset/limit for large files.`,
      parameters: Type.Object({
        path: Type.String({ description: "Repository-relative file path" }),
        offset: Type.Optional(
          Type.Integer({ minimum: 1, description: "First line to read (1-based)" }),
        ),
        limit: Type.Optional(
          Type.Integer({ minimum: 1, description: "Number of lines to read" }),
        ),
      }),
      executionMode: "parallel",
      async execute(_toolCallId, params) {
        const absolute = resolveWithin(cwd, params.path);
        if (absolute === null) {
          throw new Error(`Path escapes the repository root: ${params.path}`);
        }
        await assertRealPathWithin(cwd, absolute);
        const buffer = await readFile(absolute);
        const truncated =
          buffer.byteLength > MAX_READ_BYTES
            ? buffer.subarray(0, MAX_READ_BYTES).toString("utf8")
            : buffer.toString("utf8");
        return textResult(
          formatNumberedLines(
            truncated,
            params.offset ?? 1,
            params.limit ?? MAX_READ_LINES,
          ),
        );
      },
    }),
    defineTool({
      name: "glob_files",
      label: "Glob files",
      description:
        `List repository files matching a glob pattern (*, **, ?, {a,b}). Returns at most ${MAX_GLOB_RESULTS} paths.`,
      parameters: Type.Object({
        pattern: Type.String({ description: "Glob pattern, e.g. src/**/*.ts" }),
      }),
      executionMode: "parallel",
      async execute(_toolCallId, params) {
        const glob = globToRegExp(params.pattern);
        const matches: string[] = [];
        for await (const entry of walkRepository(cwd)) {
          if (glob.test(entry.path)) {
            matches.push(entry.path);
            if (matches.length >= MAX_GLOB_RESULTS) break;
          }
        }
        matches.sort();
        return textResult(
          matches.length === 0
            ? "No files matched the pattern."
            : matches.join("\n"),
        );
      },
    }),
    defineTool({
      name: "search_files",
      label: "Search files",
      description:
        "Search file contents with a regular expression (ripgrep syntax when available). " +
        `Returns path:line: text matches, at most ${MAX_SEARCH_RESULTS}.`,
      parameters: Type.Object({
        query: Type.String({ description: "Regular expression to search for" }),
        glob: Type.Optional(
          Type.String({ description: "Restrict search to files matching this glob" }),
        ),
        maxResults: Type.Optional(
          Type.Integer({ minimum: 1, maximum: MAX_SEARCH_RESULTS, description: "Match cap" }),
        ),
      }),
      executionMode: "parallel",
      async execute(_toolCallId, params) {
        const maxResults = params.maxResults ?? DEFAULT_SEARCH_RESULTS;
        const glob = params.glob === undefined ? undefined : globToRegExp(params.glob);
        let hits: SearchHit[];
        if (await isRipgrepAvailable()) {
          const { stdout } = await execFileAsync(
            "rg",
            [
              "--no-config",
              "--no-messages",
              "--line-number",
              "--no-heading",
              "--max-count",
              "20",
              "-e",
              params.query,
              ".",
            ],
            { cwd, maxBuffer: 16 * 1024 * 1024, timeout: 30_000 },
          ).catch(() => ({ stdout: "" }));
          const all = parseRipgrepOutput(stdout);
          hits = all.filter((hit) => glob === undefined || glob.test(hit.path)).slice(0, maxResults);
        } else {
          hits = await searchWithWalker(cwd, params.query, glob, maxResults);
        }
        if (hits.length === 0) return textResult("No matches found.");
        return textResult(formatSearchHits(hits));
      },
    }),
    defineTool({
      name: "git_show",
      label: "Show file at revision",
      description:
        "Show a repository file's content at a given git revision. Use this to " +
        "inspect deleted files or the baseline version of changed files.",
      parameters: Type.Object({
        ref: Type.String({ description: "Git revision, e.g. a branch, tag, or commit hash" }),
        path: Type.String({ description: "Repository-relative path at that revision" }),
      }),
      executionMode: "parallel",
      async execute(_toolCallId, params) {
        if (!validateGitRef(params.ref)) {
          throw new Error(`Invalid git revision: ${params.ref}`);
        }
        const path = normalizeRepoPath(params.path);
        if (path === null) {
          throw new Error(`Path escapes the repository root: ${params.path}`);
        }
        const { stdout } = await execFileAsync(
          "git",
          ["-C", cwd, "show", `${params.ref}:${path}`],
          { maxBuffer: 16 * 1024 * 1024, timeout: 30_000 },
        );
        const text =
          stdout.length > MAX_GIT_BYTES
            ? `${stdout.slice(0, MAX_GIT_BYTES)}\n(truncated)`
            : stdout;
        return textResult(text);
      },
    }),
  ];
}

/** Parses `path:line:text` ripgrep output; colons in path are handled by rg's JSON-free format ambiguity, so paths containing colons may misparse in this fallback and are rare in practice. */
export function parseRipgrepOutput(stdout: string): SearchHit[] {
  const hits: SearchHit[] = [];
  for (const line of stdout.split("\n")) {
    if (line === "") continue;
    const match = /^(.+?):(\d+):(.*)$/u.exec(line);
    if (match === null) continue;
    hits.push({ path: match[1]!, line: Number(match[2]), text: match[3]! });
  }
  return hits;
}

export const READ_ONLY_TOOL_NAMES = ["read_file", "glob_files", "search_files", "git_show"] as const;
