import type { DiffHunk, GitChangedFile } from "../git.js";

/**
 * Directory names excluded from review, ported from the reference
 * methodology's deterministic inventory rules.
 */
const EXCLUDED_DIRS: ReadonlySet<string> = new Set([
  ".cache",
  ".circleci",
  ".devcontainer",
  ".git",
  ".github",
  ".idea",
  ".mypy_cache",
  ".pytest_cache",
  ".ruff_cache",
  ".tox",
  ".venv",
  ".vscode",
  "__pycache__",
  "bench",
  "benchmark",
  "bintest",
  "build",
  "build_config",
  "build_configs",
  "build-tools",
  "build_tools",
  "ci",
  "coverage",
  "deps",
  "dev",
  "dist",
  "doc",
  "docs",
  "example",
  "examples",
  "external",
  "extern",
  "fixture",
  "fixtures",
  "generated",
  "node_modules",
  "sample",
  "samples",
  "target",
  "test",
  "tests",
  "testing",
  "third-party",
  "third_party",
  "tmp",
  "vendor",
]);

const EXCLUDED_FILENAMES: ReadonlySet<string> = new Set([
  ".DS_Store",
  "CHANGELOG",
  "CHANGELOG.md",
  "CONTRIBUTING.md",
  "Dockerfile",
  "Gemfile",
  "Gemfile.lock",
  "LICENSE",
  "LICENSE.md",
  "Makefile",
  "NEWS",
  "NEWS.md",
  "NOTICE",
  "README",
  "README.md",
  "README.rst",
  "Rakefile",
  "SECURITY.md",
  "TODO",
  "TODO.md",
  "docker-compose.yml",
  "package-lock.json",
  "pnpm-lock.yaml",
  "yarn.lock",
]);

const TEXT_CODE_EXTENSIONS: ReadonlySet<string> = new Set([
  ".c",
  ".cc",
  ".cfg",
  ".clj",
  ".cpp",
  ".cs",
  ".css",
  ".cue",
  ".cxx",
  ".dart",
  ".ex",
  ".exs",
  ".go",
  ".graphql",
  ".h",
  ".hpp",
  ".hs",
  ".html",
  ".java",
  ".js",
  ".json",
  ".jsx",
  ".kt",
  ".kts",
  ".lua",
  ".mjs",
  ".mm",
  ".php",
  ".proto",
  ".py",
  ".rb",
  ".rs",
  ".scala",
  ".sh",
  ".sql",
  ".swift",
  ".toml",
  ".ts",
  ".tsx",
  ".vue",
  ".xml",
  ".yaml",
  ".yml",
]);

export interface InventoryFile {
  path: string;
  status: GitChangedFile["status"];
  previousPath?: string;
  /** Changed line ranges in the head revision, when available. */
  hunks: DiffHunk[];
}

export interface ScanInventory {
  files: InventoryFile[];
  /** Changed paths dropped by the exclusion rules, for honest coverage. */
  excluded: string[];
}

export function isReviewablePath(path: string): boolean {
  const segments = path.split("/");
  if (segments.some((segment) => EXCLUDED_DIRS.has(segment))) return false;
  const filename = segments.at(-1) ?? "";
  if (EXCLUDED_FILENAMES.has(filename)) return false;
  if (filename.endsWith(".min.js") || filename.endsWith(".map")) return false;
  const extension = filename.slice(filename.lastIndexOf(".")).toLowerCase();
  return TEXT_CODE_EXTENSIONS.has(extension);
}

/**
 * Builds the review inventory. Deleted files are kept (they are reviewed at
 * the baseline revision); every other changed file is reviewed at head.
 */
export function buildInventory(
  changed: readonly GitChangedFile[],
  hunks: ReadonlyMap<string, DiffHunk[]>,
): ScanInventory {
  const files: InventoryFile[] = [];
  const excluded: string[] = [];
  for (const file of changed) {
    if (isReviewablePath(file.path)) {
      files.push({
        path: file.path,
        status: file.status,
        ...(file.previousPath === undefined
          ? {}
          : { previousPath: file.previousPath }),
        hunks: hunks.get(file.path) ?? [],
      });
    } else {
      excluded.push(file.path);
    }
  }
  // Code-point order (not locale-aware) keeps the inventory deterministic
  // across machines and locales.
  files.sort((left, right) => (left.path < right.path ? -1 : left.path > right.path ? 1 : 0));
  excluded.sort((left, right) => (left < right ? -1 : left > right ? 1 : 0));
  return { files, excluded };
}
