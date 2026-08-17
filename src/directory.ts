import { createHash } from "node:crypto";
import { readdir, realpath, stat } from "node:fs/promises";
import { join, relative, sep } from "node:path";
import { isExcludedSegment, isReviewablePath } from "./pipeline/inventory.js";

export interface DirectorySnapshot {
  root: string;
  /** Every walked file (reviewable and not), repository-relative POSIX paths. */
  allPaths: string[];
  /**
   * sha256 over each reviewable file's path, size, and modification time —
   * the stable identity for non-Git targets (cache keys, fingerprints).
   */
  digest: string;
}

/**
 * Walks a plain directory the way `git ls-files` would walk a repository:
 * descends into every subdirectory except the inventory's excluded
 * directories, records every file, and hashes the reviewable content into a
 * snapshot digest that plays the role a commit SHA plays for Git targets.
 */
export async function scanDirectory(rootInput: string): Promise<DirectorySnapshot> {
  const root = await realpath(rootInput);
  const entries: { path: string; size: number; mtimeMs: number }[] = [];
  const walk = async (directory: string): Promise<void> => {
    const children = await readdir(directory, { withFileTypes: true });
    for (const child of children) {
      if (isExcludedSegment(child.name)) continue;
      const absolute = join(directory, child.name);
      if (child.isDirectory()) {
        await walk(absolute);
        continue;
      }
      if (!child.isFile()) continue;
      try {
        const info = await stat(absolute);
        entries.push({
          path: relative(root, absolute).split(sep).join("/"),
          size: info.size,
          mtimeMs: Math.floor(info.mtimeMs),
        });
      } catch {
        // Broken symlink or vanished file; skip.
      }
    }
  };
  await walk(root);
  entries.sort((left, right) =>
    left.path < right.path ? -1 : left.path > right.path ? 1 : 0,
  );
  const hash = createHash("sha256");
  for (const entry of entries) {
    if (!isReviewablePath(entry.path)) continue;
    hash.update(`${entry.path}\0${entry.size}\0${entry.mtimeMs}\0`);
  }
  return { root, allPaths: entries.map((entry) => entry.path), digest: hash.digest("hex") };
}

/** Stable identity for a directory-scan target. */
export function directoryTargetId(digest: string): string {
  return createHash("sha256").update(`directory:${digest}`).digest("hex").slice(0, 24);
}
