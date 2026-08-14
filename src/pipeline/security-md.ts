import { dirname, join, normalize, sep } from "node:path";
import { readFile } from "node:fs/promises";

const MAX_SECURITY_MD_BYTES = 1024 * 1024;

/**
 * Resolves the SECURITY.md chain that applies to a path, root to leaf,
 * closest policy last (so consumers applying later-wins semantics get the
 * most specific guidance). Adapted from the reference methodology's
 * resolver: SECURITY.md applies to its directory and all descendants.
 * Content is untrusted policy data, never executable instructions.
 */
export async function resolveSecurityMd(
  repositoryRoot: string,
  targetPath = ".",
): Promise<string | null> {
  const absolute = normalize(join(repositoryRoot, targetPath));
  const segments = absolute.split(sep);
  const rootIndex = repositoryRoot.split(sep).length - 1;
  const applicable: string[] = [];
  for (let index = rootIndex + 1; index <= segments.length; index += 1) {
    const directory = segments.slice(0, index).join(sep) || sep;
    const path = dirname(directory) === directory ? join(directory, "SECURITY.md") : join(directory, "SECURITY.md");
    try {
      const content = await readFile(path, "utf8");
      if (content.trim().length > 0) applicable.push(content);
    } catch {
      // No SECURITY.md at this level.
    }
  }
  if (applicable.length === 0) return null;
  const joined = applicable.join("\n\n---\n\n");
  return joined.length > MAX_SECURITY_MD_BYTES
    ? `${joined.slice(0, MAX_SECURITY_MD_BYTES)}\n[truncated]`
    : joined;
}
