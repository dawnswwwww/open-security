import { createHash } from "node:crypto";
import { readFile, writeFile, mkdir } from "node:fs/promises";
import { dirname, join } from "node:path";
import { z } from "zod";
import type { AgentRuntime } from "../runtime/types.js";
import { threatModelPrompt } from "../prompt/threat-model.js";
import { extractJsonObject } from "./json.js";

const threatModelSchema = z.object({
  summary: z.string().min(1),
  assets: z.array(z.string()).default([]),
  trustBoundaries: z.array(z.string()).default([]),
  attackerCapabilities: z.array(z.string()).default([]),
  securityObjectives: z.array(z.string()).default([]),
  assumptions: z.array(z.string()).default([]),
});

export type ThreatModel = z.infer<typeof threatModelSchema>;

/**
 * Runs (or reloads) the repository threat model. The model is
 * diff-agnostic, so it is cached per repository head revision inside the
 * output directory and reused across scans of the same target.
 */
export async function loadThreatModel(options: {
  runtime: AgentRuntime;
  repository: string;
  cacheKey: string;
  outputDir: string;
  maxTurns?: number;
  signal?: AbortSignal;
}): Promise<ThreatModel> {
  const cachePath = join(
    options.outputDir,
    "cache",
    `threat-model-${options.cacheKey}.json`,
  );
  const cached = await readCache(cachePath);
  if (cached !== null) return cached;
  const result = await options.runtime.run({
    prompt: threatModelPrompt(),
    cwd: options.repository,
    ...(options.maxTurns === undefined ? {} : { maxTurns: options.maxTurns }),
    ...(options.signal === undefined ? {} : { signal: options.signal }),
  });
  const model = threatModelSchema.parse(extractJsonObject(result.text));
  await writeCache(cachePath, model);
  return model;
}

function readCache(path: string): Promise<ThreatModel | null> {
  return readFile(path, "utf8")
    .then((content) => threatModelSchema.parse(JSON.parse(content)))
    .catch(() => null);
}

async function writeCache(path: string, model: ThreatModel): Promise<void> {
  try {
    await mkdir(dirname(path), { recursive: true });
    await writeFile(path, `${JSON.stringify(model, null, 2)}\n`, "utf8");
  } catch {
    // Cache writes are best-effort; the scan proceeds without persistence.
  }
}

export function threatModelCacheKey(
  repository: string,
  revision: string,
): string {
  return createHash("sha256")
    .update(`${repository}:${revision}`)
    .digest("hex")
    .slice(0, 16);
}
