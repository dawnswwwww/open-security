import { z } from "zod";
import type { AgentRuntime } from "../runtime/types.js";
import type { ScanInventory } from "./inventory.js";
import { discoveryPrompt } from "../prompt/discovery.js";
import { extractJsonObject } from "./json.js";

const candidateSchema = z.object({
  title: z.string().min(1),
  path: z.string().min(1),
  startLine: z.number().int().positive(),
  endLine: z.number().int().positive().nullable(),
  category: z.string().min(1),
  cwe: z.array(z.string()).default([]),
  attackerSource: z.string(),
  sinkOrBrokenControl: z.string(),
  closestControl: z.string(),
  impact: z.string(),
  whyPlausible: z.string(),
  relevantLines: z.array(z.number().int().positive()).default([]),
  supportingPaths: z.array(z.string()).default([]),
});

const discoveryResultSchema = z.object({
  candidates: z.array(candidateSchema),
});

export type Candidate = {
  id: string;
} & z.infer<typeof candidateSchema>;

/**
 * Discovery phase: reviews the changed files (sequentially in this MVP — the
 * reference methodology explicitly defines sequential review as the valid
 * degraded mode) and records plausible candidates with evidence.
 */
export async function runDiscovery(options: {
  runtime: AgentRuntime;
  repository: string;
  inventory: ScanInventory;
  threatModel: string;
  securityMd: string | null;
  diffSummary: string;
  maxTurns?: number;
  signal?: AbortSignal;
}): Promise<Candidate[]> {
  if (options.inventory.files.length === 0) return [];
  const result = await options.runtime.run({
    prompt: discoveryPrompt({
      files: options.inventory.files,
      threatModel: options.threatModel,
      securityMd: options.securityMd,
      diffSummary: options.diffSummary,
    }),
    cwd: options.repository,
    ...(options.maxTurns === undefined ? {} : { maxTurns: options.maxTurns }),
    ...(options.signal === undefined ? {} : { signal: options.signal }),
  });
  const parsed = discoveryResultSchema.parse(extractJsonObject(result.text));
  const seen = new Set<string>();
  const candidates: Candidate[] = [];
  for (const [index, candidate] of parsed.candidates.entries()) {
    const id = `cand_${String(index + 1).padStart(4, "0")}`;
    if (seen.has(id)) continue;
    seen.add(id);
    candidates.push({ id, ...candidate });
  }
  return candidates;
}
