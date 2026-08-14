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

const DISCOVERY_BATCH_SIZE = 25;

/**
 * Discovery phase: reviews the inventory (sequentially in this MVP — the
 * reference methodology explicitly defines sequential review as the valid
 * degraded mode). Diff inventories are small enough for one pass;
 * repository inventories are split into batches so a single agent context
 * stays bounded.
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
  onBatchProgress?: (batch: number, batches: number) => void;
}): Promise<Candidate[]> {
  const files = options.inventory.files;
  if (files.length === 0) return [];
  const batches: (typeof files)[] = [];
  for (let index = 0; index < files.length; index += DISCOVERY_BATCH_SIZE) {
    batches.push(files.slice(index, index + DISCOVERY_BATCH_SIZE));
  }
  const candidates: Candidate[] = [];
  const seen = new Set<string>();
  for (const [batchIndex, batch] of batches.entries()) {
    options.onBatchProgress?.(batchIndex + 1, batches.length);
    const result = await options.runtime.run({
      prompt: discoveryPrompt({
        files: batch,
        threatModel: options.threatModel,
        securityMd: options.securityMd,
        diffSummary: options.diffSummary,
        origin: options.inventory.origin,
      }),
      cwd: options.repository,
      ...(options.maxTurns === undefined
        ? {}
        : { maxTurns: options.maxTurns }),
      ...(options.signal === undefined ? {} : { signal: options.signal }),
    });
    const parsed = discoveryResultSchema.parse(extractJsonObject(result.text));
    for (const candidate of parsed.candidates) {
      if (seen.has(candidate.title + candidate.path)) continue;
      seen.add(candidate.title + candidate.path);
      candidates.push({
        id: `cand_${String(candidates.length + 1).padStart(4, "0")}`,
        ...candidate,
      });
    }
  }
  return candidates;
}
