import { z } from "zod";
import type { AgentRuntime } from "../runtime/types.js";
import type { Candidate } from "./discovery.js";
import { validationPrompt } from "../prompt/validation.js";
import { extractJsonObject } from "./json.js";

const verdictSchema = z.object({
  disposition: z.enum(["reportable", "suppressed", "not_applicable", "deferred"]),
  survives: z.enum(["yes", "no", "uncertain"]),
  method: z.literal("static"),
  summary: z.string(),
  source: z.string(),
  control: z.string(),
  sink: z.string(),
  dataflow: z.string(),
  counterevidence: z.string(),
  proofGaps: z.array(z.string()).default([]),
  confidence: z.enum(["high", "medium", "low"]),
  confidenceRationale: z.string(),
  vector: z.enum(["remote", "local_network", "localhost", "none", "unknown"]),
  preconditions: z.enum(["plausible", "unlikely", "unachievable", "unknown"]),
  attackerInputControl: z.enum(["yes", "plausible", "no", "unknown"]),
  authScope: z.enum(["public", "internal-only", "admin-only", "unknown"]),
  impact: z.enum(["high", "medium", "low", "ignore", "unknown"]),
});

export type Verdict = z.infer<typeof verdictSchema>;

export interface ValidatedCandidate {
  candidate: Candidate;
  verdict: Verdict;
}

/**
 * Validation phase: each candidate gets a fresh, independent session that
 * must produce source-backed counterevidence to reject it. Candidates are
 * validated independently — never collapsed by shared family.
 */
export async function runValidation(options: {
  runtime: AgentRuntime;
  repository: string;
  candidates: readonly Candidate[];
  threatModel: string;
  securityMd: string | null;
  maxTurns?: number;
  signal?: AbortSignal;
  onProgress?: (completed: number, total: number) => void;
}): Promise<ValidatedCandidate[]> {
  const results: ValidatedCandidate[] = [];
  for (const [index, candidate] of options.candidates.entries()) {
    const result = await options.runtime.run({
      prompt: validationPrompt({
        candidate,
        threatModel: options.threatModel,
        securityMd: options.securityMd,
      }),
      cwd: options.repository,
      ...(options.maxTurns === undefined ? {} : { maxTurns: options.maxTurns }),
      ...(options.signal === undefined ? {} : { signal: options.signal }),
    });
    const verdict = verdictSchema.parse(extractJsonObject(result.text));
    results.push({ candidate, verdict });
    options.onProgress?.(index + 1, options.candidates.length);
  }
  return results;
}
