import { z } from "zod";

/**
 * Runtime selection. `claude-agent` drives the Claude Agent SDK (Anthropic
 * Messages protocol; custom endpoints via baseUrl). `acp` launches any
 * ACP-compatible agent process and lets it own model routing. `pi` embeds
 * the pi agent loop (https://github.com/earendil-works/pi) and routes it at
 * any OpenAI Chat Completions-compatible endpoint.
 */
export const RUNTIME_KINDS = ["claude-agent", "acp", "pi"] as const;
export type RuntimeKind = (typeof RUNTIME_KINDS)[number];

/**
 * Default runtime when `--runtime` is omitted. An explicit protocol (`--api`)
 * always selects pi. Bare invocations keep the zero-config claude-agent
 * path; a `--base-url` that clearly is not an Anthropic endpoint cannot work
 * under claude-agent anyway, so pi is auto-selected for it
 * (OpenAI-compatible endpoints).
 */
export function inferRuntimeKind(
  baseUrl: string | undefined,
  api?: string,
): RuntimeKind {
  if (api !== undefined) return "pi";
  if (baseUrl === undefined) return "claude-agent";
  return /anthropic|claude/iu.test(baseUrl) ? "claude-agent" : "pi";
}

export const SeverityLevels = [
  "critical",
  "high",
  "medium",
  "low",
  "informational",
] as const;
export type SeverityLevel = (typeof SeverityLevels)[number];
export const SEVERITY_RANK: Record<SeverityLevel, number> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
  informational: 0,
};

const runtimeConfigSchema = z.discriminatedUnion("runtime", [
  z.object({
    runtime: z.literal("claude-agent"),
    /**
     * Anthropic-protocol base URL (for example an internal gateway that
     * exposes the Anthropic Messages API). Omit to use the runtime default.
     */
    baseUrl: z.string().url().optional(),
    /** Environment variable holding the API key (preferred over apiKey). */
    apiKeyEnv: z.string().min(1).optional(),
    apiKey: z.string().min(1).optional(),
    model: z.string().min(1).optional(),
    maxTurnsPerPhase: z.number().int().positive().optional(),
  }),
  z.object({
    runtime: z.literal("acp"),
    /** Command line that launches the ACP agent, e.g. "claude-code-acp". */
    acpCommand: z.string().min(1),
    model: z.string().min(1).optional(),
    maxTurnsPerPhase: z.number().int().positive().optional(),
  }),
  z.object({
    runtime: z.literal("pi"),
    /** Model API root, e.g. https://api.openai.com/v1 or https://api.anthropic.com. */
    baseUrl: z.string().url(),
    /** Model id the endpoint serves. */
    model: z.string().min(1),
    /**
     * Wire protocol. Defaults to openai-completions; pass
     * "anthropic-messages" explicitly for Anthropic-protocol endpoints.
     */
    api: z.enum(["openai-completions", "anthropic-messages"]).optional(),
    /** Provider label pi-ai resolves credentials under (default per api). */
    provider: z.string().min(1).optional(),
    apiKeyEnv: z.string().min(1).optional(),
    apiKey: z.string().min(1).optional(),
    /** Model context window claim (default 128000); used for overflow handling. */
    contextWindow: z.number().int().positive().optional(),
    /** Per-request output token cap (default 16384). */
    maxTokens: z.number().int().positive().optional(),
    maxTurnsPerPhase: z.number().int().positive().optional(),
  }),
]);

export const scanOptionsSchema = z.object({
  /** Git ref the diff starts from. */
  base: z.string().min(1),
  /** Git ref the diff ends at. Defaults to HEAD. */
  head: z.string().min(1).default("HEAD"),
  /** Scan staged + unstaged changes against base instead of committed refs. */
  workingTree: z.boolean().default(false),
  failOnSeverity: z
    .enum(["critical", "high", "medium", "low", "informational"])
    .optional(),
  /** Output directory for the contract documents and reports. */
  outputDir: z.string().min(1).optional(),
});

export const repositoryScanOptionsSchema = z.object({
  /** Git ref to scan. Defaults to HEAD. */
  head: z.string().min(1).optional(),
  /** Cap on deep-reviewed files after ranking (default: 150). */
  maxFiles: z.number().int().positive().optional(),
  failOnSeverity: z
    .enum(["critical", "high", "medium", "low", "informational"])
    .optional(),
  outputDir: z.string().min(1).optional(),
});

export type ScanOptions = z.infer<typeof scanOptionsSchema>;
export type RepositoryScanOptions = z.infer<typeof repositoryScanOptionsSchema>;
export type RuntimeConfig = z.infer<typeof runtimeConfigSchema>;

export interface OpenSecurityConfig {
  runtime: RuntimeConfig;
  /**
   * Injects a custom agent runtime, bypassing the built-in adapters. This is
   * the extension point for alternative executors and for tests.
   */
  agent?: import("./runtime/types.js").AgentRuntime;
  /** Abort signal propagated to every agent run. */
  signal?: AbortSignal;
}

export function parseRuntimeConfig(
  value: unknown,
): RuntimeConfig {
  return runtimeConfigSchema.parse(value);
}

export function meetsFailThreshold(
  level: SeverityLevel,
  threshold: SeverityLevel,
): boolean {
  return SEVERITY_RANK[level] >= SEVERITY_RANK[threshold];
}
