/**
 * Agent runtime abstraction.
 *
 * open-security never talks to a model directly. Each pipeline phase sends a
 * self-contained prompt to an AgentRuntime, which executes it with an agent
 * that has read access to the repository under scan. Implementations decide
 * how models are routed (Anthropic protocol, ACP agent process, ...).
 */

export interface TokenUsage {
  inputTokens: number;
  outputTokens: number;
  /** Prompt tokens served from a provider-side cache, when reported. */
  cacheReadTokens?: number;
  /** Prompt tokens written into a provider-side cache, when reported. */
  cacheWriteTokens?: number;
  /** Runtime-reported cost of the run in USD, when the runtime can price it. */
  costUSD?: number;
  /** Agent turns consumed by the run, when the runtime reports them. */
  turns?: number;
}

export interface AgentRunRequest {
  /** Fully self-contained task prompt. */
  prompt: string;
  /** Repository root the agent may read. */
  cwd: string;
  /** Replaces the runtime's default system prompt when provided. */
  systemPrompt?: string;
  /** Upper bound on agent turns, when the runtime supports it. */
  maxTurns?: number;
  signal?: AbortSignal;
}

export interface AgentRunResult {
  /** Final assistant text. */
  text: string;
  usage?: TokenUsage;
}

export interface AgentRuntime {
  readonly kind: string;
  run(request: AgentRunRequest): Promise<AgentRunResult>;
}

export class AgentRuntimeError extends Error {
  public constructor(
    message: string,
    public readonly kind: string,
    options?: ErrorOptions,
  ) {
    super(message, options);
    this.name = "AgentRuntimeError";
  }
}
