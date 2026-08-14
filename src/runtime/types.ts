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
