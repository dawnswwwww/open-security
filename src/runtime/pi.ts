import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { Model } from "@mariozechner/pi-ai";
import {
  AuthStorage,
  createAgentSession,
  DefaultResourceLoader,
  SessionManager,
} from "@mariozechner/pi-coding-agent";
import {
  AgentRuntimeError,
  type AgentRuntime,
  type AgentRunRequest,
  type AgentRunResult,
  type TokenUsage,
} from "./types.js";
import {
  READ_ONLY_TOOL_NAMES,
  readOnlyToolDefinitions,
} from "./read-only-tools.js";
import { REVIEWER_SYSTEM_PROMPT } from "./claude-agent.js";

/**
 * pi runtime (https://github.com/earendil-works/pi). Embeds the pi agent loop
 * in-process and routes it at OpenAI Chat Completions-compatible endpoints
 * (OpenAI, DeepSeek, Kimi, Qwen, OpenRouter, vLLM, Ollama /v1, LiteLLM, ...)
 * or Anthropic Messages endpoints (api.anthropic.com or a gateway) — one
 * runtime for both wire protocols.
 *
 * Read-only policy: built-in tools are disabled (`noTools: "all"`) and the
 * only registered tools are open-security's inspection tools, so the model
 * physically cannot mutate the repository under scan. Sessions are in-memory
 * and the pi config directory is a throwaway temp dir: nothing is written
 * into the scanned repository and no user-level pi skills, extensions, or
 * credentials leak into a scan.
 */

const DEFAULT_CONTEXT_WINDOW = 128_000;
const DEFAULT_MAX_TOKENS = 16_384;

export type PiApiKind = "openai-completions" | "anthropic-messages";

export interface PiRuntimeConfig {
  baseUrl: string;
  model: string;
  api?: PiApiKind | undefined;
  provider?: string | undefined;
  apiKeyEnv?: string | undefined;
  apiKey?: string | undefined;
  contextWindow?: number | undefined;
  maxTokens?: number | undefined;
  maxTurnsPerPhase?: number | undefined;
}

interface AssistantLikeMessage {
  role: string;
  content: { type: string; text?: string }[];
  usage?: TokenUsageLike;
  stopReason?: string;
  errorMessage?: string;
}

interface TokenUsageLike {
  input: number;
  output: number;
}

export class PiRuntime implements AgentRuntime {
  public readonly kind = "pi";
  readonly #config: PiRuntimeConfig;

  public constructor(config: PiRuntimeConfig) {
    this.#config = config;
  }

  public async run(request: AgentRunRequest): Promise<AgentRunResult> {
    if (request.signal?.aborted) {
      throw new AgentRuntimeError("Run aborted before start.", this.kind);
    }
    // Fail fast instead of sending OpenAI-shaped requests to an Anthropic
    // endpoint: the default protocol is openai-completions and is never
    // guessed from the URL.
    if (
      this.#config.api === undefined &&
      /anthropic|claude/iu.test(this.#config.baseUrl)
    ) {
      throw new AgentRuntimeError(
        "The default wire protocol is openai-completions, but baseUrl looks like an Anthropic endpoint. Pass api: \"anthropic-messages\" (CLI: --api anthropic-messages), or use the claude-agent runtime.",
        this.kind,
      );
    }
    // Throwaway config dir: isolates the scan from ~/.pi (settings, skills,
    // auth) and keeps every write outside the repository under review.
    const agentDir = await mkdtemp(join(tmpdir(), "open-security-pi-"));
    let text: string | null = null;
    let usage: TokenUsage | undefined;
    try {
      const loader = new DefaultResourceLoader({
        cwd: request.cwd,
        agentDir,
        noExtensions: true,
        noSkills: true,
        noContextFiles: true,
        noPromptTemplates: true,
        noThemes: true,
        systemPrompt: request.systemPrompt ?? REVIEWER_SYSTEM_PROMPT,
      });
      await loader.reload();
      const api = this.#api();
      const provider =
        this.#config.provider ?? (api === "anthropic-messages" ? "anthropic" : "openai");
      const authStorage = AuthStorage.create(join(agentDir, "auth.json"));
      const apiKey = this.#resolveApiKey();
      if (apiKey !== undefined) authStorage.setRuntimeApiKey(provider, apiKey);
      const { session } = await createAgentSession({
        cwd: request.cwd,
        model: this.#buildModel(api, provider),
        noTools: "all",
        tools: [...READ_ONLY_TOOL_NAMES],
        customTools: readOnlyToolDefinitions(request.cwd),
        sessionManager: SessionManager.inMemory(),
        resourceLoader: loader,
        authStorage,
      });

      const maxTurns = request.maxTurns ?? this.#config.maxTurnsPerPhase;
      let toolCalls = 0;
      let hitTurnLimit = false;
      const inputTokens = { total: 0 };
      const outputTokens = { total: 0 };
      const lastAssistant: AssistantLikeMessage[] = [];
      const unsubscribe = session.subscribe((event) => {
        if (event.type === "tool_execution_start") {
          toolCalls += 1;
          if (maxTurns !== undefined && toolCalls > maxTurns && !hitTurnLimit) {
            hitTurnLimit = true;
            void session.abort().catch(() => undefined);
          }
          return;
        }
        if (event.type !== "message_end") return;
        const message = event.message as AssistantLikeMessage;
        if (message.role !== "assistant") return;
        if (message.usage !== undefined) {
          inputTokens.total += message.usage.input;
          outputTokens.total += message.usage.output;
        }
        lastAssistant[0] = message;
      });
      const onAbort = () => void session.abort().catch(() => undefined);
      request.signal?.addEventListener("abort", onAbort, { once: true });
      try {
        await session.prompt(request.prompt);
      } finally {
        request.signal?.removeEventListener("abort", onAbort);
        unsubscribe();
        session.dispose();
      }

      const final = lastAssistant[0];
      if (request.signal?.aborted) {
        throw new AgentRuntimeError("Run aborted.", this.kind);
      }
      if (hitTurnLimit) {
        const limit = maxTurns ?? 0;
        throw new AgentRuntimeError(
          `pi agent run hit the turn limit (${limit}). Large repositories need more turns for the repository-wide threat-model phase; re-run with a higher limit, e.g. --max-turns ${Math.max(limit * 2, 100)}.`,
          this.kind,
        );
      }
      if (final === undefined) {
        throw new AgentRuntimeError(
          "pi agent run produced no assistant message.",
          this.kind,
        );
      }
      if (final.stopReason === "error") {
        throw new AgentRuntimeError(
          `pi agent run failed: ${final.errorMessage ?? "model request error"}`,
          this.kind,
        );
      }
      text = final.content
        .filter((part) => part.type === "text")
        .map((part) => part.text ?? "")
        .join("");
      if (text.trim().length === 0) {
        throw new AgentRuntimeError(
          "pi agent run ended without text output.",
          this.kind,
        );
      }
      usage = { inputTokens: inputTokens.total, outputTokens: outputTokens.total };
      return usage.inputTokens === 0 && usage.outputTokens === 0
        ? { text }
        : { text, usage };
    } catch (error) {
      if (error instanceof AgentRuntimeError) throw error;
      throw new AgentRuntimeError(
        `pi agent run failed: ${
          error instanceof Error ? error.message : String(error)
        }`,
        this.kind,
        { cause: error },
      );
    } finally {
      await rm(agentDir, { recursive: true, force: true }).catch(() => undefined);
    }
  }

  /**
   * pi-ai models are plain data; for compatibility endpoints we describe the
   * model ourselves instead of looking it up in the built-in catalog.
   * `compat` quirks are auto-detected by pi-ai from the baseUrl.
   */
  #buildModel(api: PiApiKind, provider: string): Model<PiApiKind> {
    return {
      id: this.#config.model,
      name: this.#config.model,
      api,
      provider,
      baseUrl: this.#config.baseUrl,
      reasoning: api === "anthropic-messages",
      input: ["text"],
      cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 },
      contextWindow: this.#config.contextWindow ?? DEFAULT_CONTEXT_WINDOW,
      maxTokens: this.#config.maxTokens ?? DEFAULT_MAX_TOKENS,
    };
  }

  /** Wire protocol: explicit config wins, otherwise openai-completions. */
  #api(): PiApiKind {
    return this.#config.api ?? "openai-completions";
  }

  #resolveApiKey(): string | undefined {
    if (this.#config.apiKey !== undefined) return this.#config.apiKey;
    if (this.#config.apiKeyEnv !== undefined) {
      const value = process.env[this.#config.apiKeyEnv];
      if (value !== undefined && value.length > 0) return value;
    }
    return undefined;
  }
}
