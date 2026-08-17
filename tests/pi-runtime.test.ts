import { beforeEach, describe, expect, test, vi } from "vitest";

/**
 * The pi SDK surface is mocked: these tests pin the contract that matters to
 * open-security — read-only tool registration, session isolation flags,
 * system-prompt passthrough, usage accounting, and the max-turns abort.
 */
const state = vi.hoisted(() => {
  return {
    session: undefined as
      | {
          prompt: ReturnType<typeof vi.fn>;
          subscribe: ReturnType<typeof vi.fn>;
          abort: ReturnType<typeof vi.fn>;
          dispose: ReturnType<typeof vi.fn>;
          emit: (event: unknown) => void;
        }
      | undefined,
    sessionOptions: undefined as Record<string, unknown>,
    loaderOptions: undefined as Record<string, unknown>,
    inMemoryUsed: false,
    runtimeApiKeys: {} as Record<string, string>,
  };
});

vi.mock("@mariozechner/pi-coding-agent", () => ({
  AuthStorage: {
    create: () => ({
      setRuntimeApiKey: (provider: string, key: string) => {
        state.runtimeApiKeys[provider] = key;
      },
    }),
  },
  SessionManager: {
    inMemory: () => {
      state.inMemoryUsed = true;
      return {};
    },
  },
  DefaultResourceLoader: class {
    public constructor(options: Record<string, unknown>) {
      state.loaderOptions = options;
    }
    public async reload(): Promise<void> {}
  },
  createAgentSession: async (options: Record<string, unknown>) => {
    state.sessionOptions = options;
    return { session: state.session };
  },
}));

import { PiRuntime } from "../src/runtime/pi.js";
import { AgentRuntimeError } from "../src/runtime/types.js";

interface AssistantMessageSpec {
  text: string;
  stopReason: string;
  inputTokens?: number;
  outputTokens?: number;
  errorMessage?: string;
}

/** Builds a fake session whose prompt() replays scripted events. */
function fakeSession(options: {
  toolCalls?: number;
  messages?: AssistantMessageSpec[];
  promptAction?: () => void;
}): void {
  const listeners = new Set<(event: unknown) => void>();
  state.session = {
    prompt: vi.fn(async () => {
      options.promptAction?.();
      for (let index = 0; index < (options.toolCalls ?? 0); index += 1) {
        listeners.forEach((listener) =>
          listener({ type: "tool_execution_start", toolCallId: `t${index}` }),
        );
      }
      for (const message of options.messages ?? []) {
        listeners.forEach((listener) =>
          listener({
            type: "message_end",
            message: {
              role: "assistant",
              content: [{ type: "text", text: message.text }],
              usage: {
                input: message.inputTokens ?? 10,
                output: message.outputTokens ?? 5,
              },
              stopReason: message.stopReason,
              errorMessage: message.errorMessage,
            },
          }),
        );
      }
    }),
    subscribe: vi.fn((listener: (event: unknown) => void) => {
      listeners.add(listener);
      return () => listeners.delete(listener);
    }),
    abort: vi.fn(async () => {}),
    dispose: vi.fn(),
    emit: (event: unknown) => listeners.forEach((listener) => listener(event)),
  };
}

const RUN = { prompt: "review this", cwd: process.cwd() } as const;

beforeEach(() => {
  state.session = undefined;
  state.sessionOptions = undefined;
  state.loaderOptions = undefined;
  state.inMemoryUsed = false;
  state.runtimeApiKeys = {};
});

describe("PiRuntime", () => {
  test("returns final text and summed usage, and registers only read-only tools", async () => {
    fakeSession({
      toolCalls: 2,
      messages: [
        { text: "partial", stopReason: "toolUse", inputTokens: 10, outputTokens: 5 },
        { text: '{"candidates":[]}', stopReason: "stop", inputTokens: 20, outputTokens: 7 },
      ],
    });
    const result = await new PiRuntime({
      baseUrl: "https://api.example.com/v1",
      model: "test-model",
      provider: undefined,
      apiKeyEnv: undefined,
      apiKey: undefined,
      contextWindow: undefined,
      maxTokens: undefined,
      maxTurnsPerPhase: undefined,
    }).run({ ...RUN });
    expect(result.text).toBe('{"candidates":[]}');
    expect(result.usage).toEqual({ inputTokens: 30, outputTokens: 12 });

    expect(state.sessionOptions?.["noTools"]).toBe("all");
    expect(state.sessionOptions?.["tools"]).toEqual([
      "read_file",
      "glob_files",
      "search_files",
      "git_show",
    ]);
    const customTools = state.sessionOptions?.["customTools"] as unknown[];
    expect(customTools.map((tool) => (tool as { name: string }).name)).toEqual([
      "read_file",
      "glob_files",
      "search_files",
      "git_show",
    ]);
    expect(state.inMemoryUsed).toBe(true);
  });

  test("isolates the pi config dir and passes the reviewer system prompt", async () => {
    fakeSession({ messages: [{ text: "ok", stopReason: "stop" }] });
    await new PiRuntime({
      baseUrl: "https://api.example.com/v1",
      model: "m",
      provider: undefined,
      apiKeyEnv: undefined,
      apiKey: undefined,
      contextWindow: undefined,
      maxTokens: undefined,
      maxTurnsPerPhase: undefined,
    }).run({ ...RUN });
    expect(state.loaderOptions?.["noExtensions"]).toBe(true);
    expect(state.loaderOptions?.["noSkills"]).toBe(true);
    expect(state.loaderOptions?.["noContextFiles"]).toBe(true);
    expect(state.loaderOptions?.["cwd"]).toBe(process.cwd());
    expect(String(state.loaderOptions?.["systemPrompt"])).toContain(
      "security code reviewer",
    );
  });

  test("forwards a custom system prompt verbatim", async () => {
    fakeSession({ messages: [{ text: "ok", stopReason: "stop" }] });
    await new PiRuntime({
      baseUrl: "https://api.example.com/v1",
      model: "m",
      provider: undefined,
      apiKeyEnv: undefined,
      apiKey: undefined,
      contextWindow: undefined,
      maxTokens: undefined,
      maxTurnsPerPhase: undefined,
    }).run({ ...RUN, systemPrompt: "CUSTOM SYSTEM PROMPT" });
    expect(state.loaderOptions?.["systemPrompt"]).toBe("CUSTOM SYSTEM PROMPT");
  });

  test("aborts and reports diagnosably when the turn limit is hit", async () => {
    fakeSession({
      toolCalls: 3,
      messages: [{ text: "half-done", stopReason: "aborted" }],
    });
    const runtime = new PiRuntime({
      baseUrl: "https://api.example.com/v1",
      model: "m",
      provider: undefined,
      apiKeyEnv: undefined,
      apiKey: undefined,
      contextWindow: undefined,
      maxTokens: undefined,
      maxTurnsPerPhase: undefined,
    });
    await expect(runtime.run({ ...RUN, maxTurns: 2 })).rejects.toThrow(
      AgentRuntimeError,
    );
    await expect(runtime.run({ ...RUN, maxTurns: 2 })).rejects.toThrow(
      /turn limit/u,
    );
    expect(state.session?.abort).toHaveBeenCalled();
  });

  test("surfaces model errors from the final assistant message", async () => {
    fakeSession({
      messages: [
        { text: "", stopReason: "error", errorMessage: "401 unauthorized" },
      ],
    });
    await expect(
      new PiRuntime({
        baseUrl: "https://api.example.com/v1",
        model: "m",
        provider: undefined,
        apiKeyEnv: undefined,
        apiKey: undefined,
        contextWindow: undefined,
        maxTokens: undefined,
        maxTurnsPerPhase: undefined,
      }).run({ ...RUN }),
    ).rejects.toThrow(/401 unauthorized/u);
  });

  test("fails fast when apiKeyEnv names a variable that is not set", async () => {
    await expect(
      new PiRuntime({
        baseUrl: "https://api.example.com/v1",
        model: "m",
        api: undefined,
        provider: undefined,
        apiKeyEnv: "OPEN_SECURITY_DEFINITELY_UNSET_KEY",
        apiKey: undefined,
        contextWindow: undefined,
        maxTokens: undefined,
        maxTurnsPerPhase: undefined,
      }).run({ ...RUN }),
    ).rejects.toThrow(/is not set in the environment/u);
  });

  test("resolves the API key from the configured env var and provider label", async () => {
    fakeSession({ messages: [{ text: "ok", stopReason: "stop" }] });
    process.env["OPEN_SECURITY_TEST_PI_KEY"] = "secret-key";
    try {
      await new PiRuntime({
        baseUrl: "https://api.example.com/v1",
        model: "m",
        provider: "deepseek",
        apiKeyEnv: "OPEN_SECURITY_TEST_PI_KEY",
        apiKey: undefined,
        contextWindow: undefined,
        maxTokens: undefined,
        maxTurnsPerPhase: undefined,
      }).run({ ...RUN });
    } finally {
      delete process.env["OPEN_SECURITY_TEST_PI_KEY"];
    }
    expect(state.runtimeApiKeys).toEqual({ deepseek: "secret-key" });
  });

  test("defaults to openai-completions and fails fast on Anthropic-looking URLs", async () => {
    fakeSession({ messages: [{ text: "ok", stopReason: "stop" }] });
    await new PiRuntime({
      baseUrl: "https://api.deepseek.com/v1",
      model: "deepseek-chat",
      api: undefined,
      provider: undefined,
      apiKeyEnv: undefined,
      apiKey: undefined,
      contextWindow: undefined,
      maxTokens: undefined,
      maxTurnsPerPhase: undefined,
    }).run({ ...RUN });
    const model = state.sessionOptions?.["model"] as Record<string, unknown>;
    expect(model["api"]).toBe("openai-completions");
    expect(model["provider"]).toBe("openai");

    await expect(
      new PiRuntime({
        baseUrl: "https://api.anthropic.com",
        model: "claude-sonnet-4-5",
        api: undefined,
        provider: undefined,
        apiKeyEnv: undefined,
        apiKey: undefined,
        contextWindow: undefined,
        maxTokens: undefined,
        maxTurnsPerPhase: undefined,
      }).run({ ...RUN }),
    ).rejects.toThrow(/--api anthropic-messages/u);
  });

  test("routes Anthropic endpoints over anthropic-messages with the anthropic provider label", async () => {
    fakeSession({ messages: [{ text: "ok", stopReason: "stop" }] });
    await new PiRuntime({
      baseUrl: "https://api.anthropic.com",
      model: "claude-sonnet-4-5",
      api: "anthropic-messages",
      provider: undefined,
      apiKeyEnv: undefined,
      apiKey: undefined,
      contextWindow: undefined,
      maxTokens: undefined,
      maxTurnsPerPhase: undefined,
    }).run({ ...RUN });
    const model = state.sessionOptions?.["model"] as Record<string, unknown>;
    expect(model["api"]).toBe("anthropic-messages");
    expect(model["provider"]).toBe("anthropic");
    expect(model["reasoning"]).toBe(true);
    // Anthropic key resolution happens under the same provider label.
    process.env["OPEN_SECURITY_TEST_PI_KEY"] = "sk-ant";
    try {
      await new PiRuntime({
        baseUrl: "https://api.anthropic.com",
        model: "claude-sonnet-4-5",
        api: "anthropic-messages",
        provider: undefined,
        apiKeyEnv: "OPEN_SECURITY_TEST_PI_KEY",
        apiKey: undefined,
        contextWindow: undefined,
        maxTokens: undefined,
        maxTurnsPerPhase: undefined,
      }).run({ ...RUN });
    } finally {
      delete process.env["OPEN_SECURITY_TEST_PI_KEY"];
    }
    expect(state.runtimeApiKeys).toEqual({ anthropic: "sk-ant" });
  });

  test("explicit anthropic-messages wins on neutral gateway URLs", async () => {
    fakeSession({ messages: [{ text: "ok", stopReason: "stop" }] });
    await new PiRuntime({
      baseUrl: "https://llm-gateway.internal/v1",
      model: "claude-sonnet-4-5",
      api: "anthropic-messages",
      provider: undefined,
      apiKeyEnv: undefined,
      apiKey: undefined,
      contextWindow: undefined,
      maxTokens: undefined,
      maxTurnsPerPhase: undefined,
    }).run({ ...RUN });
    const model = state.sessionOptions?.["model"] as Record<string, unknown>;
    expect(model["api"]).toBe("anthropic-messages");
    expect(model["provider"]).toBe("anthropic");
  });

  test("rejects a run that was aborted before it started", async () => {
    const controller = new AbortController();
    controller.abort();
    await expect(
      new PiRuntime({
        baseUrl: "https://api.example.com/v1",
        model: "m",
        provider: undefined,
        apiKeyEnv: undefined,
        apiKey: undefined,
        contextWindow: undefined,
        maxTokens: undefined,
        maxTurnsPerPhase: undefined,
      }).run({ ...RUN, signal: controller.signal }),
    ).rejects.toThrow(/aborted before start/u);
  });
});
