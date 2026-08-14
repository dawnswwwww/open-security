import { spawn } from "node:child_process";
import { Readable, Writable } from "node:stream";
import * as acp from "@agentclientprotocol/sdk";
import {
  AgentRuntimeError,
  type AgentRuntime,
  type AgentRunRequest,
  type AgentRunResult,
} from "./types.js";

/** Tool kinds a security reviewer may use: inspection and reasoning only. */
const READ_ONLY_TOOL_KINDS: ReadonlySet<string> = new Set([
  "read",
  "search",
  "think",
]);

/**
 * Agent Client Protocol runtime. Launches any ACP-compatible agent process
 * (declared via `acpCommand`) per run, so every pipeline phase gets a fresh,
 * isolated session. Model routing belongs to the ACP agent's own
 * configuration; open-security only enforces the read-only tool policy.
 */
export class AcpRuntime implements AgentRuntime {
  public readonly kind = "acp";
  readonly #command: string;

  public constructor(config: { acpCommand: string }) {
    this.#command = config.acpCommand;
  }

  public async run(request: AgentRunRequest): Promise<AgentRunResult> {
    const [command, ...arguments_] = splitCommandLine(this.#command);
    if (command === undefined || command.length === 0) {
      throw new AgentRuntimeError("--acp-command is empty.", this.kind);
    }
    const child = spawn(command, arguments_, {
      stdio: ["pipe", "pipe", "inherit"] as ["pipe", "pipe", "inherit"],
      cwd: request.cwd,
      env: process.env,
    });
    const abort = () => child.kill("SIGTERM");
    request.signal?.addEventListener("abort", abort, { once: true });
    if (request.signal?.aborted) {
      child.kill("SIGTERM");
      throw new AgentRuntimeError("Run aborted before start.", this.kind);
    }
    try {
      const stream = acp.ndJsonStream(
        Writable.toWeb(child.stdin!),
        Readable.toWeb(child.stdout!),
      );
      const text = await acp
        .client({ name: "open-security" })
        .onRequest(
          acp.methods.client.session.requestPermission,
          (context) => this.#permissionResponse(context.params),
        )
        .connectWith(stream, async (context) => {
          await context.request(acp.methods.agent.initialize, {
            protocolVersion: acp.PROTOCOL_VERSION,
            clientCapabilities: {
              fs: { readTextFile: false, writeTextFile: false },
            },
          });
          return await context
            .buildSession(request.cwd)
            .withSession(async (session) => {
              await session.prompt(
                request.systemPrompt === undefined
                  ? request.prompt
                  : [
                      {
                        type: "text",
                        text: `${request.systemPrompt}\n\n${request.prompt}`,
                      },
                    ],
              );
              let collected = "";
              for (;;) {
                const message = await session.nextUpdate();
                if (message.kind === "stop") {
                  if (message.response.stopReason === "refusal") {
                    throw new AgentRuntimeError(
                      "The ACP agent refused the prompt.",
                      this.kind,
                    );
                  }
                  return collected;
                }
                const update = message.notification.update;
                if (
                  update.sessionUpdate === "agent_message_chunk" &&
                  update.content.type === "text"
                ) {
                  collected += update.content.text;
                }
              }
            });
        });
      return { text };
    } catch (error) {
      if (error instanceof AgentRuntimeError) throw error;
      throw new AgentRuntimeError(
        `ACP agent run failed: ${
          error instanceof Error ? error.message : String(error)
        }`,
        this.kind,
        { cause: error },
      );
    } finally {
      request.signal?.removeEventListener("abort", abort);
      child.kill();
    }
  }

  /**
   * Read-only policy: allow inspection and reasoning tool kinds, reject
   * everything else by selecting the agent's own reject option.
   */
  #permissionResponse(
    params: unknown,
  ): { outcome: { outcome: "selected"; optionId: string } } {
    const request = params as {
      toolCall?: { kind?: string };
      options?: { optionId: string; kind: string }[];
    };
    const allowed = READ_ONLY_TOOL_KINDS.has(request.toolCall?.kind ?? "other");
    const wanted = allowed ? "allow" : "reject";
    const option =
      request.options?.find((candidate) =>
        candidate.kind.startsWith(wanted),
      ) ?? request.options?.[0];
    return {
      outcome: {
        outcome: "selected",
        optionId: option?.optionId ?? "",
      },
    };
  }
}

/** Minimal shell-style tokenizer for `--acp-command "cmd --flag 'value'"`. */
export function splitCommandLine(command: string): string[] {
  const tokens: string[] = [];
  let current = "";
  let quote: '"' | "'" | null = null;
  for (const character of command) {
    if (quote !== null) {
      if (character === quote) quote = null;
      else current += character;
      continue;
    }
    if (character === '"' || character === "'") {
      quote = character;
      continue;
    }
    if (/\s/u.test(character)) {
      if (current.length > 0) {
        tokens.push(current);
        current = "";
      }
      continue;
    }
    current += character;
  }
  if (current.length > 0) tokens.push(current);
  return tokens;
}
