import { describe, expect, test } from "vitest";
import { z } from "zod";
import { extractJsonObject, runStructured } from "../src/pipeline/json.js";
import type {
  AgentRunRequest,
  AgentRuntime,
  AgentRunResult,
} from "../src/runtime/types.js";

class ScriptedRuntime implements AgentRuntime {
  public readonly kind = "scripted";
  readonly #replies: string[];
  readonly #prompts: string[] = [];
  #cursor = 0;

  public constructor(replies: readonly string[]) {
    this.#replies = [...replies];
  }

  public get prompts(): readonly string[] {
    return this.#prompts;
  }

  public async run(request: AgentRunRequest): Promise<AgentRunResult> {
    this.#prompts.push(request.prompt);
    const reply = this.#replies[this.#cursor];
    this.#cursor += 1;
    if (reply === undefined) throw new Error("ScriptedRuntime exhausted");
    return { text: reply };
  }
}

const schema = z.object({ ok: z.boolean() });

describe("extractJsonObject diagnostics", () => {
  test("quotes the beginning of unparsable output", () => {
    expect(() => extractJsonObject("no braces at all")).toThrow(
      /no braces at all/u,
    );
    expect(() => extractJsonObject("")).toThrow(/<empty model output>/u);
  });

  test("extracts the final JSON after per-file narration", () => {
    const narrated = [
      "I acknowledge the reminders. Let me analyze each file:",
      "",
      "**auth.rs**: reads a secret from stdin. No vulnerabilities — the secret",
      'is only reported as a boolean. The expression `foo { "bar" }` in the',
      "file is quoted prose, not JSON.",
      "",
      'Final answer: {"ok": true}',
    ].join("\n");
    expect(extractJsonObject(narrated)).toEqual({ ok: true });
  });

  test("prefers the last object when several appear", () => {
    expect(extractJsonObject('draft {"a":1} final {"ok": true}')).toEqual({
      ok: true,
    });
  });

  test("still accepts fenced and wrapped JSON", () => {
    expect(extractJsonObject('```json\n{"ok": true}\n```')).toEqual({
      ok: true,
    });
    expect(extractJsonObject('Sure! Here it is: {"ok": true} hope it helps')).toEqual(
      { ok: true },
    );
  });
});

describe("runStructured retry", () => {
  test("recovers when the second attempt returns valid JSON", async () => {
    const runtime = new ScriptedRuntime([
      "I cannot answer in JSON right now.",
      '{"ok": true}',
    ]);
    const parsed = await runStructured({
      runtime,
      request: { prompt: "original", cwd: "/tmp" },
      schema,
      context: "unit test",
    });
    expect(parsed).toEqual({ ok: true });
    expect(runtime.prompts).toHaveLength(2);
    expect(runtime.prompts[0]).toBe("original");
    expect(runtime.prompts[1]).toContain("could not be parsed");
    expect(runtime.prompts[1]).toContain("original");
  });

  test("throws a diagnosable error after the retry", async () => {
    const runtime = new ScriptedRuntime(["garbage one", "garbage two"]);
    await expect(
      runStructured({
        runtime,
        request: { prompt: "original", cwd: "/tmp" },
        schema,
        context: "validating cand_0002 (src/x.py)",
      }),
    ).rejects.toThrow(
      /failed after retry \(validating cand_0002 \(src\/x\.py\)\).*garbage two/us,
    );
    expect(runtime.prompts).toHaveLength(2);
  });
});
