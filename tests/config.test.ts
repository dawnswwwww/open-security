import { describe, expect, test } from "vitest";
import { inferPiApi } from "../src/config.js";

describe("inferPiApi", () => {
  test("bare invocations default to the Anthropic Messages protocol", () => {
    expect(inferPiApi(undefined)).toBe("anthropic-messages");
  });

  test("non-Anthropic base URLs use the OpenAI completions protocol", () => {
    expect(inferPiApi("https://api.deepseek.com/v1")).toBe("openai-completions");
    expect(inferPiApi("https://api.openai.com/v1")).toBe("openai-completions");
    expect(inferPiApi("http://localhost:11434/v1")).toBe("openai-completions");
    expect(inferPiApi("https://llm-gateway.internal/v1")).toBe(
      "openai-completions",
    );
  });

  test("Anthropic-looking base URLs get the anthropic-messages protocol", () => {
    expect(inferPiApi("https://api.anthropic.com")).toBe("anthropic-messages");
    expect(inferPiApi("https://claude-gateway.internal")).toBe(
      "anthropic-messages",
    );
  });

  test("an explicit protocol always wins over URL inference", () => {
    expect(inferPiApi("https://api.anthropic.com", "openai-completions")).toBe(
      "openai-completions",
    );
    expect(inferPiApi(undefined, "openai-completions")).toBe(
      "openai-completions",
    );
    expect(inferPiApi("https://api.openai.com/v1", "anthropic-messages")).toBe(
      "anthropic-messages",
    );
  });
});
