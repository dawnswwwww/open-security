import { describe, expect, test } from "vitest";
import { inferRuntimeKind } from "../src/config.js";

describe("inferRuntimeKind", () => {
  test("keeps bare invocations on the zero-config claude-agent path", () => {
    expect(inferRuntimeKind(undefined)).toBe("claude-agent");
  });

  test("auto-selects pi for non-Anthropic base URLs", () => {
    expect(inferRuntimeKind("https://api.deepseek.com/v1")).toBe("pi");
    expect(inferRuntimeKind("https://api.openai.com/v1")).toBe("pi");
    expect(inferRuntimeKind("http://localhost:11434/v1")).toBe("pi");
    expect(inferRuntimeKind("https://llm-gateway.internal/v1")).toBe("pi");
  });

  test("keeps Anthropic-looking base URLs on claude-agent", () => {
    expect(inferRuntimeKind("https://api.anthropic.com")).toBe("claude-agent");
    expect(inferRuntimeKind("https://claude-gateway.internal")).toBe(
      "claude-agent",
    );
  });

  test("an explicit protocol always selects pi", () => {
    expect(inferRuntimeKind("https://api.anthropic.com", "anthropic-messages")).toBe("pi");
    expect(inferRuntimeKind(undefined, "openai-completions")).toBe("pi");
  });
});
