import { describe, expect, test } from "vitest";
import {
  formatDuration,
  renderUsageReport,
  UsageMeter,
  type ScanUsage,
} from "../src/usage.js";
import type {
  AgentRunRequest,
  AgentRuntime,
  AgentRunResult,
  TokenUsage,
} from "../src/runtime/types.js";

/** Scripted runtime: returns the given usage per run, in order. */
class ScriptedRuntime implements AgentRuntime {
  public readonly kind = "scripted";
  public readonly requests: AgentRunRequest[] = [];

  public constructor(private readonly usage: (TokenUsage | undefined)[]) {}

  public async run(request: AgentRunRequest): Promise<AgentRunResult> {
    this.requests.push(request);
    const usage = this.usage.shift();
    return { text: "ok", ...(usage === undefined ? {} : { usage }) };
  }
}

function totals(overrides: Partial<ScanUsage["totals"]> = {}): ScanUsage["totals"] {
  return {
    runs: 0,
    durationMs: 0,
    inputTokens: 0,
    outputTokens: 0,
    cacheReadTokens: 0,
    cacheWriteTokens: 0,
    ...overrides,
  };
}

describe("UsageMeter", () => {
  test("aggregates usage across runs", async () => {
    const meter = new UsageMeter(
      new ScriptedRuntime([
        { inputTokens: 100, outputTokens: 10, cacheReadTokens: 5, costUSD: 0.5, turns: 3 },
        { inputTokens: 50, outputTokens: 5 },
      ]),
    );
    await meter.runtime.run({ prompt: "a", cwd: "." });
    await meter.runtime.run({ prompt: "b", cwd: "." });
    expect(meter.snapshot()).toEqual(
      totals({
        runs: 2,
        inputTokens: 150,
        outputTokens: 15,
        cacheReadTokens: 5,
        costUSD: 0.5,
        turns: 3,
      }),
    );
    expect(meter.snapshot().durationMs).toBeGreaterThanOrEqual(0);
  });

  test("phaseUsage reports the delta since a snapshot and keeps the kind", async () => {
    const meter = new UsageMeter(
      new ScriptedRuntime([
        { inputTokens: 100, outputTokens: 10 },
        { inputTokens: 1, outputTokens: 1, costUSD: 0.25 },
      ]),
    );
    await meter.runtime.run({ prompt: "threat", cwd: "." });
    const before = meter.snapshot();
    await meter.runtime.run({ prompt: "discovery", cwd: "." });
    expect(meter.phaseUsage(before, "discovery")).toEqual({
      phase: "discovery",
      runs: 1,
      durationMs: expect.any(Number),
      inputTokens: 1,
      outputTokens: 1,
      cacheReadTokens: 0,
      cacheWriteTokens: 0,
      costUSD: 0.25,
    });
  });

  test("omits cost and turns when no run reported them", async () => {
    const meter = new UsageMeter(
      new ScriptedRuntime([{ inputTokens: 1, outputTokens: 1 }]),
    );
    await meter.runtime.run({ prompt: "a", cwd: "." });
    const snapshot = meter.snapshot();
    expect(snapshot.costUSD).toBeUndefined();
    expect(snapshot.turns).toBeUndefined();
  });

  test("marks the threat-model phase cached and drops token fields", async () => {
    const meter = new UsageMeter(new ScriptedRuntime([]));
    const before = meter.snapshot();
    const phase = meter.phaseUsage(before, "threat-model", true);
    expect(phase.cached).toBe(true);
    expect(phase.runs).toBe(0);
  });

  test("tokensReported is false when the runtime never reports usage", async () => {
    const meter = new UsageMeter(new ScriptedRuntime([undefined, undefined]));
    await meter.runtime.run({ prompt: "a", cwd: "." });
    await meter.runtime.run({ prompt: "b", cwd: "." });
    const usage = meter.buildScanUsage({
      scanId: "scan-1",
      runtime: "acp",
      totals: meter.snapshot(),
      phases: [],
    });
    expect(usage.tokensReported).toBe(false);
    expect(usage.totals.runs).toBe(2);
    expect(usage.totals.inputTokens).toBe(0);
  });
});

describe("renderUsageReport", () => {
  test("renders totals, phases, cost, and turns", () => {
    const usage: ScanUsage = {
      documentType: "open-security.usage",
      schemaVersion: "1.0",
      scanId: "scan-1",
      runtime: "pi",
      tokensReported: true,
      totals: totals({
        runs: 6,
        inputTokens: 1_234_567,
        outputTokens: 45_678,
        cacheReadTokens: 200_000,
        cacheWriteTokens: 100_000,
        costUSD: 12.5,
        turns: 90,
      }),
      phases: [
        {
          phase: "threat-model",
          ...totals({ runs: 1, inputTokens: 400_000, outputTokens: 20_000 }),
        },
        {
          phase: "discovery",
          ...totals({ runs: 2, inputTokens: 600_000, outputTokens: 15_678 }),
        },
        {
          phase: "validation",
          ...totals({
            runs: 3,
            inputTokens: 234_567,
            outputTokens: 10_000,
            cacheReadTokens: 200_000,
            cacheWriteTokens: 100_000,
            costUSD: 12.5,
            turns: 90,
          }),
        },
      ],
    };
    const lines = renderUsageReport(usage, 252_000);
    expect(lines[0]).toBe(
      "Usage: 4m12s · 6 agent runs · 1,234,567 in / 45,678 out, cache 200,000r/100,000w · $12.50 · 90 turns",
    );
    expect(lines[1]).toBe(
      "  threat-model 0s · 1 run · 400,000 in / 20,000 out",
    );
    expect(lines[2]).toBe(
      "  discovery    0s · 2 runs · 600,000 in / 15,678 out",
    );
    expect(lines[3]).toBe(
      "  validation   0s · 3 runs · 234,567 in / 10,000 out, cache 200,000r/100,000w · $12.50 · 90 turns",
    );
  });

  test("notes runtimes without usage reporting and cached phases", () => {
    const usage: ScanUsage = {
      documentType: "open-security.usage",
      schemaVersion: "1.0",
      scanId: "scan-1",
      runtime: "acp",
      tokensReported: false,
      totals: totals({ runs: 2 }),
      phases: [
        { phase: "threat-model", cached: true, ...totals() },
        { phase: "discovery", ...totals({ runs: 2 }) },
      ],
    };
    const lines = renderUsageReport(usage, 90_000);
    expect(lines[0]).toBe("Usage: 1m30s · 2 agent runs");
    expect(lines[1]).toBe(
      "  (the acp runtime does not report token usage; runs and durations only)",
    );
    expect(lines[2]).toBe("  threat-model cached (no model call)");
    expect(lines[3]).toBe("  discovery    0s · 2 runs");
  });
});

describe("formatDuration", () => {
  test("formats seconds, minutes, and hours", () => {
    expect(formatDuration(0)).toBe("0s");
    expect(formatDuration(59_400)).toBe("59s");
    expect(formatDuration(60_000)).toBe("1m00s");
    expect(formatDuration(252_000)).toBe("4m12s");
    expect(formatDuration(3_600_000)).toBe("1h00m");
  });
});
