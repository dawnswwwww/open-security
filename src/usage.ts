/**
 * Scan usage accounting. Every pipeline phase routes its agent runs through a
 * metered runtime wrapper, so token consumption, runtime-reported cost, and
 * wall-clock agent time are aggregated per phase and for the whole scan —
 * independent of which runtime (pi, acp, custom) is configured.
 *
 * What is available differs per runtime: pi reports tokens and cache tokens
 * (cost is unknowable because gateway pricing is not registered); acp reports
 * nothing (the protocol has no usage notification), so only run counts and
 * durations are recorded.
 */
import type {
  AgentRunRequest,
  AgentRunResult,
  AgentRuntime,
  TokenUsage,
} from "./runtime/types.js";

/** Aggregated usage numbers; token fields are 0 when the runtime cannot report them. */
export interface UsageTotals {
  /** Metered agent runs. */
  runs: number;
  /** Wall-clock milliseconds across metered runtime.run() calls. */
  durationMs: number;
  inputTokens: number;
  outputTokens: number;
  cacheReadTokens: number;
  cacheWriteTokens: number;
  /** Present only when at least one metered run reported a cost. */
  costUSD?: number;
  /** Present only when at least one metered run reported its turn count. */
  turns?: number;
}

export type ScanPhaseKind = "threat-model" | "discovery" | "validation";

export interface ScanPhaseUsage extends UsageTotals {
  phase: ScanPhaseKind;
  /** threat-model only: loaded from cache, so no model call was made. */
  cached?: boolean;
}

export interface ScanUsage {
  documentType: "open-security.usage";
  schemaVersion: "1.0";
  scanId: string;
  runtime: string;
  /** false when no metered run reported token usage (e.g. the acp runtime). */
  tokensReported: boolean;
  totals: UsageTotals;
  phases: ScanPhaseUsage[];
}

class UsageMeterState {
  runs = 0;
  durationMs = 0;
  inputTokens = 0;
  outputTokens = 0;
  cacheReadTokens = 0;
  cacheWriteTokens = 0;
  costUSD = 0;
  turns = 0;
  reportedTokens = false;
  reportedCost = false;
  reportedTurns = false;

  record(usage: TokenUsage | undefined, durationMs: number): void {
    this.runs += 1;
    this.durationMs += durationMs;
    if (usage === undefined) return;
    this.reportedTokens = true;
    this.inputTokens += usage.inputTokens;
    this.outputTokens += usage.outputTokens;
    this.cacheReadTokens += usage.cacheReadTokens ?? 0;
    this.cacheWriteTokens += usage.cacheWriteTokens ?? 0;
    if (usage.costUSD !== undefined) {
      this.reportedCost = true;
      this.costUSD += usage.costUSD;
    }
    if (usage.turns !== undefined) {
      this.reportedTurns = true;
      this.turns += usage.turns;
    }
  }

  snapshot(): UsageTotals {
    return {
      runs: this.runs,
      durationMs: this.durationMs,
      inputTokens: this.inputTokens,
      outputTokens: this.outputTokens,
      cacheReadTokens: this.cacheReadTokens,
      cacheWriteTokens: this.cacheWriteTokens,
      ...(this.reportedCost ? { costUSD: this.costUSD } : {}),
      ...(this.reportedTurns ? { turns: this.turns } : {}),
    };
  }
}

/** Runtime wrapper that records every completed run into the meter. */
class MeteredRuntime implements AgentRuntime {
  public readonly kind: string;
  readonly #inner: AgentRuntime;
  readonly #state: UsageMeterState;

  public constructor(inner: AgentRuntime, state: UsageMeterState) {
    this.kind = inner.kind;
    this.#inner = inner;
    this.#state = state;
  }

  public async run(request: AgentRunRequest): Promise<AgentRunResult> {
    const startedAt = Date.now();
    const result = await this.#inner.run(request);
    this.#state.record(result.usage, Date.now() - startedAt);
    return result;
  }
}

/**
 * Wraps an AgentRuntime: pass `meter.runtime` to the pipeline phases, take a
 * `snapshot()` before and after a phase, and diff them with `phaseUsage()`.
 */
export class UsageMeter {
  readonly runtime: AgentRuntime;
  readonly #state = new UsageMeterState();

  public constructor(inner: AgentRuntime) {
    this.runtime = new MeteredRuntime(inner, this.#state);
  }

  public snapshot(): UsageTotals {
    return this.#state.snapshot();
  }

  /** Difference between two snapshots, labelled with the phase it covered. */
  public phaseUsage(
    before: UsageTotals,
    phase: ScanPhaseKind,
    cached = false,
  ): ScanPhaseUsage {
    return {
      phase,
      ...(phase === "threat-model" && cached ? { cached: true } : {}),
      ...this.delta(before),
    };
  }

  public buildScanUsage(input: {
    scanId: string;
    runtime: string;
    totals: UsageTotals;
    phases: readonly ScanPhaseUsage[];
  }): ScanUsage {
    return {
      documentType: "open-security.usage",
      schemaVersion: "1.0",
      scanId: input.scanId,
      runtime: input.runtime,
      tokensReported: this.#state.reportedTokens,
      totals: input.totals,
      phases: [...input.phases],
    };
  }

  private delta(before: UsageTotals): UsageTotals {
    const after = this.snapshot();
    return {
      runs: after.runs - before.runs,
      durationMs: after.durationMs - before.durationMs,
      inputTokens: after.inputTokens - before.inputTokens,
      outputTokens: after.outputTokens - before.outputTokens,
      cacheReadTokens: after.cacheReadTokens - before.cacheReadTokens,
      cacheWriteTokens: after.cacheWriteTokens - before.cacheWriteTokens,
      ...(after.costUSD === undefined
        ? {}
        : { costUSD: after.costUSD - (before.costUSD ?? 0) }),
      ...(after.turns === undefined
        ? {}
        : { turns: after.turns - (before.turns ?? 0) }),
    };
  }
}

const NUMBER = new Intl.NumberFormat("en-US");

export function formatDuration(milliseconds: number): string {
  const totalSeconds = Math.round(milliseconds / 1000);
  if (totalSeconds < 60) return `${totalSeconds}s`;
  const minutes = Math.floor(totalSeconds / 60);
  if (minutes < 60) {
    return `${minutes}m${String(totalSeconds % 60).padStart(2, "0")}s`;
  }
  return `${Math.floor(minutes / 60)}h${String(minutes % 60).padStart(2, "0")}m`;
}

function tokenSummary(totals: UsageTotals): string {
  const parts = [
    `${NUMBER.format(totals.inputTokens)} in / ${NUMBER.format(totals.outputTokens)} out`,
  ];
  if (totals.cacheReadTokens > 0 || totals.cacheWriteTokens > 0) {
    parts.push(
      `cache ${NUMBER.format(totals.cacheReadTokens)}r/${NUMBER.format(totals.cacheWriteTokens)}w`,
    );
  }
  return parts.join(", ");
}

function phaseLine(phase: ScanPhaseUsage, tokensReported: boolean): string {
  const label = phase.phase.padEnd(12, " ");
  const details = [
    formatDuration(phase.durationMs),
    `${phase.runs} run${phase.runs === 1 ? "" : "s"}`,
  ];
  if (tokensReported) details.push(tokenSummary(phase));
  if (phase.costUSD !== undefined) details.push(`$${phase.costUSD.toFixed(2)}`);
  if (phase.turns !== undefined) details.push(`${phase.turns} turns`);
  return `  ${label} ${details.join(" · ")}`;
}

/**
 * Human-readable usage report for stderr. `wallDurationMs` is the whole scan's
 * wall time (meter durations cover agent calls only).
 */
export function renderUsageReport(
  usage: ScanUsage,
  wallDurationMs: number,
): string[] {
  const head = [
    formatDuration(wallDurationMs),
    `${usage.totals.runs} agent run${usage.totals.runs === 1 ? "" : "s"}`,
  ];
  if (usage.tokensReported) head.push(tokenSummary(usage.totals));
  if (usage.totals.costUSD !== undefined) {
    head.push(`$${usage.totals.costUSD.toFixed(2)}`);
  }
  if (usage.totals.turns !== undefined) {
    head.push(`${NUMBER.format(usage.totals.turns)} turns`);
  }
  const lines = [`Usage: ${head.join(" · ")}`];
  if (!usage.tokensReported) {
    lines.push(
      `  (the ${usage.runtime} runtime does not report token usage; runs and durations only)`,
    );
  }
  for (const phase of usage.phases) {
    if (phase.cached === true) {
      lines.push(
        `  ${phase.phase.padEnd(12, " ")} cached (no model call)`,
      );
      continue;
    }
    lines.push(phaseLine(phase, usage.tokensReported));
  }
  return lines;
}
