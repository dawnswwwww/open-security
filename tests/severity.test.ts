import { describe, expect, test } from "vitest";
import { assessSeverity } from "../src/pipeline/severity.js";
import type { ValidatedCandidate } from "../src/pipeline/validation.js";
import type { Candidate } from "../src/pipeline/discovery.js";

function candidate(overrides: Partial<Candidate> = {}): Candidate {
  return {
    id: "cand_0001",
    title: "Unsafe archive extraction",
    path: "src/extract.py",
    startLine: 41,
    endLine: 44,
    category: "path-traversal",
    cwe: ["CWE-22"],
    attackerSource: "archive entry name",
    sinkOrBrokenControl: "filesystem write without containment",
    closestControl: "none found",
    impact: "arbitrary file write",
    whyPlausible: "direct source-to-sink trace",
    relevantLines: [41],
    supportingPaths: [],
    ...overrides,
  };
}

function verdict(overrides: Record<string, unknown>): ValidatedCandidate {
  return {
    candidate: candidate(),
    verdict: {
      disposition: "reportable",
      survives: "yes",
      method: "static",
      summary: "Direct trace.",
      source: "user",
      control: "none",
      sink: "write",
      dataflow: "direct",
      counterevidence: "none found",
      proofGaps: [],
      confidence: "high",
      confidenceRationale: "full chain",
      vector: "remote",
      preconditions: "plausible",
      attackerInputControl: "yes",
      authScope: "public",
      impact: "high",
      ...overrides,
    },
  } as ValidatedCandidate;
}

describe("severity calibration matrix", () => {
  test("remote plausible high impact with full input control reaches critical", () => {
    const assessment = assessSeverity(verdict({}));
    expect(assessment.severity).toBe("critical");
    expect(assessment.priority).toBe("P0");
    expect(assessment.policyDecision).toBe("report");
  });

  test("high impact with capped input control lands at medium", () => {
    const assessment = assessSeverity(verdict({ attackerInputControl: "plausible" }));
    expect(assessment.severity).toBe("medium");
    expect(assessment.priority).toBe("P2");
  });

  test("medium impact remote caps at medium", () => {
    const assessment = assessSeverity(verdict({ impact: "medium" }));
    expect(assessment.severity).toBe("medium");
  });

  test("local_network vector yields at most medium likelihood", () => {
    const assessment = assessSeverity(verdict({ vector: "local_network" }));
    expect(assessment.severity).toBe("medium");
  });

  test("localhost vector yields low severity for high impact", () => {
    const assessment = assessSeverity(verdict({ vector: "localhost" }));
    expect(assessment.severity).toBe("low");
  });

  test("no attacker input control hard-suppresses to ignore", () => {
    const assessment = assessSeverity(verdict({ attackerInputControl: "no" }));
    expect(assessment.policyDecision).toBe("ignore");
    expect(assessment.priority).toBeNull();
    expect(assessment.severity).toBe("informational");
  });

  test("rejected validation hard-suppresses to ignore", () => {
    const assessment = assessSeverity(
      verdict({ survives: "no", disposition: "suppressed" }),
    );
    expect(assessment.policyDecision).toBe("ignore");
  });

  test("unachievable preconditions hard-suppress to ignore", () => {
    const assessment = assessSeverity(verdict({ preconditions: "unachievable" }));
    expect(assessment.policyDecision).toBe("ignore");
  });

  test("ignore impact suppresses regardless of vector", () => {
    const assessment = assessSeverity(verdict({ impact: "ignore" }));
    expect(assessment.policyDecision).toBe("ignore");
  });

  test("unknown impact with remote vector lands at medium", () => {
    const assessment = assessSeverity(verdict({ impact: "unknown" }));
    expect(assessment.severity).toBe("medium");
  });

  test("unlikely preconditions cap high likelihood to medium severity", () => {
    const assessment = assessSeverity(verdict({ preconditions: "unlikely" }));
    expect(assessment.severity).toBe("medium");
  });
});
