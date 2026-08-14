import type { SeverityLevel } from "../config.js";
import type { Verdict, ValidatedCandidate } from "./validation.js";

/**
 * Mechanical severity calibration, ported from the reference methodology's
 * severity-policy (Apache-2.0, see NOTICE). This is deliberately pure code,
 * not a model decision: the final policy adjustment must be applied
 * mechanically rather than re-argued per finding.
 */

export type Likelihood = "high" | "medium" | "low" | "ignore" | "unknown";
export type PolicyDecision = "report" | "ignore";

export interface SeverityAssessment {
  severity: SeverityLevel;
  likelihood: Likelihood;
  policyDecision: PolicyDecision;
  priority: "P0" | "P1" | "P2" | "P3" | null;
  rationale: string;
}

const VECTOR_LIKELIHOOD: Record<Verdict["vector"], Likelihood> = {
  remote: "high",
  local_network: "medium",
  localhost: "low",
  none: "low",
  unknown: "unknown",
};

/**
 * Hard suppression: no attacker-controlled input, unachievable
 * preconditions, a rejected validation, or an impact that is not a security
 * issue at all.
 */
function isHardSuppressed(verdict: Verdict): boolean {
  return (
    verdict.impact === "ignore" ||
    verdict.preconditions === "unachievable" ||
    verdict.attackerInputControl === "no" ||
    verdict.survives === "no"
  );
}

function calibratedSeverity(
  impact: Verdict["impact"],
  likelihood: Likelihood,
  remote: boolean,
  plausible: boolean,
): SeverityLevel {
  if (impact === "ignore") return "informational";
  if (likelihood === "ignore") return "informational";
  if (impact === "high") {
    if (likelihood === "high") {
      // Critical is reserved for a clear, remotely plausible
      // compromise-equivalent path; otherwise the finding stays high.
      return remote && plausible ? "critical" : "high";
    }
    if (likelihood === "unknown") return "medium";
    return likelihood === "medium" ? "medium" : "low";
  }
  if (impact === "medium") {
    if (likelihood === "high") return "medium";
    return likelihood === "unknown" ? "low" : "low";
  }
  if (impact === "low") return "low";
  // impact === "unknown"
  if (likelihood === "high") return "medium";
  return "low";
}

const PRIORITY: Record<Exclude<SeverityLevel, "informational">, "P0" | "P1" | "P2" | "P3"> = {
  critical: "P0",
  high: "P1",
  medium: "P2",
  low: "P3",
};

export function assessSeverity(entry: ValidatedCandidate): SeverityAssessment {
  const { verdict } = entry;
  if (isHardSuppressed(verdict)) {
    return {
      severity: "informational",
      likelihood: "ignore",
      policyDecision: "ignore",
      priority: null,
      rationale: `Policy suppression: impact=${verdict.impact}, preconditions=${verdict.preconditions}, attackerInputControl=${verdict.attackerInputControl}, survives=${verdict.survives}.`,
    };
  }
  let likelihood = VECTOR_LIKELIHOOD[verdict.vector];
  if (verdict.attackerInputControl === "plausible" && likelihood === "high") {
    // Plausible-but-unconfirmed input control caps likelihood one notch.
    likelihood = "medium";
  }
  if (verdict.preconditions === "unlikely" && likelihood === "high") {
    likelihood = "medium";
  }
  const severity = calibratedSeverity(
    verdict.impact,
    likelihood,
    verdict.vector === "remote",
    verdict.preconditions === "plausible",
  );
  if (severity === "informational") {
    return {
      severity,
      likelihood,
      policyDecision: "ignore",
      priority: null,
      rationale: `Calibration matrix result: impact=${verdict.impact}, likelihood=${likelihood}.`,
    };
  }
  return {
    severity,
    likelihood,
    policyDecision: "report",
    priority: PRIORITY[severity],
    rationale:
      `impact=${verdict.impact}, likelihood=${likelihood} (vector=${verdict.vector}, ` +
      `preconditions=${verdict.preconditions}, inputControl=${verdict.attackerInputControl}, ` +
      `authScope=${verdict.authScope}); matrix severity=${severity}.`,
  };
}
