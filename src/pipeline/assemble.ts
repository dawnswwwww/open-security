import type { ScanInventory } from "./inventory.js";
import type { ValidatedCandidate } from "./validation.js";
import type { SeverityAssessment } from "./severity.js";
import { assessSeverity } from "./severity.js";
import type {
  CoverageDocument,
  CoverageSurface,
  Finding,
  FindingsDocument,
  ScanManifest,
} from "../contract/types.js";
import {
  anchorFor,
  findingIdFrom,
  primaryFingerprint,
} from "../contract/identity.js";
import type { ThreatModel } from "./threat-model.js";

export interface AssembleInput {
  scanId: string;
  startedAt: Date;
  completedAt: Date;
  targetId: string;
  displayName: string;
  remote?: string;
  baseRevision?: string;
  headRevision?: string;
  workingTree: boolean;
  origin: "diff" | "repository";
  inventory: ScanInventory;
  threatModel: ThreatModel;
  validated: readonly ValidatedCandidate[];
  producer: { name: string; version: string };
}

export interface AssembleResult {
  manifest: ScanManifest;
  findings: FindingsDocument;
  coverage: CoverageDocument;
  /** The raw per-candidate assessments, keyed by candidate id. */
  assessments: Map<string, SeverityAssessment>;
}

export function assemble(input: AssembleInput): AssembleResult {
  const assessments = new Map<string, SeverityAssessment>();
  const findings: Finding[] = [];
  const surfaces: CoverageSurface[] = [];
  const deferred: CoverageDocument["deferred"] = [];

  for (const entry of input.validated) {
    const assessment = assessSeverity(entry);
    assessments.set(entry.candidate.id, assessment);
    const surfaceDisposition = surfaceDispositionFor(entry, assessment);
    surfaces.push({
      id: `surface_${entry.candidate.id}`,
      label: `${entry.candidate.path} — ${entry.candidate.title}`,
      disposition: surfaceDisposition,
      riskArea: entry.candidate.category,
      notes: `disposition=${entry.verdict.disposition}, survives=${entry.verdict.survives}`,
    });
    if (assessment.policyDecision === "ignore") continue;
    if (entry.verdict.disposition === "deferred") {
      deferred.push({
        id: entry.candidate.id,
        reason: entry.verdict.summary,
        paths: [entry.candidate.path],
      });
      continue;
    }
    findings.push(toFinding(input, entry, assessment));
  }

  for (const notReviewed of input.inventory.deferredNotReviewed ?? []) {
    deferred.push({
      id: `deferred_rank_${deferred.length + 1}`,
      reason: "Ranked below the repository-scan review cap; not reviewed.",
      paths: [notReviewed],
    });
  }

  for (const file of input.inventory.files) {
    surfaces.push({
      id: `surface_file_${file.path.replace(/[^a-z0-9]+/giu, "_")}`,
      label: file.path,
      disposition: "no_issue_found",
    });
  }

  const completeness: CoverageDocument["completeness"] =
    deferred.length > 0 || (input.inventory.deferredNotReviewed?.length ?? 0) > 0
      ? "partial"
      : "complete";

  const manifest: ScanManifest = {
    documentType: "open-security.scan-manifest",
    schemaVersion: "1.0",
    scan: {
      id: input.scanId,
      producer: input.producer,
      status: "completed",
      startedAt: input.startedAt.toISOString(),
      completedAt: input.completedAt.toISOString(),
      target: {
        kind:
          input.origin === "repository"
            ? "git_revision"
            : input.workingTree
              ? "git_worktree"
              : "git_diff",
        targetId: input.targetId,
        displayName: input.displayName,
        ...(input.remote === undefined ? {} : { remote: input.remote }),
        ...(input.origin === "repository" || input.baseRevision === undefined
          ? {}
          : { baseRevision: input.baseRevision }),
        ...(input.headRevision === undefined
          ? {}
          : { headRevision: input.headRevision }),
      },
      scope: {
        includePaths: input.inventory.files.map((file) => file.path),
        excludePaths: input.inventory.excluded,
        summary:
        input.origin === "repository"
          ? `Repository scan: ${input.inventory.files.length} ranked file(s) deep-reviewed${input.inventory.deferredNotReviewed?.length ? `, ${input.inventory.deferredNotReviewed.length} ranked out (deferred)` : ""}.`
          : `Diff scan: ${input.inventory.files.length} changed file(s) reviewed.`,
      },
      coverageRef: "coverage.json",
      findingsRef: "findings.json",
      threatModel: {
        summary: input.threatModel.summary,
        ...(input.threatModel.assets.length === 0
          ? {}
          : { assets: input.threatModel.assets }),
        ...(input.threatModel.trustBoundaries.length === 0
          ? {}
          : { trustBoundaries: input.threatModel.trustBoundaries }),
        ...(input.threatModel.attackerCapabilities.length === 0
          ? {}
          : { attackerCapabilities: input.threatModel.attackerCapabilities }),
        ...(input.threatModel.securityObjectives.length === 0
          ? {}
          : { securityObjectives: input.threatModel.securityObjectives }),
        ...(input.threatModel.assumptions.length === 0
          ? {}
          : { assumptions: input.threatModel.assumptions }),
      },
    },
  };

  const findingsDocument: FindingsDocument = {
    documentType: "open-security.findings",
    schemaVersion: "1.0",
    scanId: input.scanId,
    findings,
  };

  const coverage: CoverageDocument = {
    documentType: "open-security.coverage",
    schemaVersion: "1.0",
    scanId: input.scanId,
    mode:
      input.origin === "repository"
        ? "repository"
        : input.workingTree
          ? "working_tree"
          : "diff",
    completeness,
    inventoryStrategy: input.origin,
    includePaths: input.inventory.files.map((file) => file.path),
    excludePaths: input.inventory.excluded,
    surfaces,
    explicitExclusions: [],
    deferred,
  };

  return { manifest, findings: findingsDocument, coverage, assessments };
}

function surfaceDispositionFor(
  entry: ValidatedCandidate,
  assessment: SeverityAssessment,
): CoverageSurface["disposition"] {
  if (assessment.policyDecision === "report") return "reported";
  if (entry.verdict.disposition === "deferred") return "needs_follow_up";
  if (entry.verdict.disposition === "suppressed") return "rejected";
  if (entry.verdict.disposition === "not_applicable") return "not_applicable";
  return "rejected";
}

function toFinding(
  input: AssembleInput,
  entry: ValidatedCandidate,
  assessment: SeverityAssessment,
): Finding {
  const { candidate, verdict } = entry;
  const ruleId = normalizeRuleId(candidate.category);
  const anchor = anchorFor(ruleId, candidate.path, candidate.title);
  const primary = primaryFingerprint(input.targetId, ruleId, anchor, "1");
  return {
    findingId: findingIdFrom(primary),
    ruleId,
    fingerprints: { algorithm: "open-security/v1", primary },
    title: candidate.title,
    summary: candidate.impact,
    severity: {
      level: assessment.severity,
      rationale: assessment.rationale,
    },
    confidence: {
      level: verdict.confidence,
      rationale: verdict.confidenceRationale,
    },
    taxonomy: {
      category: candidate.category,
      cwe: [...candidate.cwe],
    },
    locations: [
      {
        path: candidate.path,
        startLine: candidate.startLine,
        ...(candidate.endLine === null
          ? {}
          : { endLine: candidate.endLine, role: "sink" }),
      },
    ],
    rootCause: `${verdict.control}. ${verdict.summary}`,
    remediation: remediationGuidance(candidate, verdict),
    validation: {
      method: "static",
      summary: verdict.summary,
      survives: verdict.survives,
      counterevidence: verdict.counterevidence,
      proofGaps: [...verdict.proofGaps],
    },
    attackPath: {
      source: verdict.source,
      sink: verdict.sink,
      dataflow: verdict.dataflow,
      vector: verdict.vector,
      likelihood: assessment.likelihood,
      impact: verdict.impact,
    },
    provenance: { source: "open-security diff scan" },
    priority: assessment.priority,
  };
}

function remediationGuidance(
  candidate: ValidatedCandidate["candidate"],
  verdict: ValidatedCandidate["verdict"],
): string {
  const control = verdict.control.trim();
  if (control.length > 0 && !/^none$/iu.test(control)) {
    return `Fix the control gap at ${candidate.path}: ${control}. Expected: ${verdict.source} must not reach ${verdict.sink} without an effective check.`;
  }
  return `Prevent ${verdict.source} from reaching ${verdict.sink} (${candidate.path}:${candidate.startLine}) with an explicit allowlist, canonicalization, or authorization check.`;
}

function normalizeRuleId(category: string): string {
  const normalized = category
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "");
  return normalized.length === 0 ? "security-issue" : normalized;
}
