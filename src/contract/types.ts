import { z } from "zod";
import { SeverityLevels } from "../config.js";

/**
 * Output contract, structurally adapted from the reference methodology's
 * scan contract (Apache-2.0, see NOTICE) and re-branded for open-security.
 */

export const severitySchema = z.object({
  level: z.enum(SeverityLevels),
  rationale: z.string().optional(),
});

export const confidenceSchema = z.object({
  level: z.enum(["high", "medium", "low"]),
  rationale: z.string().min(1),
});

export const locationSchema = z.object({
  path: z.string().min(1),
  startLine: z.number().int().positive(),
  endLine: z.number().int().positive().optional(),
  role: z.string().optional(),
});

export const findingSchema = z.object({
  findingId: z.string().regex(/^osf_[a-f0-9]{24}$/u),
  ruleId: z.string().regex(/^[a-z0-9][a-z0-9._/-]*$/u),
  fingerprints: z.object({
    algorithm: z.literal("open-security/v1"),
    primary: z.string().regex(/^open-security\/v1:sha256:[a-f0-9]{64}$/u),
  }),
  title: z.string().min(1),
  summary: z.string().min(1),
  severity: severitySchema,
  confidence: confidenceSchema,
  taxonomy: z.object({
    category: z.string().min(1),
    cwe: z.array(z.string()),
  }),
  locations: z.array(locationSchema).min(1),
  rootCause: z.string().optional(),
  remediation: z.string().min(1),
  validation: z
    .object({
      method: z.string(),
      summary: z.string(),
      survives: z.enum(["yes", "no", "uncertain"]),
      counterevidence: z.string(),
      proofGaps: z.array(z.string()),
    })
    .nullable(),
  attackPath: z
    .object({
      source: z.string(),
      sink: z.string(),
      dataflow: z.string(),
      vector: z.string(),
      likelihood: z.string(),
      impact: z.string(),
    })
    .nullable(),
  provenance: z.object({ source: z.string().min(1) }),
  priority: z.enum(["P0", "P1", "P2", "P3"]).nullable(),
});

export const findingsDocumentSchema = z.object({
  documentType: z.literal("open-security.findings"),
  schemaVersion: z.literal("1.0"),
  scanId: z.string().min(1),
  findings: z.array(findingSchema),
});

export const manifestSchema = z.object({
  documentType: z.literal("open-security.scan-manifest"),
  schemaVersion: z.literal("1.0"),
  scan: z.object({
    id: z.string().min(1),
    producer: z.object({ name: z.string(), version: z.string() }),
    status: z.literal("completed"),
    startedAt: z.string().datetime(),
    completedAt: z.string().datetime(),
    target: z.object({
      kind: z.enum(["git_diff", "git_worktree", "git_revision", "directory_snapshot"]),
      targetId: z.string().min(1),
      displayName: z.string().min(1),
      remote: z.string().optional(),
      baseRevision: z.string().optional(),
      headRevision: z.string().optional(),
      snapshotDigest: z.string().optional(),
    }),
    scope: z.object({
      includePaths: z.array(z.string()),
      excludePaths: z.array(z.string()),
      summary: z.string().optional(),
    }),
    coverageRef: z.literal("coverage.json"),
    findingsRef: z.literal("findings.json"),
    threatModel: z
      .object({
        summary: z.string(),
        assets: z.array(z.string()).optional(),
        trustBoundaries: z.array(z.string()).optional(),
        attackerCapabilities: z.array(z.string()).optional(),
        securityObjectives: z.array(z.string()).optional(),
        assumptions: z.array(z.string()).optional(),
      })
      .optional(),
  }),
});

export const surfaceSchema = z.object({
  id: z.string().min(1),
  label: z.string().min(1),
  disposition: z.enum([
    "reported",
    "no_issue_found",
    "rejected",
    "not_applicable",
    "needs_follow_up",
  ]),
  riskArea: z.string().optional(),
  notes: z.string().optional(),
});

export const coverageDocumentSchema = z.object({
  documentType: z.literal("open-security.coverage"),
  schemaVersion: z.literal("1.0"),
  scanId: z.string().min(1),
  mode: z.enum(["diff", "commit", "branch_diff", "working_tree", "repository"]),
  completeness: z.enum(["complete", "partial", "unknown"]),
  inventoryStrategy: z.enum(["diff", "repository", "directory"]),
  includePaths: z.array(z.string()),
  excludePaths: z.array(z.string()),
  surfaces: z.array(surfaceSchema),
  explicitExclusions: z.array(
    z.object({ pattern: z.string(), reason: z.string() }),
  ),
  deferred: z.array(
    z.object({
      id: z.string(),
      reason: z.string(),
      paths: z.array(z.string()).optional(),
    }),
  ),
  openQuestions: z
    .array(z.object({ question: z.string() }))
    .optional(),
});

export type Finding = z.infer<typeof findingSchema>;
export type FindingsDocument = z.infer<typeof findingsDocumentSchema>;
export type ScanManifest = z.infer<typeof manifestSchema>;
export type CoverageDocument = z.infer<typeof coverageDocumentSchema>;
export type CoverageSurface = z.infer<typeof surfaceSchema>;
