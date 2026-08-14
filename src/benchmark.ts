import { readFile } from "node:fs/promises";
import { z } from "zod";
import { OpenSecurity, type ScanResult } from "./index.js";
import type { Finding } from "./contract/types.js";
import { meetsFailThreshold } from "./config.js";
import { VERSION } from "./version.js";

/**
 * Quality benchmark harness (plan milestone 6): runs the scanner against
 * repositories with known ground-truth findings and computes recall and
 * precision. The harness mechanics are covered by tests with a mock runtime;
 * the actual quality numbers require a real model and are meant to be run
 * against an internal endpoint before relying on the scanner in CI.
 */

export const expectedFindingSchema = z.object({
  /** Ground truth rule/category, matched case-insensitively on slug form. */
  category: z.string().min(1),
  /** Repository-relative path of the primary location. */
  path: z.string().min(1),
  /** Optional minimum severity the finding should reach (inclusive). */
  minSeverity: z
    .enum(["critical", "high", "medium", "low", "informational"])
    .optional(),
  /** Free-form description of the known vulnerability. */
  note: z.string().optional(),
});

export const benchmarkCaseSchema = z.object({
  name: z.string().min(1),
  repository: z.string().min(1),
  base: z.string().min(1),
  head: z.string().min(1).default("HEAD"),
  expected: z.array(expectedFindingSchema).min(1),
});

export const benchmarkSuiteSchema = z.object({
  cases: z.array(benchmarkCaseSchema).min(1),
});

export type ExpectedFinding = z.infer<typeof expectedFindingSchema>;
export type BenchmarkCase = z.infer<typeof benchmarkCaseSchema>;

export interface MatchedPair {
  expected: ExpectedFinding;
  finding: Finding;
}

export interface BenchmarkCaseReport {
  name: string;
  scanId: string;
  expected: number;
  reported: number;
  matched: MatchedPair[];
  missed: ExpectedFinding[];
  unexpected: Finding[];
  recall: number;
  /** Precision over reported findings; 1 when nothing was reported. */
  precision: number;
  error?: string;
}

export interface BenchmarkReport {
  tool: string;
  version: string;
  runtime: string;
  startedAt: string;
  completedAt: string;
  cases: BenchmarkCaseReport[];
  totals: {
    expected: number;
    reported: number;
    matched: number;
    recall: number;
    precision: number;
  };
}

function normalizeCategory(category: string): string {
  return category.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "");
}

function matches(expected: ExpectedFinding, finding: Finding): boolean {
  const location = finding.locations[0];
  if (location === undefined) return false;
  if (location.path !== expected.path) return false;
  if (normalizeCategory(finding.taxonomy.category) !== normalizeCategory(expected.category)) {
    return false;
  }
  if (expected.minSeverity !== undefined) {
    if (!meetsFailThreshold(finding.severity.level, expected.minSeverity)) {
      return false;
    }
  }
  return true;
}

export async function runBenchmark(options: {
  scanner: OpenSecurity;
  cases: readonly BenchmarkCase[];
  outputRoot: string;
  signal?: AbortSignal;
}): Promise<BenchmarkReport> {
  const startedAt = new Date();
  const reports: BenchmarkCaseReport[] = [];
  for (const [index, testCase] of options.cases.entries()) {
    let scan: ScanResult;
    try {
      scan = await options.scanner.scanDiff(testCase.repository, {
        base: testCase.base,
        head: testCase.head,
        workingTree: false,
        outputDir: `${options.outputRoot}/case-${index}-${normalizeCategory(testCase.name)}`,
        ...(options.signal === undefined ? {} : { signal: options.signal }),
      });
    } catch (error) {
      reports.push({
        name: testCase.name,
        scanId: "",
        expected: testCase.expected.length,
        reported: 0,
        matched: [],
        missed: [...testCase.expected],
        unexpected: [],
        recall: 0,
        precision: 1,
        error: error instanceof Error ? error.message : String(error),
      });
      continue;
    }
    const document = JSON.parse(
      await readFile(scan.findingsPath, "utf8"),
    ) as { findings: Finding[] };
    reports.push(
      evaluateCase(testCase, document.findings ?? [], scan.scanId),
    );
  }
  const completedAt = new Date();
  const expected = reports.reduce((total, report) => total + report.expected, 0);
  const reported = reports.reduce((total, report) => total + report.reported, 0);
  const matched = reports.reduce((total, report) => total + report.matched.length, 0);
  return {
    tool: "open-security",
    version: VERSION,
    runtime: options.scanner.runtimeKind,
    startedAt: startedAt.toISOString(),
    completedAt: completedAt.toISOString(),
    cases: reports,
    totals: {
      expected,
      reported,
      matched,
      recall: expected === 0 ? 1 : matched / expected,
      precision: reported === 0 ? 1 : matched / reported,
    },
  };
}

export function evaluateCase(
  testCase: BenchmarkCase,
  findings: readonly Finding[],
  scanId: string,
): BenchmarkCaseReport {
  const matched: MatchedPair[] = [];
  const missed: ExpectedFinding[] = [];
  const consumed = new Set<number>();
  for (const expected of testCase.expected) {
    const index = findings.findIndex(
      (finding, position) =>
        !consumed.has(position) && matches(expected, finding),
    );
    if (index === -1) {
      missed.push(expected);
      continue;
    }
    consumed.add(index);
    matched.push({ expected, finding: findings[index]! });
  }
  const unexpected = findings.filter(
    (_finding, position) => !consumed.has(position),
  );
  return {
    name: testCase.name,
    scanId,
    expected: testCase.expected.length,
    reported: findings.length,
    matched,
    missed,
    unexpected,
    recall: testCase.expected.length === 0 ? 1 : matched.length / testCase.expected.length,
    precision: findings.length === 0 ? 1 : matched.length / findings.length,
  };
}

export async function loadBenchmarkSuite(
  path: string,
): Promise<readonly BenchmarkCase[]> {
  const suite = benchmarkSuiteSchema.parse(
    JSON.parse(await readFile(path, "utf8")),
  );
  return suite.cases;
}
