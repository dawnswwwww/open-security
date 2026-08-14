import { afterAll, describe, expect, test } from "vitest";
import { execFile } from "node:child_process";
import { mkdir, mkdtemp, rm, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";
import { evaluateCase, runBenchmark } from "../src/benchmark.js";
import type { BenchmarkCase } from "../src/benchmark.js";
import type { Finding } from "../src/contract/types.js";
import { OpenSecurity } from "../src/index.js";
import type {
  AgentRunRequest,
  AgentRuntime,
  AgentRunResult,
} from "../src/runtime/types.js";

const execFileAsync = promisify(execFile);
const temporaryDirectories: string[] = [];

afterAll(async () => {
  await Promise.all(
    temporaryDirectories.map((path) => rm(path, { recursive: true, force: true })),
  );
});

function finding(overrides: Partial<Finding> = {}): Finding {
  return {
    findingId: "osf_0000000000000000000000ff",
    ruleId: "path-traversal",
    fingerprints: {
      algorithm: "open-security/v1",
      primary: "open-security/v1:sha256:" + "a".repeat(64),
    },
    title: "Traversal",
    summary: "Escapes output dir",
    severity: { level: "high" },
    confidence: { level: "high", rationale: "chain" },
    taxonomy: { category: "path-traversal", cwe: ["CWE-22"] },
    locations: [{ path: "src/extract.py", startLine: 9 }],
    remediation: "normalize",
    validation: null,
    attackPath: null,
    provenance: { source: "test" },
    priority: "P1",
    ...overrides,
  };
}

describe("evaluateCase metrics", () => {
  const testCase: BenchmarkCase = {
    name: "metrics",
    repository: "/tmp/unused",
    base: "HEAD~1",
    head: "HEAD",
    expected: [
      { category: "path-traversal", path: "src/extract.py" },
      { category: "ssrf", path: "src/fetch.js" },
      { category: "sql-injection", path: "src/db.go", minSeverity: "high" },
    ],
  };

  test("perfect match yields recall and precision of 1", () => {
    const report = evaluateCase(
      testCase,
      [
        finding(),
        finding({
          ruleId: "ssrf",
          taxonomy: { category: "SSRF", cwe: ["CWE-918"] },
          locations: [{ path: "src/fetch.js", startLine: 3 }],
        }),
        finding({
          ruleId: "sql-injection",
          taxonomy: { category: "SQL Injection", cwe: ["CWE-89"] },
          locations: [{ path: "src/db.go", startLine: 7 }],
          severity: { level: "critical" },
        }),
      ],
      "scan_1",
    );
    expect(report.recall).toBe(1);
    expect(report.precision).toBe(1);
    expect(report.missed).toHaveLength(0);
    expect(report.unexpected).toHaveLength(0);
  });

  test("missed and unexpected findings lower recall and precision", () => {
    const report = evaluateCase(
      testCase,
      [
        finding(),
        // Not expected: an unrelated extra finding.
        finding({
          ruleId: "open-redirect",
          taxonomy: { category: "open-redirect", cwe: [] },
          locations: [{ path: "src/redirect.ts", startLine: 1 }],
        }),
      ],
      "scan_2",
    );
    expect(report.recall).toBeCloseTo(1 / 3);
    expect(report.precision).toBeCloseTo(1 / 2);
    expect(report.missed.map((miss) => miss.category)).toEqual([
      "ssrf",
      "sql-injection",
    ]);
    expect(report.unexpected).toHaveLength(1);
  });

  test("minSeverity gate rejects weaker matches", () => {
    const report = evaluateCase(
      testCase,
      [
        finding(),
        finding({
          ruleId: "ssrf",
          taxonomy: { category: "ssrf", cwe: [] },
          locations: [{ path: "src/fetch.js", startLine: 3 }],
        }),
        finding({
          ruleId: "sql-injection",
          taxonomy: { category: "sql-injection", cwe: [] },
          locations: [{ path: "src/db.go", startLine: 7 }],
          severity: { level: "low" },
        }),
      ],
      "scan_3",
    );
    // The sql-injection finding exists but below the expected severity.
    expect(report.recall).toBeCloseTo(2 / 3);
    expect(report.missed.some((miss) => miss.category === "sql-injection")).toBe(
      true,
    );
  });
});

/** Mock agent reporting one known finding for the benchmark e2e run. */
class BenchmarkMockRuntime implements AgentRuntime {
  public readonly kind = "benchmark-mock";
  readonly #threatModel = {
    summary: "Fixture repository with a known archive traversal.",
    assets: ["filesystem"],
    trustBoundaries: [],
    attackerCapabilities: [],
    securityObjectives: [],
    assumptions: [],
  };

  async run(request: AgentRunRequest): Promise<AgentRunResult> {
    if (request.prompt.includes("independent validator")) {
      return {
        text: JSON.stringify({
          disposition: "reportable",
          survives: "yes",
          method: "static",
          summary: "confirmed",
          source: "requested_entry",
          control: "absent",
          sink: "src/extract.py:9",
          dataflow: "direct",
          counterevidence: "none",
          proofGaps: [],
          confidence: "high",
          confidenceRationale: "chain",
          vector: "remote",
          preconditions: "plausible",
          attackerInputControl: "yes",
          authScope: "public",
          impact: "high",
        }),
      };
    }
    if (request.prompt.includes("discovery reviewer")) {
      return {
        text: JSON.stringify({
          candidates: [
            {
              title: "Traversal",
              path: "src/extract.py",
              startLine: 9,
              endLine: 9,
              category: "path-traversal",
              cwe: ["CWE-22"],
              attackerSource: "entry name",
              sinkOrBrokenControl: "write",
              closestControl: "none",
              impact: "file write",
              whyPlausible: "trace",
              relevantLines: [9],
              supportingPaths: [],
            },
          ],
        }),
      };
    }
    return { text: JSON.stringify(this.#threatModel) };
  }
}

describe("runBenchmark end to end (mock runtime)", () => {
  test("produces recall/precision over a fixture repository", async () => {
    const root = await mkdtemp(join(tmpdir(), "open-security-bench-"));
    temporaryDirectories.push(root);
    const repository = join(root, "repo");
    await mkdir(join(repository, "src"), { recursive: true });
    const git = async (...arguments_: string[]) =>
      execFileAsync("git", ["-C", repository, ...arguments_]);
    await git("init", "-b", "main");
    await git("config", "user.email", "bench@example.com");
    await git("config", "user.name", "Bench");
    await writeFile(
      join(repository, "src", "extract.py"),
      "import zipfile\n\ndef extract(path, out):\n    zipfile.ZipFile(path).extractall(out)\n",
      "utf8",
    );
    await git("add", "-A");
    await git("commit", "-m", "initial");
    await writeFile(
      join(repository, "src", "extract.py"),
      "import os\nimport zipfile\n\ndef extract(path, out, entry):\n    zipfile.ZipFile(path).extract(entry, os.path.join(out, entry))\n",
      "utf8",
    );
    await git("add", "-A");
    await git("commit", "-m", "entry");

    const outputRoot = join(root, "benchmark-out");
    const scanner = new OpenSecurity({
      runtime: { runtime: "claude-agent", maxTurnsPerPhase: 5 },
      agent: new BenchmarkMockRuntime(),
    });
    const report = await runBenchmark({
      scanner,
      outputRoot,
      cases: [
        {
          name: "archive-traversal",
          repository,
          base: "HEAD~1",
          head: "HEAD",
          expected: [
            { category: "path-traversal", path: "src/extract.py", minSeverity: "high" },
          ],
        },
      ],
    });
    expect(report.runtime).toBe("benchmark-mock");
    expect(report.cases).toHaveLength(1);
    expect(report.cases[0]?.recall).toBe(1);
    expect(report.cases[0]?.precision).toBe(1);
    expect(report.totals.matched).toBe(1);
    const persisted = JSON.parse(
      await readFile(join(outputRoot, "case-0-archive-traversal", "findings.json"), "utf8"),
    );
    expect(persisted.documentType).toBe("open-security.findings");
  });
});
