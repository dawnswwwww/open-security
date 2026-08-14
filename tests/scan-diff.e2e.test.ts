import { afterAll, describe, expect, test } from "vitest";
import { execFile } from "node:child_process";
import { mkdir, mkdtemp, rm, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";
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

async function git(cwd: string, ...arguments_: string[]): Promise<void> {
  await execFileAsync("git", ["-C", cwd, ...arguments_]);
}

async function createFixtureRepository(): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), "open-security-fixture-"));
  temporaryDirectories.push(root);
  await git(root, "init", "-b", "main");
  await git(root, "config", "user.email", "fixture@example.com");
  await git(root, "config", "user.name", "Fixture");
  await mkdir(join(root, "src"), { recursive: true });
  await writeFile(
    join(root, "src", "extract.py"),
    [
      "import zipfile",
      "",
      "",
      "def extract(archive_path, output_dir):",
      '    with zipfile.ZipFile(archive_path) as archive:',
      "        for entry in archive.namelist():",
      "            archive.extract(entry, output_dir)",
      "",
    ].join("\n"),
  );
  await git(root, "add", "-A");
  await git(root, "commit", "-m", "initial");
  // Vulnerable change: user-supplied path flows into a filesystem write.
  await writeFile(
    join(root, "src", "extract.py"),
    [
      "import os",
      "import zipfile",
      "",
      "",
      "def extract(archive_path, output_dir, requested_entry):",
      '    with zipfile.ZipFile(archive_path) as archive:',
      "        target = os.path.join(output_dir, requested_entry)",
      "        archive.extract(requested_entry, target)",
      "",
    ].join("\n"),
  );
  await git(root, "add", "-A");
  await git(root, "commit", "-m", "support requested entry");
  return root;
}

/** Canned agent: distinguishes phases by prompt content. */
class MockRuntime implements AgentRuntime {
  public readonly kind = "mock";
  readonly #threatModel = {
    summary:
      "The service extracts user-supplied archives. Assets include the filesystem and configuration files.",
    assets: ["filesystem integrity"],
    trustBoundaries: ["user input to filesystem writes (src/extract.py)"],
    attackerCapabilities: ["crafted archive entries"],
    securityObjectives: ["extraction stays inside output_dir"],
    assumptions: ["archive paths are untrusted"],
  };

  async run(request: AgentRunRequest): Promise<AgentRunResult> {
    await mkdir(join(request.cwd, ".mock-agent-read"), { recursive: true });
    // Order matters: the validation prompt quotes the discovery reviewer, so
    // the most specific markers are checked first.
    if (request.prompt.includes("independent validator")) {
      return {
        text: JSON.stringify({
          disposition: "reportable",
          survives: "yes",
          method: "static",
          summary: "Confirmed: no canonicalization between input and write.",
          source: "requested_entry, attacker-controlled archive entry name",
          control: "absent; join() preserves traversal segments",
          sink: "src/extract.py:10 archive.extract write",
          dataflow: "requested_entry -> join -> extract() write",
          counterevidence: "none found",
          proofGaps: [],
          confidence: "high",
          confidenceRationale: "exact source-control-sink chain with no gap",
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
              title: "Archive entry path escapes output directory",
              path: "src/extract.py",
              startLine: 9,
              endLine: 10,
              category: "path-traversal",
              cwe: ["CWE-22"],
              attackerSource: "requested_entry derived from archive entry names",
              sinkOrBrokenControl: "filesystem write without containment check",
              closestControl: "none; os.path.join preserves ../ segments",
              impact: "arbitrary file write outside output_dir",
              whyPlausible: "requested_entry flows unchecked into extract()",
              relevantLines: [9, 10],
              supportingPaths: [],
            },
          ],
        }),
      };
    }
    if (request.prompt.includes("building a repository threat model")) {
      return { text: JSON.stringify(this.#threatModel) };
    }
    throw new Error("MockRuntime received an unexpected prompt.");
  }
}

describe("diff scan end to end (mock runtime)", () => {
  test("produces a complete contract for a fixture repository", async () => {
    const repository = await createFixtureRepository();
    const outputDir = join(repository, "..", `out-${Date.now()}`);
    temporaryDirectories.push(outputDir);
    const scanner = new OpenSecurity({
      runtime: {
        runtime: "claude-agent",
        maxTurnsPerPhase: 5,
      },
      agent: new MockRuntime(),
    });
    const phases: string[] = [];
    const result = await scanner.scanDiff(
      repository,
      {
        base: "HEAD~1",
        head: "HEAD",
        workingTree: false,
        outputDir,
      },
      (event) => {
        phases.push(
          event.phase === "inventory"
            ? "inventory"
            : event.phase === "threat-model"
              ? `threat-model:${event.status}`
              : event.phase === "discovery"
                ? `discovery:${event.status}`
                : event.phase === "validation"
                  ? `validation:${event.status}`
                  : event.phase,
        );
      },
    );
    expect(phases).toEqual([
      "inventory",
      "threat-model:running",
      "threat-model:done",
      "discovery:running",
      "discovery:done",
      "validation:running",
      "validation:running",
      "validation:done",
      "assemble",
      "complete",
    ]);

    expect(result.findings).toBe(1);
    expect(result.failedThreshold).toBe(false);
    expect(result.maxSeverity).toBe("critical");

    const findings = JSON.parse(
      await readFile(result.findingsPath, "utf8"),
    ) as { documentType: string; findings: { severity: { level: string } }[] };
    expect(findings.documentType).toBe("open-security.findings");
    expect(findings.findings[0]?.severity.level).toBe("critical");

    const manifest = JSON.parse(await readFile(result.manifestPath, "utf8"));
    expect(manifest.scan.target.kind).toBe("git_diff");
    expect(manifest.scan.target.baseRevision).toMatch(/^[0-9a-f]{40}$/u);

    const coverage = JSON.parse(await readFile(result.coveragePath, "utf8"));
    expect(coverage.mode).toBe("diff");
    expect(coverage.completeness).toBe("complete");
    expect(coverage.includePaths).toContain("src/extract.py");

    expect(result.sarifPath).not.toBeNull();
    const sarif = JSON.parse(await readFile(result.sarifPath!, "utf8"));
    expect(sarif.version).toBe("2.1.0");
    expect(sarif.runs[0].results).toHaveLength(1);
  });

  test("fail-on-severity gates the exit decision", async () => {
    const repository = await createFixtureRepository();
    const outputDir = join(repository, "..", `gate-${Date.now()}`);
    temporaryDirectories.push(outputDir);
    const scanner = new OpenSecurity({
      runtime: { runtime: "claude-agent", maxTurnsPerPhase: 5 },
      agent: new MockRuntime(),
    });
    const result = await scanner.scanDiff(repository, {
      base: "HEAD~1",
      head: "HEAD",
      workingTree: false,
      failOnSeverity: "high",
      outputDir,
    });
    expect(result.failedThreshold).toBe(true);
  });
});
