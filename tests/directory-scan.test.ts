import { afterAll, describe, expect, test } from "vitest";
import { mkdir, mkdtemp, rm, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { directoryTargetId, scanDirectory } from "../src/directory.js";
import { OpenSecurity } from "../src/index.js";
import type {
  AgentRunRequest,
  AgentRuntime,
  AgentRunResult,
} from "../src/runtime/types.js";

const temporaryDirectories: string[] = [];

afterAll(async () => {
  await Promise.all(
    temporaryDirectories.map((path) => rm(path, { recursive: true, force: true })),
  );
});

describe("scanDirectory", () => {
  test("walks reviewable files, skips excluded directories, digests stably", async () => {
    const root = await mkdtemp(join(tmpdir(), "open-security-dir-"));
    temporaryDirectories.push(root);
    await mkdir(join(root, "src", "auth"), { recursive: true });
    await mkdir(join(root, "node_modules", "pkg"), { recursive: true });
    await mkdir(join(root, "docs"), { recursive: true });
    await writeFile(join(root, "src", "auth", "Login.java"), "class Login {}\n");
    await writeFile(join(root, "src", "util.ts"), "export const x = 1;\n");
    await writeFile(join(root, "node_modules", "pkg", "y.js"), "module.exports\n");
    await writeFile(join(root, "docs", "guide.md"), "# Guide\n");

    const first = await scanDirectory(root);
    expect(first.allPaths).toContain("src/auth/Login.java");
    expect(first.allPaths).toContain("src/util.ts");
    // Excluded directories are pruned during traversal, not filtered later.
    expect(first.allPaths.some((path) => path.startsWith("node_modules/"))).toBe(
      false,
    );
    expect(first.allPaths.some((path) => path.startsWith("docs/"))).toBe(false);

    const second = await scanDirectory(root);
    expect(second.digest).toBe(first.digest);
    expect(directoryTargetId(first.digest)).toBe(directoryTargetId(second.digest));

    await writeFile(join(root, "src", "util.ts"), "export const x = 2;\n");
    const third = await scanDirectory(root);
    expect(third.digest).not.toBe(first.digest);
  });
});

class DirMockRuntime implements AgentRuntime {
  public readonly kind = "dir-mock";
  readonly #threatModel = {
    summary: "Directory-hosted CLI tool with a config writer.",
    assets: ["config file"],
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
          source: "user-supplied filename",
          control: "absent",
          sink: "src/store.ts:8",
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
              title: "Config path traversal",
              path: "src/store.ts",
              startLine: 8,
              endLine: 8,
              category: "path-traversal",
              cwe: ["CWE-22"],
              attackerSource: "filename argument",
              sinkOrBrokenControl: "config write",
              closestControl: "none",
              impact: "arbitrary write",
              whyPlausible: "trace",
              relevantLines: [],
              supportingPaths: [],
            },
          ],
        }),
      };
    }
    return { text: JSON.stringify(this.#threatModel) };
  }
}

describe("repository scan on a plain (non-Git) directory", () => {
  test("scans without git and reports a directory_snapshot target", async () => {
    const root = await mkdtemp(join(tmpdir(), "open-security-plain-"));
    temporaryDirectories.push(root);
    await mkdir(join(root, "src"), { recursive: true });
    await writeFile(
      join(root, "src", "store.ts"),
      'import { writeFileSync } from "node:fs";\nexport function save(base: string, name: string, data: string) {\n  writeFileSync(`${base}/${name}`, data);\n}\n',
    );
    const outputDir = join(root, "out");
    temporaryDirectories.push(outputDir);
    const scanner = new OpenSecurity({
      runtime: { runtime: "claude-agent", maxTurnsPerPhase: 5 },
      agent: new DirMockRuntime(),
    });
    const result = await scanner.scanRepository(root, { outputDir });

    expect(result.findings).toBe(1);
    const manifest = JSON.parse(await readFile(result.manifestPath, "utf8"));
    expect(manifest.scan.target.kind).toBe("directory_snapshot");
    expect(manifest.scan.target.snapshotDigest).toMatch(
      /^open-security-snapshot\/v1:sha256:[a-f0-9]{64}$/u,
    );
    expect(manifest.scan.target).not.toHaveProperty("headRevision");
    const coverage = JSON.parse(await readFile(result.coveragePath, "utf8"));
    expect(coverage.mode).toBe("repository");
    expect(coverage.inventoryStrategy).toBe("directory");
    const report = await readFile(result.reportPath, "utf8");
    expect(report).toContain("directory snapshot");
  });
});
