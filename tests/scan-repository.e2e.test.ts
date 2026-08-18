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
import {
  buildRepositoryInventory,
  rankRepositoryFiles,
} from "../src/pipeline/inventory.js";

const execFileAsync = promisify(execFile);
const temporaryDirectories: string[] = [];

afterAll(async () => {
  await Promise.all(
    temporaryDirectories.map((path) => rm(path, { recursive: true, force: true })),
  );
});

describe("repository ranking heuristic", () => {
  test("ranks auth and crypto paths above generic code", () => {
    const files = [
      { path: "src/util/Format.java", hunks: [] },
      { path: "src/auth/TokenValidator.java", hunks: [] },
      { path: "src/crypto/CipherUtil.java", hunks: [] },
      { path: "src/model/User.java", hunks: [] },
    ];
    const ranked = rankRepositoryFiles(files).map((file) => file.path);
    expect(ranked.indexOf("src/auth/TokenValidator.java")).toBeLessThan(
      ranked.indexOf("src/util/Format.java"),
    );
    expect(ranked.indexOf("src/crypto/CipherUtil.java")).toBeLessThan(
      ranked.indexOf("src/util/Format.java"),
    );
  });

  test("caps deep review and defers the remainder honestly", () => {
    const tracked = [
      "src/auth/Login.java",
      "src/auth/OAuth.java",
      "src/auth/Session.java",
      "src/model/User.java",
      "src/util/A.java",
      "src/util/B.java",
      "README.md",
      "tests/Test.java",
    ];
    const inventory = buildRepositoryInventory(tracked, 3);
    expect(inventory.origin).toBe("repository");
    expect(inventory.files).toHaveLength(3);
    expect(inventory.files.every((file) => file.path.startsWith("src/auth/"))).toBe(
      true,
    );
    expect(inventory.deferredNotReviewed).toEqual([
      "src/model/User.java",
      "src/util/A.java",
      "src/util/B.java",
    ]);
    expect(inventory.excluded).toEqual(["README.md", "tests/Test.java"]);
  });
});

/** Mock agent for the repository-scan e2e run. */
class RepoMockRuntime implements AgentRuntime {
  public readonly kind = "repo-mock";
  readonly #threatModel = {
    summary: "Fixture service with an authenticated upload path.",
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
          source: "filename from multipart upload",
          control: "absent",
          sink: "src/upload/Store.java:12",
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
              title: "Upload path traversal",
              path: "src/upload/Store.java",
              startLine: 12,
              endLine: 12,
              category: "path-traversal",
              cwe: ["CWE-22"],
              attackerSource: "uploaded filename",
              sinkOrBrokenControl: "filesystem write",
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

describe("repository scan end to end (mock runtime)", () => {
  test("scans the whole ranked inventory with repository coverage mode", async () => {
    const root = await mkdtemp(join(tmpdir(), "open-security-repo-"));
    temporaryDirectories.push(root);
    const repository = join(root, "repo");
    for (const directory of ["src/auth", "src/upload", "docs"]) {
      await mkdir(join(repository, directory), { recursive: true });
    }
    const git = async (...arguments_: string[]) =>
      execFileAsync("git", ["-C", repository, ...arguments_]);
    await git("init", "-b", "main");
    await git("config", "user.email", "repo@example.com");
    await git("config", "user.name", "Repo");
    await writeFile(
      join(repository, "src", "auth", "Login.java"),
      "public class Login { boolean check(String p) { return p != null; } }\n",
      "utf8",
    );
    await writeFile(
      join(repository, "src", "upload", "Store.java"),
      "public class Store { void store(String name, byte[] data) { /* writes name under root */ } }\n",
      "utf8",
    );
    await writeFile(join(repository, "docs", "guide.md"), "# Guide\n", "utf8");
    await git("add", "-A");
    await git("commit", "-m", "initial");

    const outputDir = join(root, "out");
    temporaryDirectories.push(outputDir);
    const scanner = new OpenSecurity({
      runtime: {
        runtime: "pi",
        baseUrl: "https://unit.test/v1",
        model: "test-model",
        maxTurnsPerPhase: 5,
      },
      agent: new RepoMockRuntime(),
    });
    const result = await scanner.scanRepository(repository, {
      outputDir,
    });

    expect(result.findings).toBe(1);
    const manifest = JSON.parse(await readFile(result.manifestPath, "utf8"));
    expect(manifest.scan.target.kind).toBe("git_revision");
    expect(manifest.scan.target.headRevision).toMatch(/^[0-9a-f]{40}$/u);
    expect(manifest.scan.target).not.toHaveProperty("baseRevision");
    const coverage = JSON.parse(await readFile(result.coveragePath, "utf8"));
    expect(coverage.mode).toBe("repository");
    expect(coverage.inventoryStrategy).toBe("repository");
    expect(coverage.completeness).toBe("complete");
    expect(coverage.includePaths).toContain("src/upload/Store.java");
    expect(coverage.excludePaths).toContain("docs/guide.md");
    const report = await readFile(result.reportPath, "utf8");
    expect(report).toContain("repository scan");
  });
});
