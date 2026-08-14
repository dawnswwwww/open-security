import { afterAll, describe, expect, test } from "vitest";
import { execFile } from "node:child_process";
import { mkdtemp, mkdir, rm, readFile, readdir, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";
import { fileURLToPath } from "node:url";
import { OpenSecurity } from "../src/index.js";
import { splitCommandLine } from "../src/runtime/acp.js";

const execFileAsync = promisify(execFile);
const FIXTURE_AGENT = fileURLToPath(
  new URL("./fixtures/fake-acp-agent.mjs", import.meta.url),
);
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
  const root = await mkdtemp(join(tmpdir(), "open-security-acp-"));
  temporaryDirectories.push(root);
  await git(root, "init", "-b", "main");
  await git(root, "config", "user.email", "fixture@example.com");
  await git(root, "config", "user.name", "Fixture");
  await mkdir(join(root, "src"), { recursive: true });
  await writeFile(
    join(root, "src", "extract.py"),
    "import zipfile\n\ndef extract(archive_path, output_dir):\n    with zipfile.ZipFile(archive_path) as archive:\n        archive.extractall(output_dir)\n",
    "utf8",
  );
  await git(root, "add", "-A");
  await git(root, "commit", "-m", "initial");
  await writeFile(
    join(root, "src", "extract.py"),
    "import os\nimport zipfile\n\ndef extract(archive_path, output_dir, requested_entry):\n    with zipfile.ZipFile(archive_path) as archive:\n        target = os.path.join(output_dir, requested_entry)\n        archive.extract(requested_entry, target)\n",
    "utf8",
  );
  await git(root, "add", "-A");
  await git(root, "commit", "-m", "entry selection");
  return root;
}

describe("splitCommandLine", () => {
  test("splits shell-style command lines with quotes", () => {
    expect(splitCommandLine("node agent.mjs --flag")).toEqual([
      "node",
      "agent.mjs",
      "--flag",
    ]);
    expect(splitCommandLine('claude-code-acp --model "my model"')).toEqual([
      "claude-code-acp",
      "--model",
      "my model",
    ]);
    expect(splitCommandLine("")).toEqual([]);
  });
});

describe("ACP runtime end to end (fake agent process)", () => {
  test("runs the full diff scan pipeline through an ACP agent", async () => {
    const repository = await createFixtureRepository();
    const outputDir = join(repository, "..", `acp-out-${Date.now()}`);
    temporaryDirectories.push(outputDir);
    const scanner = new OpenSecurity({
      runtime: {
        runtime: "acp",
        acpCommand: `node ${JSON.stringify(FIXTURE_AGENT)}`,
        maxTurnsPerPhase: 5,
      },
    });
    const result = await scanner.scanDiff(repository, {
      base: "HEAD~1",
      head: "HEAD",
      workingTree: false,
      outputDir,
    });

    expect(result.findings).toBe(1);
    expect(result.maxSeverity).toBe("critical");
    const findings = JSON.parse(await readFile(result.findingsPath, "utf8"));
    expect(findings.documentType).toBe("open-security.findings");
    expect(findings.findings[0]?.taxonomy?.cwe).toEqual(["CWE-22"]);
    // The threat model cache lives in the stable per-repository directory.
    const cacheFiles = await readdir(
      join(repository, "..", ".open-security", "cache"),
    ).catch(() => []);
    expect(cacheFiles.some((name) => name.startsWith("threat-model-"))).toBe(
      true,
    );
  }, 60_000);
});
