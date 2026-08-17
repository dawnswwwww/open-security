import { afterAll, describe, expect, test } from "vitest";
import { execFile } from "node:child_process";
import {
  mkdir,
  mkdtemp,
  rm,
  symlink,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";
import {
  formatNumberedLines,
  globToRegExp,
  normalizeRepoPath,
  parseRipgrepOutput,
  readOnlyToolDefinitions,
  resolveWithin,
  searchWithWalker,
  validateGitRef,
} from "../src/runtime/read-only-tools.js";

const execFileAsync = promisify(execFile);
const temporaryDirectories: string[] = [];

afterAll(async () => {
  await Promise.all(
    temporaryDirectories.map((path) => rm(path, { recursive: true, force: true })),
  );
});

async function createFixtureTree(): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), "open-security-tools-"));
  temporaryDirectories.push(root);
  await mkdir(join(root, "src", "auth"), { recursive: true });
  await writeFile(join(root, "src", "auth", "login.ts"), "export function login(token: string) {\n  return verify(token);\n}\n", "utf8");
  await writeFile(join(root, "src", "util.ts"), "export const answer = 42;\n", "utf8");
  await writeFile(join(root, "README.md"), "# fixture\n", "utf8");
  return root;
}

describe("resolveWithin", () => {
  test("keeps relative paths inside the root", () => {
    const root = "/repo";
    expect(resolveWithin(root, "src/a.ts")).toBe("/repo/src/a.ts");
    expect(resolveWithin(root, "/repo/src/a.ts")).toBe("/repo/src/a.ts");
  });

  test("rejects paths escaping the root", () => {
    expect(resolveWithin("/repo", "../outside.txt")).toBeNull();
    expect(resolveWithin("/repo", "/etc/passwd")).toBeNull();
    expect(resolveWithin("/repo", "/repository/evil.txt")).toBeNull();
  });
});

describe("formatNumberedLines", () => {
  test("numbers lines and reports truncation", () => {
    const content = ["alpha", "beta", "gamma"].join("\n");
    expect(formatNumberedLines(content, 1, 10)).toBe("1\talpha\n2\tbeta\n3\tgamma");
    expect(formatNumberedLines(content, 2, 1)).toBe("2\tbeta\n(starting at line 2) (truncated at line 2 of 3)");
    expect(formatNumberedLines(content, 1, 2)).toContain("truncated at line 2 of 3");
  });
});

describe("globToRegExp", () => {
  test("matches star, double-star, and brace patterns", () => {
    const pattern = globToRegExp("src/**/*.ts");
    expect(pattern.test("src/util.ts")).toBe(true);
    expect(pattern.test("src/auth/login.ts")).toBe(true);
    expect(pattern.test("src/auth/login.js")).toBe(false);
    expect(globToRegExp("src/*.{ts,tsx}").test("src/app.tsx")).toBe(true);
    expect(globToRegExp("a?c.txt").test("abc.txt")).toBe(true);
    expect(globToRegExp("a?c.txt").test("ac.txt")).toBe(false);
  });
});

describe("git ref and path validation", () => {
  test("accepts normal refs, rejects option-like or nested ones", () => {
    expect(validateGitRef("HEAD")).toBe(true);
    expect(validateGitRef("origin/main")).toBe(true);
    expect(validateGitRef("abc123")).toBe(true);
    expect(validateGitRef("-n")).toBe(false);
    expect(validateGitRef("HEAD;rm -rf")).toBe(false);
    expect(validateGitRef("a..b")).toBe(false);
  });

  test("normalizes repo-relative paths and rejects escapes", () => {
    expect(normalizeRepoPath("src/a.ts")).toBe("src/a.ts");
    expect(normalizeRepoPath("./a.ts")).toBe("a.ts");
    expect(normalizeRepoPath("../a.ts")).toBeNull();
    expect(normalizeRepoPath("/etc/passwd")).toBeNull();
  });
});

describe("parseRipgrepOutput", () => {
  test("parses path:line:text rows", () => {
    const hits = parseRipgrepOutput("src/a.ts:3:eval(input)\nsrc/b.ts:7:eval(x)\n");
    expect(hits).toEqual([
      { path: "src/a.ts", line: 3, text: "eval(input)" },
      { path: "src/b.ts", line: 7, text: "eval(x)" },
    ]);
  });
});

describe("read-only tools against a fixture tree", () => {
  test("read_file returns numbered lines and rejects escapes", async () => {
    const root = await createFixtureTree();
    const tools = readOnlyToolDefinitions(root);
    const read = tools.find((tool) => tool.name === "read_file")!;
    const result = await read.execute("call-1", { path: "src/util.ts" }, undefined, undefined, {} as never);
    expect(result.content[0]).toMatchObject({ type: "text" });
    expect((result.content[0] as { text: string }).text).toContain("1\texport const answer = 42;");
    await expect(
      read.execute("call-2", { path: "../../etc/passwd" }, undefined, undefined, {} as never),
    ).rejects.toThrow(/escapes the repository root/u);
  });

  test("read_file refuses symlinks pointing outside the repository", async () => {
    const root = await createFixtureTree();
    const secretRoot = await mkdtemp(join(tmpdir(), "open-security-outside-"));
    temporaryDirectories.push(secretRoot);
    await writeFile(join(secretRoot, "secret.txt"), "token=abc\n", "utf8");
    await symlink(join(secretRoot, "secret.txt"), join(root, "leak.txt"));
    const read = readOnlyToolDefinitions(root).find((tool) => tool.name === "read_file")!;
    await expect(
      read.execute("call-3", { path: "leak.txt" }, undefined, undefined, {} as never),
    ).rejects.toThrow(/escapes the repository root/u);
  });

  test("glob_files lists matching paths only", async () => {
    const root = await createFixtureTree();
    const glob = readOnlyToolDefinitions(root).find((tool) => tool.name === "glob_files")!;
    const result = await glob.execute("call-4", { pattern: "src/**/*.ts" }, undefined, undefined, {} as never);
    const text = (result.content[0] as { text: string }).text;
    expect(text).toContain("src/auth/login.ts");
    expect(text).toContain("src/util.ts");
    expect(text).not.toContain("README.md");
  });

  test("searchWithWalker finds matches with line numbers", async () => {
    const root = await createFixtureTree();
    const hits = await searchWithWalker(root, "verify\\(", undefined, 10);
    expect(hits).toEqual([
      { path: "src/auth/login.ts", line: 2, text: "  return verify(token);" },
    ]);
  });

  test("search_files returns matches through either backend", async () => {
    const root = await createFixtureTree();
    const search = readOnlyToolDefinitions(root).find((tool) => tool.name === "search_files")!;
    const result = await search.execute("call-5", { query: "answer" }, undefined, undefined, {} as never);
    expect((result.content[0] as { text: string }).text).toContain("src/util.ts:1:");
  });

  test("git_show reads the committed baseline, not the working tree", async () => {
    const root = await createFixtureTree();
    await execFileAsync("git", ["-C", root, "init", "-b", "main"]);
    await execFileAsync("git", ["-C", root, "config", "user.email", "fixture@example.com"]);
    await execFileAsync("git", ["-C", root, "config", "user.name", "Fixture"]);
    await execFileAsync("git", ["-C", root, "add", "-A"]);
    await execFileAsync("git", ["-C", root, "commit", "-m", "initial"]);
    await writeFile(join(root, "src", "util.ts"), "export const answer = 99;\n", "utf8");
    const gitShow = readOnlyToolDefinitions(root).find((tool) => tool.name === "git_show")!;
    const result = await gitShow.execute(
      "call-6",
      { ref: "HEAD", path: "src/util.ts" },
      undefined,
      undefined,
      {} as never,
    );
    expect((result.content[0] as { text: string }).text).toContain("answer = 42");
    await expect(
      gitShow.execute("call-7", { ref: "--exec=evil", path: "src/util.ts" }, undefined, undefined, {} as never),
    ).rejects.toThrow(/Invalid git revision/u);
  });
});
