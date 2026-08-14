import { describe, expect, test } from "vitest";
import {
  buildInventory,
  isReviewablePath,
} from "../src/pipeline/inventory.js";
import { parseNameStatus, parseUnifiedDiffHunks } from "../src/git.js";

describe("reviewable path rules", () => {
  test("accepts source files", () => {
    expect(isReviewablePath("src/app.py")).toBe(true);
    expect(isReviewablePath("lib/index.ts")).toBe(true);
    expect(isReviewablePath("api/handler.go")).toBe(true);
  });

  test("excludes dependency, build, and test directories", () => {
    expect(isReviewablePath("node_modules/pkg/index.js")).toBe(false);
    expect(isReviewablePath("vendor/lib.c")).toBe(false);
    expect(isReviewablePath("dist/bundle.js")).toBe(false);
    expect(isReviewablePath("tests/unit.spec.ts")).toBe(false);
    expect(isReviewablePath(".github/workflows/ci.yml")).toBe(false);
  });

  test("excludes lockfiles and documentation", () => {
    expect(isReviewablePath("package-lock.json")).toBe(false);
    expect(isReviewablePath("pnpm-lock.yaml")).toBe(false);
    expect(isReviewablePath("README.md")).toBe(false);
    expect(isReviewablePath("docs/guide.md")).toBe(false);
  });

  test("excludes minified and map artifacts", () => {
    expect(isReviewablePath("public/app.min.js")).toBe(false);
    expect(isReviewablePath("public/app.min.js.map")).toBe(false);
  });

  test("excludes non-source extensions", () => {
    expect(isReviewablePath("assets/logo.png")).toBe(false);
    expect(isReviewablePath("binary.exe")).toBe(false);
  });
});

describe("git name-status parsing", () => {
  test("parses plain status records", () => {
    const files = parseNameStatus("M\0src/a.ts\0A\0src/b.ts\0D\0src/c.ts\0");
    expect(files).toEqual([
      { path: "src/a.ts", status: "M" },
      { path: "src/b.ts", status: "A" },
      { path: "src/c.ts", status: "D" },
    ]);
  });

  test("parses rename records with similarity score", () => {
    const files = parseNameStatus("R089\0src/old.ts\0src/new.ts\0");
    expect(files).toEqual([
      { path: "src/new.ts", status: "R", previousPath: "src/old.ts" },
    ]);
  });

  test("rejects malformed records", () => {
    expect(() => parseNameStatus("X\0src/a.ts\0")).toThrow();
    expect(() => parseNameStatus("M\0")).toThrow();
  });
});

describe("diff hunk parsing", () => {
  test("extracts changed line ranges per file", () => {
    const diff = [
      "diff --git a/src/a.ts b/src/a.ts",
      "--- a/src/a.ts",
      "+++ b/src/a.ts",
      "@@ -10,2 +11,5 @@ function handler() {",
      " context",
      "+added",
      "diff --git a/src/b.py b/src/b.py",
      "--- a/src/b.py",
      "+++ b/src/b.py",
      "@@ -1 +1,2 @@",
      "+import os",
    ].join("\n");
    const hunks = parseUnifiedDiffHunks(diff);
    expect(hunks.get("src/a.ts")).toEqual([
      { path: "src/a.ts", startLine: 11, endLine: 15 },
    ]);
    expect(hunks.get("src/b.py")).toEqual([
      { path: "src/b.py", startLine: 1, endLine: 2 },
    ]);
  });
});

describe("buildInventory", () => {
  test("keeps deleted files and records excluded paths", () => {
    const inventory = buildInventory(
      [
        { path: "src/kept.ts", status: "M" },
        { path: "src/gone.ts", status: "D" },
        { path: "node_modules/x.js", status: "A" },
        { path: "README.md", status: "M" },
      ],
      new Map([["src/kept.ts", [{ path: "src/kept.ts", startLine: 3, endLine: 9 }]]]),
    );
    expect(inventory.files.map((file) => file.path)).toEqual([
      "src/gone.ts",
      "src/kept.ts",
    ]);
    expect(inventory.excluded).toEqual(["README.md", "node_modules/x.js"]);
    expect(inventory.files[1]?.hunks).toEqual([
      { path: "src/kept.ts", startLine: 3, endLine: 9 },
    ]);
  });
});
