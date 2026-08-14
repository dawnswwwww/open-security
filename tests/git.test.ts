import { describe, expect, test } from "vitest";
import { diffTargetId, stripUrlCredentials } from "../src/git.js";

describe("stripUrlCredentials", () => {
  test("removes userinfo from https remotes", () => {
    expect(stripUrlCredentials("https://user:token@host.example/repo.git")).toBe(
      "https://host.example/repo.git",
    );
    expect(stripUrlCredentials("https://oauth@host.example/repo.git")).toBe(
      "https://host.example/repo.git",
    );
  });

  test("leaves clean URLs and non-URL remotes unchanged", () => {
    expect(stripUrlCredentials("https://host.example/repo.git")).toBe(
      "https://host.example/repo.git",
    );
    expect(stripUrlCredentials("git@github.com:org/repo.git")).toBe(
      "git@github.com:org/repo.git",
    );
    expect(stripUrlCredentials("/local/path/repo")).toBe("/local/path/repo");
  });
});

describe("diffTargetId", () => {
  test("is stable for identical SHAs and independent of ref names", () => {
    const base = "a".repeat(40);
    const head = "b".repeat(40);
    expect(diffTargetId(false, base, head)).toBe(diffTargetId(false, base, head));
    expect(diffTargetId(false, base, head)).not.toBe(
      diffTargetId(false, base, "c".repeat(40)),
    );
  });

  test("distinguishes working-tree scans from committed diffs", () => {
    const base = "a".repeat(40);
    expect(diffTargetId(true, base, undefined)).not.toBe(
      diffTargetId(false, base, "a".repeat(40)),
    );
  });
});
