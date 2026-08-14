import { mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import {
  meetsFailThreshold,
  type OpenSecurityConfig,
  type RuntimeConfig,
  type ScanOptions,
  type SeverityLevel,
} from "./config.js";
import type { AgentRuntime } from "./runtime/types.js";
import { ClaudeAgentRuntime } from "./runtime/claude-agent.js";
import {
  diffHunks,
  diffTargetId,
  listChangedFiles,
  remoteUrl,
  resolveGitRoot,
  resolveRevision,
  type DiffSpec,
} from "./git.js";
import { buildInventory } from "./pipeline/inventory.js";
import {
  loadThreatModel,
  threatModelCacheKey,
} from "./pipeline/threat-model.js";
import { runDiscovery } from "./pipeline/discovery.js";
import { runValidation } from "./pipeline/validation.js";
import { assemble } from "./pipeline/assemble.js";
import { resolveSecurityMd } from "./pipeline/security-md.js";
import { toSarif } from "./contract/sarif.js";
import { newScanId } from "./contract/identity.js";
import { VERSION } from "./version.js";

export interface ScanResult {
  scanId: string;
  outputDir: string;
  findingsPath: string;
  manifestPath: string;
  coveragePath: string;
  sarifPath: string | null;
  reportPath: string;
  findings: number;
  /** Highest severity among reported findings, when any. */
  maxSeverity: SeverityLevel | null;
  /** true when a reported finding meets the failOnSeverity threshold. */
  failedThreshold: boolean;
}

export class OpenSecurity {
  readonly #config: OpenSecurityConfig;
  readonly #runtime: AgentRuntime;

  public constructor(config: OpenSecurityConfig) {
    this.#config = config;
    this.#runtime = config.agent ?? createRuntime(config.runtime);
  }

  public get runtimeKind(): string {
    return this.#runtime.kind;
  }

  public async scanDiff(
    repositoryInput: string,
    options: ScanOptions,
  ): Promise<ScanResult> {
    const repository = await resolveGitRoot(repositoryInput);
    const spec: DiffSpec = {
      base: options.base,
      head: options.head,
      workingTree: options.workingTree,
    };
    const startedAt = new Date();
    const baseSha = await resolveRevision(repository, options.base);
    const headSha = options.workingTree
      ? undefined
      : await resolveRevision(repository, options.head);
    const scanId = newScanId();
    const outputDir =
      options.outputDir === undefined
        ? join(repository, "..", ".open-security", scanId)
        : options.outputDir;
    await mkdir(outputDir, { recursive: true });

    // ① inventory
    const changed = await listChangedFiles(repository, spec);
    const hunks = await diffHunks(repository, spec);
    const inventory = buildInventory(changed, hunks);

    // ② threat model (cached per repository + head revision)
    const threatModel = await loadThreatModel({
      runtime: this.#runtime,
      repository,
      cacheKey: threatModelCacheKey(repository, headSha ?? `worktree-${baseSha}`),
      outputDir,
      ...(this.#config.runtime.maxTurnsPerPhase === undefined
        ? {}
        : { maxTurns: this.#config.runtime.maxTurnsPerPhase }),
      ...(this.#config.signal === undefined
        ? {}
        : { signal: this.#config.signal }),
    });
    const securityMd = await resolveSecurityMd(repository);
    const threatModelText = JSON.stringify(threatModel, null, 2);

    // ③ discovery
    const candidates = await runDiscovery({
      runtime: this.#runtime,
      repository,
      inventory,
      threatModel: threatModelText,
      securityMd,
      diffSummary: `base=${spec.base} head=${
        spec.workingTree ? "working-tree" : spec.head
      }, ${changed.length} changed file(s), ${inventory.files.length} in review scope.`,
      ...(this.#config.runtime.maxTurnsPerPhase === undefined
        ? {}
        : { maxTurns: this.#config.runtime.maxTurnsPerPhase }),
      ...(this.#config.signal === undefined
        ? {}
        : { signal: this.#config.signal }),
    });

    // ④ validation (fresh session per candidate)
    const validated = await runValidation({
      runtime: this.#runtime,
      repository,
      candidates,
      threatModel: threatModelText,
      securityMd,
      ...(this.#config.runtime.maxTurnsPerPhase === undefined
        ? {}
        : { maxTurns: this.#config.runtime.maxTurnsPerPhase }),
      ...(this.#config.signal === undefined
        ? {}
        : { signal: this.#config.signal }),
    });

    // ⑤⑥ severity + assemble
    const targetId = await diffTargetId(spec, baseSha);
    const remote = await remoteUrl(repository);
    const assembled = assemble({
      scanId,
      startedAt,
      completedAt: new Date(),
      targetId,
      displayName: repository,
      ...(remote === undefined ? {} : { remote }),
      baseRevision: baseSha,
      ...(headSha === undefined ? {} : { headRevision: headSha }),
      workingTree: spec.workingTree,
      inventory,
      threatModel,
      validated,
      producer: { name: "open-security", version: VERSION },
    });

    const findingsPath = join(outputDir, "findings.json");
    const manifestPath = join(outputDir, "scan-manifest.json");
    const coveragePath = join(outputDir, "coverage.json");
    const reportPath = join(outputDir, "report.md");
    await writeFile(
      findingsPath,
      `${JSON.stringify(assembled.findings, null, 2)}\n`,
      "utf8",
    );
    await writeFile(
      manifestPath,
      `${JSON.stringify(assembled.manifest, null, 2)}\n`,
      "utf8",
    );
    await writeFile(
      coveragePath,
      `${JSON.stringify(assembled.coverage, null, 2)}\n`,
      "utf8",
    );
    await writeFile(
      reportPath,
      renderReport(assembled.findings.findings, assembled.coverage.completeness),
      "utf8",
    );
    let sarifPath: string | null = null;
    if (assembled.findings.findings.length > 0) {
      sarifPath = join(outputDir, "results.sarif");
      await writeFile(
        sarifPath,
        `${JSON.stringify(
          toSarif(assembled.findings, VERSION, `file://${repository}`),
          null,
          2,
        )}\n`,
        "utf8",
      );
    }

    const reported = assembled.findings.findings;
    const maxSeverity = reported.reduce<SeverityLevel | null>(
      (current, finding) =>
        current === null || meetsFailThreshold(finding.severity.level, current)
          ? finding.severity.level
          : current,
      null,
    );
    const failedThreshold =
      options.failOnSeverity !== undefined &&
      reported.some((finding) =>
        meetsFailThreshold(finding.severity.level, options.failOnSeverity!),
      );
    return {
      scanId,
      outputDir,
      findingsPath,
      manifestPath,
      coveragePath,
      sarifPath,
      reportPath,
      findings: reported.length,
      maxSeverity,
      failedThreshold,
    };
  }
}

function createRuntime(config: RuntimeConfig): AgentRuntime {
  if (config.runtime === "claude-agent") {
    return new ClaudeAgentRuntime(config);
  }
  throw new Error(
    `Runtime "${config.runtime}" is not implemented yet; use "claude-agent".`,
  );
}

function renderReport(
  findings: assembledFindingView[],
  completeness: string,
): string {
  const lines = [
    "# Security Review (diff scan)",
    "",
    `Coverage: ${completeness}`,
    "",
    "## Findings",
    "",
  ];
  if (findings.length === 0) {
    lines.push("No reportable findings.", "");
  }
  for (const finding of findings) {
    lines.push(
      `### [${finding.priority ?? "-"}] ${finding.title} (${finding.severity.level})`,
      "",
      `- Severity: ${finding.severity.level} — ${finding.severity.rationale ?? ""}`,
      `- Confidence: ${finding.confidence.level} — ${finding.confidence.rationale}`,
      `- Category: ${finding.taxonomy.category}${
        finding.taxonomy.cwe.length === 0
          ? ""
          : ` (${finding.taxonomy.cwe.join(", ")})`
      }`,
      `- Location: ${finding.locations
        .map(
          (location) =>
            `${location.path}:${location.startLine}${
              location.endLine === undefined ? "" : `-${location.endLine}`
            }`,
        )
        .join("; ")}`,
      "",
      finding.summary,
      "",
      `Remediation: ${finding.remediation}`,
      "",
    );
  }
  return `${lines.join("\n")}\n`;
}

type assembledFindingView = ReturnType<typeof assemble>["findings"]["findings"][number];
