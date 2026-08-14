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
import { AcpRuntime } from "./runtime/acp.js";
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
import type { ScanProgressCallback } from "./progress.js";

export type {
  OpenSecurityConfig,
  RuntimeConfig,
  RuntimeKind,
  ScanOptions,
  SeverityLevel,
} from "./config.js";
export type {
  AgentRuntime,
  AgentRunRequest,
  AgentRunResult,
} from "./runtime/types.js";
export { RUNTIME_KINDS, meetsFailThreshold } from "./config.js";
export type {
  ScanProgressEvent,
  ScanProgressCallback,
} from "./progress.js";

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
    onProgress?: ScanProgressCallback,
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
    onProgress?.({
      phase: "inventory",
      filesInScope: inventory.files.length,
      excluded: inventory.excluded.length,
    });

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
      onCacheStatus: (status) => onProgress?.({ phase: "threat-model", status }),
    });
    onProgress?.({ phase: "threat-model", status: "done" });
    const securityMd = await resolveSecurityMd(repository);
    const threatModelText = JSON.stringify(threatModel, null, 2);

    // ③ discovery
    onProgress?.({
      phase: "discovery",
      status: "running",
      files: inventory.files.length,
    });
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
    onProgress?.({
      phase: "discovery",
      status: "done",
      candidates: candidates.length,
    });

    // ④ validation (fresh session per candidate)
    if (candidates.length > 0) {
      onProgress?.({
        phase: "validation",
        status: "running",
        completed: 0,
        total: candidates.length,
      });
    }
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
      onProgress: (completed, total) =>
        onProgress?.({ phase: "validation", status: "running", completed, total }),
    });
    onProgress?.({ phase: "validation", status: "done" });

    // ⑤⑥ severity + assemble
    const targetId = diffTargetId(spec.workingTree, baseSha, headSha);
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
    onProgress?.({
      phase: "assemble",
      findings: assembled.findings.findings.length,
      deferred: assembled.coverage.deferred.length,
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
      renderReport({
        findings: assembled.findings.findings,
        completeness: assembled.coverage.completeness,
        includePaths: inventory.files.map((file) => file.path),
        excludedPaths: inventory.excluded,
        threatModelSummary: threatModel.summary,
        baseRevision: baseSha,
        ...(headSha === undefined ? {} : { headRevision: headSha }),
        workingTree: spec.workingTree,
      }),
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
    const result: ScanResult = {
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
    onProgress?.({
      phase: "complete",
      findings: result.findings,
      outputDir,
    });
    return result;
  }
}

function createRuntime(config: RuntimeConfig): AgentRuntime {
  if (config.runtime === "claude-agent") {
    return new ClaudeAgentRuntime(config);
  }
  return new AcpRuntime({ acpCommand: config.acpCommand });
}

function renderReport(input: {
  findings: assembledFindingView[];
  completeness: string;
  includePaths: readonly string[];
  excludedPaths: readonly string[];
  threatModelSummary: string;
  baseRevision: string;
  headRevision?: string;
  workingTree: boolean;
}): string {
  const { findings, completeness } = input;
  const range = input.workingTree
    ? `${input.baseRevision.slice(0, 12)}…working-tree`
    : `${input.baseRevision.slice(0, 12)}…${(input.headRevision ?? "").slice(0, 12)}`;
  const lines = [
    "# Security Review (diff scan)",
    "",
    `Coverage: ${completeness}`,
    `Range: ${range}`,
    "",
    "## Scope",
    "",
    ...input.includePaths.map((path) => `- reviewed: ${path}`),
    ...input.excludedPaths.map(
      (path) => `- excluded (inventory rules): ${path}`,
    ),
    "",
    "## Threat Model (repository-wide summary)",
    "",
    input.threatModelSummary,
    "",
    "## Findings",
    "",
  ];
  if (findings.length === 0) {
    lines.push(
      "No reportable findings. Every changed file in scope was reviewed and",
      "no plausible security candidate survived validation.",
      "",
    );
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
