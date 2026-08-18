import { mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import {
  meetsFailThreshold,
  type OpenSecurityConfig,
  type RepositoryScanOptions,
  type RuntimeConfig,
  type ScanOptions,
  type SeverityLevel,
} from "./config.js";
import type { AgentRuntime } from "./runtime/types.js";
import { AcpRuntime } from "./runtime/acp.js";
import { PiRuntime } from "./runtime/pi.js";
import {
  diffHunks,
  diffTargetId,
  listChangedFiles,
  listRepositoryFiles,
  remoteUrl,
  repositoryTargetId,
  resolveGitRoot,
  resolveRevision,
  type DiffSpec,
} from "./git.js";
import {
  buildInventory,
  buildRepositoryInventory,
  type ScanInventory,
} from "./pipeline/inventory.js";
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
import {
  directoryTargetId,
  scanDirectory,
} from "./directory.js";
import { VERSION } from "./version.js";
import type { ScanProgressCallback } from "./progress.js";
import { UsageMeter, type ScanUsage } from "./usage.js";

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
export type {
  ScanPhaseKind,
  ScanPhaseUsage,
  ScanUsage,
  UsageTotals,
} from "./usage.js";

export interface ScanResult {
  scanId: string;
  outputDir: string;
  findingsPath: string;
  manifestPath: string;
  coveragePath: string;
  usagePath: string;
  sarifPath: string | null;
  reportPath: string;
  findings: number;
  /** Highest severity among reported findings, when any. */
  maxSeverity: SeverityLevel | null;
  /** true when a reported finding meets the failOnSeverity threshold. */
  failedThreshold: boolean;
  /** Token/cost/duration accounting for the scan's agent runs. */
  usage: ScanUsage;
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
    const repository = await resolveGitRoot(repositoryInput).catch(() => {
      throw new Error(
        `Diff scans require a Git repository and ${repositoryInput} is not one. ` +
          "Omit --base to scan a plain directory instead.",
      );
    });
    const spec: DiffSpec = {
      base: options.base,
      head: options.head,
      workingTree: options.workingTree,
    };
    const baseSha = await resolveRevision(repository, options.base);
    const headSha = options.workingTree
      ? undefined
      : await resolveRevision(repository, options.head);
    const scanId = newScanId();
    const outputDir =
      options.outputDir === undefined
        ? join(repository, "..", ".open-security", scanId)
        : options.outputDir;
    const changed = await listChangedFiles(repository, spec);
    const hunks = await diffHunks(repository, spec);
    const inventory = buildInventory(changed, hunks);
    const targetId = diffTargetId(spec.workingTree, baseSha, headSha);
    return await this.#executeScan({
      repository,
      scanId,
      outputDir,
      inventory,
      targetId,
      origin: "diff",
      baseSha,
      ...(headSha === undefined ? {} : { headSha }),
      workingTree: spec.workingTree,
      ...(options.failOnSeverity === undefined
        ? {}
        : { failOnSeverity: options.failOnSeverity }),
      diffSummary: `base=${spec.base} head=${
        spec.workingTree ? "working-tree" : spec.head
      }, ${changed.length} changed file(s), ${inventory.files.length} in review scope.`,
      ...(onProgress === undefined ? {} : { onProgress }),
    });
  }

  public async scanRepository(
    repositoryInput: string,
    options: RepositoryScanOptions,
    onProgress?: ScanProgressCallback,
  ): Promise<ScanResult> {
    let repository: string;
    let tracked: string[];
    let revisionKey: string;
    let targetId: string;
    let snapshotDigest: string | undefined;
    let headSha: string | undefined;
    const isGit = await resolveGitRoot(repositoryInput)
      .then(() => true)
      .catch(() => false);
    if (isGit) {
      repository = await resolveGitRoot(repositoryInput);
      headSha = await resolveRevision(repository, options.head ?? "HEAD");
      tracked = await listRepositoryFiles(repository);
      revisionKey = headSha;
      targetId = repositoryTargetId(headSha);
    } else {
      const snapshot = await scanDirectory(repositoryInput);
      repository = snapshot.root;
      tracked = snapshot.allPaths;
      revisionKey = snapshot.digest;
      targetId = directoryTargetId(snapshot.digest);
      snapshotDigest = snapshot.digest;
    }
    const scanId = newScanId();
    const outputDir =
      options.outputDir === undefined
        ? join(repository, "..", ".open-security", scanId)
        : options.outputDir;
    const inventory = buildRepositoryInventory(
      tracked,
      options.maxFiles ?? 150,
    );
    return await this.#executeScan({
      repository,
      scanId,
      outputDir,
      inventory,
      targetId,
      origin: "repository",
      ...(headSha === undefined ? {} : { headSha }),
      ...(snapshotDigest === undefined ? {} : { snapshotDigest }),
      workingTree: false,
      ...(options.failOnSeverity === undefined
        ? {}
        : { failOnSeverity: options.failOnSeverity }),
      diffSummary:
        `repository-wide scan at ${revisionKey.slice(0, 12)}: ` +
        `${inventory.files.length} file(s) selected for deep review` +
        (inventory.deferredNotReviewed === undefined
          ? ""
          : `, ${inventory.deferredNotReviewed.length} ranked out (deferred)`),
      ...(onProgress === undefined ? {} : { onProgress }),
    });
  }

  async #executeScan(input: {
    repository: string;
    scanId: string;
    outputDir: string;
    inventory: ScanInventory;
    targetId: string;
    origin: "diff" | "repository";
    baseSha?: string;
    headSha?: string;
    snapshotDigest?: string;
    workingTree: boolean;
    failOnSeverity?: SeverityLevel;
    diffSummary: string;
    onProgress?: ScanProgressCallback;
  }): Promise<ScanResult> {
    const { onProgress } = input;
    const startedAt = new Date();
    await mkdir(input.outputDir, { recursive: true });
    const meter = new UsageMeter(this.#runtime);

    // ① inventory
    onProgress?.({
      phase: "inventory",
      filesInScope: input.inventory.files.length,
      excluded: input.inventory.excluded.length,
    });

    // ② threat model (cached per repository + head revision)
    const cacheRevision = input.headSha ?? `worktree-${input.baseSha ?? "none"}`;
    let threatModelCached = false;
    const beforeThreatModel = meter.snapshot();
    const threatModel = await loadThreatModel({
      runtime: meter.runtime,
      repository: input.repository,
      cacheKey: threatModelCacheKey(input.repository, cacheRevision),
      cacheDir: join(input.repository, "..", ".open-security", "cache"),
      ...(this.#config.runtime.maxTurnsPerPhase === undefined
        ? {}
        : { maxTurns: this.#config.runtime.maxTurnsPerPhase }),
      ...(this.#config.signal === undefined
        ? {}
        : { signal: this.#config.signal }),
      onCacheStatus: (status) => {
        threatModelCached = status === "cached";
        onProgress?.({ phase: "threat-model", status });
      },
    });
    const threatModelUsage = meter.phaseUsage(
      beforeThreatModel,
      "threat-model",
      threatModelCached,
    );
    onProgress?.({ phase: "threat-model", status: "done" });
    const securityMd = await resolveSecurityMd(input.repository);
    const threatModelText = JSON.stringify(threatModel, null, 2);

    // ③ discovery (batched; the first batch event reports the running state)
    const beforeDiscovery = meter.snapshot();
    const candidates = await runDiscovery({
      runtime: meter.runtime,
      repository: input.repository,
      inventory: input.inventory,
      threatModel: threatModelText,
      securityMd,
      diffSummary: input.diffSummary,
      ...(this.#config.runtime.maxTurnsPerPhase === undefined
        ? {}
        : { maxTurns: this.#config.runtime.maxTurnsPerPhase }),
      ...(this.#config.signal === undefined
        ? {}
        : { signal: this.#config.signal }),
      onBatchProgress: (batch, batches) =>
        onProgress?.({
          phase: "discovery",
          status: "running",
          files: input.inventory.files.length,
          batch,
          batches,
        }),
    });
    const discoveryUsage = meter.phaseUsage(beforeDiscovery, "discovery");
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
    const beforeValidation = meter.snapshot();
    const validated = await runValidation({
      runtime: meter.runtime,
      repository: input.repository,
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
    const validationUsage = meter.phaseUsage(beforeValidation, "validation");
    onProgress?.({ phase: "validation", status: "done" });

    // ⑤⑥ severity + assemble
    const remote = await remoteUrl(input.repository);
    const assembled = assemble({
      scanId: input.scanId,
      startedAt,
      completedAt: new Date(),
      targetId: input.targetId,
      displayName: input.repository,
      ...(remote === undefined ? {} : { remote }),
      ...(input.baseSha === undefined ? {} : { baseRevision: input.baseSha }),
      ...(input.headSha === undefined ? {} : { headRevision: input.headSha }),
      workingTree: input.workingTree,
      origin: input.origin,
      ...(input.snapshotDigest === undefined
        ? {}
        : { snapshotDigest: input.snapshotDigest }),
      inventory: input.inventory,
      threatModel,
      validated,
      producer: { name: "open-security", version: VERSION },
    });
    onProgress?.({
      phase: "assemble",
      findings: assembled.findings.findings.length,
      deferred: assembled.coverage.deferred.length,
    });

    const outputDir = input.outputDir;
    const findingsPath = join(outputDir, "findings.json");
    const manifestPath = join(outputDir, "scan-manifest.json");
    const coveragePath = join(outputDir, "coverage.json");
    const usagePath = join(outputDir, "usage.json");
    const reportPath = join(outputDir, "report.md");
    const usage = meter.buildScanUsage({
      scanId: input.scanId,
      runtime: this.#runtime.kind,
      totals: meter.snapshot(),
      phases: [threatModelUsage, discoveryUsage, validationUsage],
    });
    await writeFile(
      usagePath,
      `${JSON.stringify(usage, null, 2)}\n`,
      "utf8",
    );
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
        includePaths: input.inventory.files.map((file) => file.path),
        excludedPaths: input.inventory.excluded,
        ...(input.inventory.deferredNotReviewed === undefined
          ? {}
          : { deferredNotReviewed: input.inventory.deferredNotReviewed }),
        threatModelSummary: threatModel.summary,
        origin: input.origin,
        ...(input.snapshotDigest === undefined
          ? {}
          : { snapshotDigest: input.snapshotDigest }),
        ...(input.baseSha === undefined
          ? {}
          : { baseRevision: input.baseSha }),
        ...(input.headSha === undefined ? {} : { headRevision: input.headSha }),
        workingTree: input.workingTree,
      }),
      "utf8",
    );
    let sarifPath: string | null = null;
    if (assembled.findings.findings.length > 0) {
      sarifPath = join(outputDir, "results.sarif");
      await writeFile(
        sarifPath,
        `${JSON.stringify(
          toSarif(assembled.findings, VERSION, `file://${input.repository}`),
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
      input.failOnSeverity !== undefined &&
      reported.some((finding) =>
        meetsFailThreshold(finding.severity.level, input.failOnSeverity!),
      );
    const result: ScanResult = {
      scanId: input.scanId,
      outputDir,
      findingsPath,
      manifestPath,
      coveragePath,
      usagePath,
      sarifPath,
      reportPath,
      findings: reported.length,
      maxSeverity,
      failedThreshold,
      usage,
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
  if (config.runtime === "pi") {
    return new PiRuntime(config);
  }
  return new AcpRuntime({ acpCommand: config.acpCommand });
}

const REPORT_LIST_CAP = 50;

function renderReport(input: {
  findings: assembledFindingView[];
  completeness: string;
  includePaths: readonly string[];
  excludedPaths: readonly string[];
  deferredNotReviewed?: readonly string[];
  threatModelSummary: string;
  origin: "diff" | "repository";
  baseRevision?: string;
  headRevision?: string;
  snapshotDigest?: string;
  workingTree: boolean;
}): string {
  const { findings, completeness } = input;
  const range =
    input.origin === "repository"
      ? input.snapshotDigest === undefined
        ? `revision ${(input.headRevision ?? "").slice(0, 12)}`
        : `directory snapshot ${input.snapshotDigest.slice(0, 12)}`
      : input.workingTree
        ? `${(input.baseRevision ?? "").slice(0, 12)}…working-tree`
        : `${(input.baseRevision ?? "").slice(0, 12)}…${(input.headRevision ?? "").slice(0, 12)}`;
  const reviewed =
    input.includePaths.length > REPORT_LIST_CAP
      ? [
          ...input.includePaths.slice(0, REPORT_LIST_CAP).map((path) => `- reviewed: ${path}`),
          `- … and ${input.includePaths.length - REPORT_LIST_CAP} more reviewed file(s)`,
        ]
      : input.includePaths.map((path) => `- reviewed: ${path}`);
  const excluded =
    input.excludedPaths.length > REPORT_LIST_CAP
      ? [
          `- excluded (inventory rules): ${input.excludedPaths.length} file(s) (docs, tests, vendored, lockfiles, ...)`,
        ]
      : input.excludedPaths.map(
          (path) => `- excluded (inventory rules): ${path}`,
        );
  const deferred =
    input.deferredNotReviewed === undefined
      ? []
      : [
          `- deferred (ranked below the repository review cap): ${input.deferredNotReviewed.length} file(s)`,
        ];
  const lines = [
    input.origin === "repository"
      ? "# Security Review (repository scan)"
      : "# Security Review (diff scan)",
    "",
    `Coverage: ${completeness}`,
    `Range: ${range}`,
    "",
    "## Scope",
    "",
    ...reviewed,
    ...excluded,
    ...deferred,
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
