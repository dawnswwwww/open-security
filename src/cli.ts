#!/usr/bin/env node
import { Command } from "commander";
import { mkdir } from "node:fs/promises";
import { writeFile } from "node:fs/promises";
import { OpenSecurity } from "./index.js";
import {
  DEFAULT_PI_API_KEY_ENV,
  DEFAULT_PI_BASE_URL,
  DEFAULT_PI_MODEL,
  inferPiApi,
  RUNTIME_KINDS,
  type PiApiKind,
} from "./config.js";
import type { SeverityLevel, RuntimeConfig } from "./config.js";
import { loadBenchmarkSuite, runBenchmark } from "./benchmark.js";
import { VERSION } from "./version.js";
import type { ScanProgressEvent } from "./progress.js";
import { renderUsageReport } from "./usage.js";

const START_TIME = Date.now();

/** Renders progress events as timestamped stderr lines; stdout stays clean. */
function progressLine(event: ScanProgressEvent): string {
  const elapsed = `${((Date.now() - START_TIME) / 1000).toFixed(0)}s`;
  switch (event.phase) {
    case "inventory":
      return `[${elapsed}] inventory: ${event.filesInScope} file(s) in review scope, ${event.excluded} excluded`;
    case "threat-model":
      return event.status === "cached"
        ? `[${elapsed}] threat model: loaded from cache`
        : `[${elapsed}] threat model: ${event.status}${event.status === "running" ? " (large repositories can take several minutes)" : ""}`;
    case "discovery":
      if (event.status === "done") {
        return `[${elapsed}] discovery: ${event.candidates} candidate(s) found`;
      }
      return event.batch === undefined
        ? `[${elapsed}] discovery: reviewing ${event.files} file(s)`
        : `[${elapsed}] discovery: batch ${event.batch}/${event.batches} (25 files per batch)`;
    case "validation":
      return event.status === "running"
        ? `[${elapsed}] validation: candidate ${event.completed}/${event.total} (each candidate gets an independent session)`
        : `[${elapsed}] validation: done`;
    case "assemble":
      return `[${elapsed}] assemble: ${event.findings} finding(s) reportable, ${event.deferred} deferred`;
    case "complete":
      return `[${elapsed}] complete: ${event.findings} finding(s), output in ${event.outputDir}`;
  }
}

const program = new Command();

program
  .name("open-security")
  .description("LLM-driven security diff scanner")
  .version(VERSION);

interface RuntimeOptions {
  runtime?: string;
  baseUrl?: string;
  api?: string;
  provider?: string;
  acpCommand?: string;
  apiKeyEnv?: string;
  apiKey?: string;
  model?: string;
  maxTurns?: number | string;
}

function parsePiApi(value: string): PiApiKind {
  if (value === "openai-completions" || value === "anthropic-messages") {
    return value;
  }
  throw new Error(
    "--api must be openai-completions or anthropic-messages (pi runtime).",
  );
}

function runtimeConfigFrom(options: RuntimeOptions): RuntimeConfig {
  const api =
    options.api === undefined ? undefined : parsePiApi(String(options.api));
  const runtime = options.runtime ?? "pi";
  if (api !== undefined && runtime !== "pi") {
    throw new Error("--api applies to the pi runtime only.");
  }
  const maxTurns =
    options.maxTurns === undefined ? undefined : Number(options.maxTurns);
  if (maxTurns !== undefined && (!Number.isInteger(maxTurns) || maxTurns <= 0)) {
    throw new Error("--max-turns must be a positive integer.");
  }
  const turnLimit = maxTurns === undefined ? {} : { maxTurnsPerPhase: maxTurns };
  if (runtime === "acp") {
    if (options.acpCommand === undefined) {
      throw new Error("--acp-command is required with --runtime acp.");
    }
    return {
      runtime: "acp",
      acpCommand: String(options.acpCommand),
      ...(options.model === undefined ? {} : { model: String(options.model) }),
      ...turnLimit,
    };
  }
  if (runtime === "pi") {
    const defaultEndpoint = options.baseUrl === undefined;
    if (options.model === undefined && !defaultEndpoint) {
      throw new Error(
        `--model is required with an explicit --base-url; it only defaults to ${DEFAULT_PI_MODEL} on the default ${DEFAULT_PI_BASE_URL} endpoint.`,
      );
    }
    const baseUrl = defaultEndpoint ? DEFAULT_PI_BASE_URL : String(options.baseUrl);
    // The default key env belongs to the default endpoint only, so explicit
    // OpenAI-style endpoints are never pointed at ANTHROPIC_API_KEY.
    const apiKeyEnv =
      options.apiKeyEnv !== undefined
        ? String(options.apiKeyEnv)
        : defaultEndpoint && options.apiKey === undefined
          ? DEFAULT_PI_API_KEY_ENV
          : undefined;
    return {
      runtime: "pi",
      baseUrl,
      model: options.model === undefined
        ? DEFAULT_PI_MODEL
        : String(options.model),
      api: inferPiApi(baseUrl, api),
      ...(options.provider === undefined
        ? {}
        : { provider: String(options.provider) }),
      ...(apiKeyEnv === undefined ? {} : { apiKeyEnv }),
      ...(options.apiKey === undefined
        ? {}
        : { apiKey: String(options.apiKey) }),
      ...turnLimit,
    };
  }
  throw new Error(
    `Unknown runtime: ${runtime}; expected one of ${RUNTIME_KINDS.join(" | ")}.`,
  );
}

function addRuntimeOptions(command: Command): Command {
  return command
    .option(
      "--runtime <kind>",
      `Agent runtime: ${RUNTIME_KINDS.join(" | ")} (default: pi)`,
    )
    .option(
      "--base-url <url>",
      `Model API root (default: ${DEFAULT_PI_BASE_URL}); OpenAI-compatible endpoints use the openai wire protocol`,
    )
    .option(
      "--api <protocol>",
      "Wire protocol for the pi runtime: openai-completions | anthropic-messages (default: inferred from --base-url)",
    )
    .option(
      "--provider <name>",
      "pi runtime provider label for credential resolution (default: inferred)",
    )
    .option("--acp-command <command>", "ACP agent command line (acp runtime)")
    .option(
      "--api-key-env <name>",
      `Environment variable holding the API key (default: ${DEFAULT_PI_API_KEY_ENV} on the default endpoint)`,
    )
    .option("--api-key <key>", "API key (prefer --api-key-env)")
    .option(
      "--model <id>",
      `Model id passed to the runtime (default: ${DEFAULT_PI_MODEL} on the default endpoint)`,
    )
    .option(
      "--max-turns <n>",
      "Max agent turns per phase",
      (value) => Number(value),
      80,
    );
}

addRuntimeOptions(
  program
    .command("scan")
    .description("Scan a Git diff for security vulnerabilities")
    .argument("[repository]", "repository path", ".")
    .option(
      "--base <ref>",
      "Git ref the diff starts from; omit for a repository-wide scan",
    )
    .option("--head <ref>", "Git ref to scan (default: HEAD)")
    .option(
      "--max-files <n>",
      "Repository scans: cap on deep-reviewed files after ranking (default: 150)",
      Number,
    )
    .option("--working-tree", "Scan staged + unstaged changes against --base")
    .option("--fail-on-severity <level>", "Exit 1 for findings at or above LEVEL")
    .option("--output-dir <dir>", "Output directory for scan artifacts")
    .option("--json", "Print the result summary as JSON"),
).action(async (repository: string, options: Record<string, unknown>) => {
  const scanner = new OpenSecurity({
    runtime: runtimeConfigFrom(options as RuntimeOptions),
  });
  const onProgress = (event: ScanProgressEvent): void => {
    process.stderr.write(`${progressLine(event)}\n`);
  };
  const failOnSeverity =
    options["failOnSeverity"] === undefined
      ? {}
      : {
          failOnSeverity: String(options["failOnSeverity"]) as SeverityLevel,
        };
  const outputDir =
    options["outputDir"] === undefined
      ? {}
      : { outputDir: String(options["outputDir"]) };
  if (options["base"] === undefined && options["workingTree"] === true) {
    throw new Error(
      "--working-tree requires --base; omit both for a repository scan.",
    );
  }
  const result =
    options["base"] === undefined
      ? await scanner.scanRepository(
            repository,
            {
              ...(options["head"] === undefined
                ? {}
                : { head: String(options["head"]) }),
              ...(options["maxFiles"] === undefined
                ? {}
                : { maxFiles: Number(options["maxFiles"]) }),
              ...failOnSeverity,
              ...outputDir,
            },
            onProgress,
          )
      : await scanner.scanDiff(
          repository,
          {
            base: String(options["base"]),
            head: options["head"] === undefined ? "HEAD" : String(options["head"]),
            workingTree: options["workingTree"] === true,
            ...failOnSeverity,
            ...outputDir,
          },
          onProgress,
        );
  if (options["json"] === true) {
    process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
  } else {
    process.stdout.write(
      [
        `Scan ${result.scanId} completed: ${result.findings} finding(s).`,
        `Report: ${result.reportPath}`,
        result.sarifPath === null ? "" : `SARIF: ${result.sarifPath}`,
        "",
      ]
        .filter((line) => line.length > 0)
        .join("\n"),
    );
  }
  process.stderr.write(
    `${renderUsageReport(result.usage, Date.now() - START_TIME).join("\n")}\n`,
  );
  if (result.failedThreshold) {
    process.exitCode = 1;
  }
});

addRuntimeOptions(
  program
    .command("benchmark")
    .description("Measure recall/precision against known ground-truth findings")
    .argument("<suite>", "benchmark suite JSON (cases with expected findings)")
    .requiredOption("--output-dir <dir>", "Directory for scan artifacts and the report")
    .option("--json", "Print the benchmark report as JSON"),
).action(async (suitePath: string, options: Record<string, unknown>) => {
  const cases = await loadBenchmarkSuite(String(suitePath));
  const outputDir = String(options["outputDir"]);
  await mkdir(outputDir, { recursive: true });
  const scanner = new OpenSecurity({
    runtime: runtimeConfigFrom(options as RuntimeOptions),
  });
  const report = await runBenchmark({ scanner, cases, outputRoot: outputDir });
  const reportPath = `${outputDir}/benchmark-report.json`;
  await writeFile(reportPath, `${JSON.stringify(report, null, 2)}\n`, "utf8");
  if (options["json"] === true) {
    process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
  } else {
    for (const caseReport of report.cases) {
      process.stdout.write(
        `${caseReport.name}: recall=${caseReport.recall.toFixed(2)} precision=${caseReport.precision.toFixed(2)} (${caseReport.matched.length}/${caseReport.expected} matched, ${caseReport.unexpected.length} unexpected)${caseReport.error === undefined ? "" : ` ERROR: ${caseReport.error}`}\n`,
      );
    }
    process.stdout.write(
      `TOTAL: recall=${report.totals.recall.toFixed(2)} precision=${report.totals.precision.toFixed(2)} — ${reportPath}\n`,
    );
  }
});

program.parseAsync(process.argv).catch((error: unknown) => {
  process.stderr.write(
    `open-security: ${error instanceof Error ? error.message : String(error)}\n`,
  );
  process.exitCode = 2;
});
