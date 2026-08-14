#!/usr/bin/env node
import { Command } from "commander";
import { mkdir } from "node:fs/promises";
import { writeFile } from "node:fs/promises";
import { OpenSecurity } from "./index.js";
import { RUNTIME_KINDS } from "./config.js";
import type { SeverityLevel, RuntimeConfig } from "./config.js";
import { loadBenchmarkSuite, runBenchmark } from "./benchmark.js";

const program = new Command();

program
  .name("open-security")
  .description("LLM-driven security diff scanner")
  .version("0.1.0");

interface RuntimeOptions {
  runtime?: string;
  baseUrl?: string;
  acpCommand?: string;
  apiKeyEnv?: string;
  apiKey?: string;
  model?: string;
  maxTurns?: number | string;
}

function runtimeConfigFrom(options: RuntimeOptions): RuntimeConfig {
  const runtime = options.runtime ?? "claude-agent";
  const maxTurns = Number(options.maxTurns ?? 80);
  if (!Number.isInteger(maxTurns) || maxTurns <= 0) {
    throw new Error("--max-turns must be a positive integer.");
  }
  if (runtime === "claude-agent") {
    return {
      runtime: "claude-agent",
      ...(options.baseUrl === undefined
        ? {}
        : { baseUrl: String(options.baseUrl) }),
      ...(options.apiKeyEnv === undefined
        ? {}
        : { apiKeyEnv: String(options.apiKeyEnv) }),
      ...(options.apiKey === undefined
        ? {}
        : { apiKey: String(options.apiKey) }),
      ...(options.model === undefined ? {} : { model: String(options.model) }),
      maxTurnsPerPhase: maxTurns,
    };
  }
  if (runtime === "acp") {
    if (options.acpCommand === undefined) {
      throw new Error("--acp-command is required with --runtime acp.");
    }
    return {
      runtime: "acp",
      acpCommand: String(options.acpCommand),
      ...(options.model === undefined ? {} : { model: String(options.model) }),
      maxTurnsPerPhase: maxTurns,
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
      `Agent runtime: ${RUNTIME_KINDS.join(" | ")} (default: claude-agent)`,
    )
    .option("--base-url <url>", "Anthropic-protocol base URL (claude-agent runtime)")
    .option("--acp-command <command>", "ACP agent command line (acp runtime)")
    .option("--api-key-env <name>", "Environment variable holding the API key")
    .option("--api-key <key>", "API key (prefer --api-key-env)")
    .option("--model <id>", "Model id passed to the runtime")
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
    .requiredOption("--base <ref>", "Git ref the diff starts from")
    .option("--head <ref>", "Git ref the diff ends at (default: HEAD)")
    .option("--working-tree", "Scan staged + unstaged changes against --base")
    .option("--fail-on-severity <level>", "Exit 1 for findings at or above LEVEL")
    .option("--output-dir <dir>", "Output directory for scan artifacts")
    .option("--json", "Print the result summary as JSON"),
).action(async (repository: string, options: Record<string, unknown>) => {
  const scanner = new OpenSecurity({
    runtime: runtimeConfigFrom(options as RuntimeOptions),
  });
  const result = await scanner.scanDiff(repository, {
    base: String(options["base"]),
    head: options["head"] === undefined ? "HEAD" : String(options["head"]),
    workingTree: options["workingTree"] === true,
    ...(options["failOnSeverity"] === undefined
      ? {}
      : {
          failOnSeverity: String(options["failOnSeverity"]) as SeverityLevel,
        }),
    ...(options["outputDir"] === undefined
      ? {}
      : { outputDir: String(options["outputDir"]) }),
  });
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
