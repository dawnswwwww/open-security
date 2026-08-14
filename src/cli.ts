#!/usr/bin/env node
import { Command } from "commander";
import { OpenSecurity } from "./index.js";
import { RUNTIME_KINDS, meetsFailThreshold } from "./config.js";
import type { SeverityLevel } from "./config.js";

const program = new Command();

program
  .name("open-security")
  .description("LLM-driven security diff scanner")
  .version("0.1.0");

program
  .command("scan")
  .description("Scan a Git diff for security vulnerabilities")
  .argument("[repository]", "repository path", ".")
  .requiredOption("--base <ref>", "Git ref the diff starts from")
  .option("--head <ref>", "Git ref the diff ends at (default: HEAD)")
  .option("--working-tree", "Scan staged + unstaged changes against --base")
  .option("--runtime <kind>", `Agent runtime: ${RUNTIME_KINDS.join(" | ")}`, "claude-agent")
  .option("--base-url <url>", "Anthropic-protocol base URL (claude-agent runtime)")
  .option("--api-key-env <name>", "Environment variable holding the API key")
  .option("--api-key <key>", "API key (prefer --api-key-env)")
  .option("--model <id>", "Model id passed to the runtime")
  .option("--max-turns <n>", "Max agent turns per phase", (value) => Number(value), 80)
  .option("--fail-on-severity <level>", "Exit 1 for findings at or above LEVEL")
  .option("--output-dir <dir>", "Output directory for scan artifacts")
  .option("--json", "Print the result summary as JSON")
  .action(async (repository: string, options: Record<string, unknown>) => {
    const runtime = String(options["runtime"]);
    const runtimeConfig =
      runtime === "claude-agent"
        ? {
            runtime: "claude-agent" as const,
            ...(options["baseUrl"] === undefined
              ? {}
              : { baseUrl: String(options["baseUrl"]) }),
            ...(options["apiKeyEnv"] === undefined
              ? {}
              : { apiKeyEnv: String(options["apiKeyEnv"]) }),
            ...(options["apiKey"] === undefined
              ? {}
              : { apiKey: String(options["apiKey"]) }),
            ...(options["model"] === undefined
              ? {}
              : { model: String(options["model"]) }),
            maxTurnsPerPhase: options["maxTurns"] as number,
          }
        : runtime === "acp"
          ? (() => {
              throw new Error(
                "The acp runtime is not implemented yet; use --runtime claude-agent.",
              );
            })()
          : (() => {
              throw new Error(`Unknown runtime: ${runtime}`);
            })();
    const scanner = new OpenSecurity({ runtime: runtimeConfig });
    const result = await scanner.scanDiff(repository, {
      base: String(options["base"]),
      head: options["head"] === undefined ? "HEAD" : String(options["head"]),
      workingTree: options["workingTree"] === true,
      ...(options["failOnSeverity"] === undefined
        ? {}
        : {
            failOnSeverity: String(
              options["failOnSeverity"],
            ) as SeverityLevel,
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

program.parseAsync(process.argv).catch((error: unknown) => {
  process.stderr.write(
    `open-security: ${error instanceof Error ? error.message : String(error)}\n`,
  );
  process.exitCode = 2;
});

export { meetsFailThreshold };
