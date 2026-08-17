# open-security

LLM-driven security diff scanner. Reviews a Git diff the way a security
engineer would — threat model, candidate discovery, independent validation,
mechanical severity calibration — and emits a structured findings contract,
a human report, and SARIF for CI.

- **CLI + SDK**: `open-security scan` or `new OpenSecurity().scanDiff()`.
- **Pluggable agent runtime**: default adapter drives the Claude Agent SDK
  (any Anthropic-protocol endpoint via `--base-url`); the `pi` runtime runs
  any OpenAI-compatible endpoint, `acp` accepts any ACP agent; inject your own
  runtime through the SDK for other executors.
- **Methodology over vibes**: discovery must cite source evidence; validation
  requires counterevidence to reject; severity is calibrated by a mechanical
  matrix in code, not re-argued by the model.
- **Honest coverage**: complete means every changed file was actually
  reviewed; deferred work is reported, never hidden.

## Security scan methodology

Adapted from the Codex Security plugin (Apache-2.0, see NOTICE):

1. **Inventory** — deterministic changed-file list (deleted files kept,
   dependency/build/test directories excluded).
2. **Threat model** — repository-wide model, cached per revision, reused
   across scans.
3. **Discovery** — candidates grounded in the actual diff with
   source/sink/control anchors; anti-hallucination rules enforced in the
   prompt.
4. **Validation** — each candidate gets a fresh session; rejection requires
   source-backed counterevidence; proof gaps are recorded, never papered
   over.
5. **Severity** — impact × likelihood matrix plus hard suppression rules,
   applied mechanically in TypeScript.
6. **Contract** — `findings.json`, `scan-manifest.json`, `coverage.json`,
   `report.md`, and SARIF 2.1.0 with stable fingerprints.

## CLI

Two scan modes: **diff scan** (review a change set, the CI gate) and
**repository scan** (ranked whole-repo review — omit `--base`).

```bash
# Repository-wide scan: works on Git repositories AND plain directories.
# Files are ranked by security relevance (auth, crypto, SQL, parsers, ...),
# top 150 deep-reviewed in batches, the rest honestly reported as deferred.
# Non-Git targets get a directory_snapshot identity (content digest).
open-security scan . --max-files 150

# Diff scan:
open-security scan . \
  --base origin/main \
  --base-url https://llm-gateway.internal/v1 \
  --api-key-env INTERNAL_LLM_KEY \
  --model my-model \
  --fail-on-severity high \
  --output-dir out/
```

Notes:

- For the default `claude-agent` runtime, `--base-url` endpoints must speak
  the Anthropic Messages API. For OpenAI-compatible endpoints use
  `--runtime pi` instead (see below).
- The agent runs with read-only tools (`Read`, `Grep`, `Glob`) — the scanner
  never modifies the repository under review.
- Exit code 1 when a finding meets `--fail-on-severity`; exit code 2 on
  operational errors. `--json` prints a machine-readable summary.

### ACP runtime

Any Agent Client Protocol agent works as the executor. The agent process is
launched fresh per pipeline phase (session isolation), model routing belongs
to the agent's own configuration, and open-security enforces a read-only tool
policy (only `read`, `search`, and `think` tool kinds are approved):

```bash
open-security scan . --base origin/main \
  --runtime acp --acp-command "claude-code-acp"
```

### pi runtime (OpenAI-compatible and Anthropic endpoints)

The `pi` runtime embeds the [pi](https://github.com/earendil-works/pi) agent
loop in-process and routes it at any OpenAI Chat Completions-compatible
endpoint — OpenAI, DeepSeek, Kimi, Qwen, OpenRouter, vLLM, Ollama (`/v1`),
LiteLLM, or an internal gateway — and equally at Anthropic Messages
endpoints. One runtime covers both wire protocols:

```bash
# OpenAI-compatible endpoint (--runtime pi is inferred from --base-url):
open-security scan . --base origin/main \
  --base-url https://api.deepseek.com/v1 \
  --api-key-env DEEPSEEK_API_KEY \
  --model deepseek-chat

# Anthropic endpoint via pi (--api selects the pi runtime by itself):
open-security scan . --base origin/main \
  --api anthropic-messages \
  --base-url https://api.anthropic.com \
  --api-key-env ANTHROPIC_API_KEY \
  --model claude-sonnet-4-5
```

Rule set when flags are omitted:

- Wire protocol (`--api`) defaults to `openai-completions` — it is never
  guessed from the URL. An explicit `--api` always selects the pi runtime.
- Runtime: bare invocations (no `--base-url`) and Anthropic-looking base
  URLs use the default claude-agent runtime; any other `--base-url`
  auto-selects pi.
- Pointing pi at an Anthropic-looking URL without `--api` fails fast with a
  hint instead of sending OpenAI-shaped requests to an Anthropic endpoint.

Read-only policy is enforced by construction: pi's built-in tools (bash,
edit, write) are disabled and the only registered tools are open-security's
own inspection tools (`read_file`, `glob_files`, `search_files`, `git_show`),
all confined to the repository root. Sessions are in-memory and the pi config
directory is a throwaway temp dir — nothing is written into the scanned
repository and no user-level pi settings, skills, or credentials leak in.

Model choice is the main quality lever for this runtime: the workload needs
long context and reliable tool calling, so pick models known for both (for
example DeepSeek-V3.x, Kimi k2, GPT-class or Claude models). Small
locally-served models without solid tool-calling will underperform.

### Quality benchmark

Measure recall and precision against repositories with known ground-truth
findings before trusting the scanner as a CI gate:

```bash
open-security benchmark suite.json --output-dir benchmark-out/ \
  --base-url https://llm-gateway.internal/v1 \
  --api-key-env INTERNAL_LLM_KEY --model my-model
```

`suite.json` lists cases (repository, diff refs) plus expected findings
(category + path, optional minimum severity); see
`tests/fixtures/benchmark-suite.example.json`. The report lands in
`benchmark-out/benchmark-report.json`. Harness mechanics are covered by the
test suite with a mock runtime; the quality numbers themselves depend on your
model and prompts — run them against your internal endpoint first.

## Install

```bash
npm install @dawnswwwww/open-security
npx @dawnswwwww/open-security --help
```

The CLI command is `open-security` regardless of the scoped package name.

## SDK

```ts
import { OpenSecurity } from "@dawnswwwww/open-security";

const scanner = new OpenSecurity({
  runtime: {
    runtime: "claude-agent",
    baseUrl: "https://llm-gateway.internal/v1",
    apiKeyEnv: "INTERNAL_LLM_KEY",
    model: "my-model",
  },
});

const result = await scanner.scanDiff(".", {
  base: "origin/main",
  failOnSeverity: "high",
});
console.log(result.reportPath, result.maxSeverity);
```

Custom executors (ACP agents, direct API loops) plug in via the `agent`
injection point:

```ts
const scanner = new OpenSecurity({
  runtime: { runtime: "claude-agent", maxTurnsPerPhase: 400 // optional cap; omit for unlimited },
  agent: myRuntime, // implements AgentRuntime
});
```

## Development

```bash
npm install
npm run lint    # tsc --noEmit
npm test        # vitest
npm run build
```

Tests run the full pipeline against a fixture Git repository with a mock
agent runtime — no model access required.

## License

Apache-2.0. Methodology and contract structures adapted from
openai/codex-security (Apache-2.0); see NOTICE.
