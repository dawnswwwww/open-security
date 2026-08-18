# open-security

LLM-driven security diff scanner. Reviews a Git diff the way a security
engineer would — threat model, candidate discovery, independent validation,
mechanical severity calibration — and emits a structured findings contract,
a human report, and SARIF for CI.

- **CLI + SDK**: `open-security scan` or `new OpenSecurity().scanDiff()`.
- **Pluggable agent runtime**: the default `pi` runtime embeds the pi agent
  loop and runs any OpenAI-compatible or Anthropic endpoint (zero-config
  against `https://api.anthropic.com`); `acp` accepts any ACP agent; inject
  your own runtime through the SDK for other executors.
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
   `report.md`, and SARIF 2.1.0 with stable fingerprints. A `usage.json`
   artifact and a stderr report close the scan with per-phase token, cost,
   turn, and duration accounting.

## CLI

Two scan modes: **diff scan** (review a change set, the CI gate) and
**repository scan** (ranked whole-repo review — omit `--base`).

```bash
# Zero-config diff scan against the Anthropic endpoint
# (defaults: --runtime pi --base-url https://api.anthropic.com
#  --api anthropic-messages --model claude-sonnet-4-5
#  --api-key-env ANTHROPIC_API_KEY):
export ANTHROPIC_API_KEY=sk-ant-...
open-security scan . --base origin/main --fail-on-severity high

# Repository-wide scan: works on Git repositories AND plain directories.
# Files are ranked by security relevance (auth, crypto, SQL, parsers, ...),
# top 150 deep-reviewed in batches, the rest honestly reported as deferred.
# Non-Git targets get a directory_snapshot identity (content digest).
open-security scan . --max-files 150

# Diff scan via any OpenAI-compatible endpoint:
open-security scan . \
  --base origin/main \
  --base-url https://llm-gateway.internal/v1 \
  --api-key-env INTERNAL_LLM_KEY \
  --model my-model \
  --fail-on-severity high \
  --output-dir out/
```

Notes:

- The agent runs with read-only tools (`read_file`, `glob_files`,
  `search_files`, `git_show`) — the scanner never modifies the repository
  under review.
- After every scan the CLI prints a usage report to stderr (total wall time,
  agent runs, input/output/cache tokens, plus per-phase breakdown; a cached
  threat model is marked `cached`), and writes the same numbers to
  `usage.json` in the output directory. `pi` reports tokens and cache tokens
  (gateway pricing is unknown to it); `acp` reports only run counts and
  durations.
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

### pi runtime (default; OpenAI-compatible and Anthropic endpoints)

The `pi` runtime embeds the [pi](https://github.com/earendil-works/pi) agent
loop in-process and routes it at any OpenAI Chat Completions-compatible
endpoint — OpenAI, DeepSeek, Kimi, Qwen, OpenRouter, vLLM, Ollama (`/v1`),
LiteLLM, or an internal gateway — and equally at Anthropic Messages
endpoints. One runtime covers both wire protocols:

```bash
# Bare invocation: Anthropic defaults apply (anthropic-messages protocol,
# claude-sonnet-4-5, key from ANTHROPIC_API_KEY):
export ANTHROPIC_API_KEY=sk-ant-...
open-security scan . --base origin/main

# OpenAI-compatible endpoint (protocol inferred from --base-url):
open-security scan . --base origin/main \
  --base-url https://api.deepseek.com/v1 \
  --api-key-env DEEPSEEK_API_KEY \
  --model deepseek-chat

# Anthropic-style gateway with an explicit model:
open-security scan . --base origin/main \
  --base-url https://claude-gateway.internal \
  --api-key-env GATEWAY_KEY \
  --model claude-sonnet-4-5
```

Rule set when flags are omitted:

- Runtime defaults to `pi` (`acp` requires `--runtime acp`).
- Bare invocations (no `--base-url`) run against
  `https://api.anthropic.com` with `--api anthropic-messages`, `--model
  claude-sonnet-4-5`, and the key from `ANTHROPIC_API_KEY`.
- Wire protocol (`--api`) is inferred from `--base-url`:
  Anthropic-looking URLs get `anthropic-messages`, everything else
  `openai-completions`. An explicit `--api` always wins.
- `--model` is required whenever `--base-url` is passed explicitly.

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
    runtime: "pi",
    baseUrl: "https://llm-gateway.internal/v1",
    model: "my-model",
    apiKeyEnv: "INTERNAL_LLM_KEY",
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
  runtime: { runtime: "pi", baseUrl: "https://unit.test/v1", model: "m", maxTurnsPerPhase: 400 }, // config is inert when agent is injected
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
