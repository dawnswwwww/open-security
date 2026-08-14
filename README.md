# open-security

LLM-driven security diff scanner. Reviews a Git diff the way a security
engineer would — threat model, candidate discovery, independent validation,
mechanical severity calibration — and emits a structured findings contract,
a human report, and SARIF for CI.

- **CLI + SDK**: `open-security scan` or `new OpenSecurity().scanDiff()`.
- **Pluggable agent runtime**: default adapter drives the Claude Agent SDK
  (any Anthropic-protocol endpoint via `--base-url`); inject your own runtime
  through the SDK for other executors.
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

```bash
open-security scan . \
  --base origin/main \
  --base-url https://llm-gateway.internal/v1 \
  --api-key-env INTERNAL_LLM_KEY \
  --model my-model \
  --fail-on-severity high \
  --output-dir out/
```

Notes:

- `--base-url` endpoints must speak the Anthropic Messages API (that is what
  the Claude Agent SDK runtime consumes). Point it at an internal gateway or
  proxy.
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

## SDK

```ts
import { OpenSecurity } from "open-security";

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
  runtime: { runtime: "claude-agent", maxTurnsPerPhase: 80 },
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
