#!/usr/bin/env node
/**
 * Minimal fake ACP agent for tests: implements initialize, session/new, and
 * session/prompt over newline-delimited JSON-RPC on stdio, streaming the
 * canned phase response as agent_message_chunk updates.
 */
import readline from "node:readline";

const THREAT_MODEL = {
  summary:
    "The service extracts user-supplied archives. Assets include the filesystem.",
  assets: ["filesystem integrity"],
  trustBoundaries: ["user input to filesystem writes"],
  attackerCapabilities: ["crafted archive entries"],
  securityObjectives: ["extraction stays inside output_dir"],
  assumptions: ["archive paths are untrusted"],
};

const DISCOVERY = {
  candidates: [
    {
      title: "Archive entry path escapes output directory",
      path: "src/extract.py",
      startLine: 9,
      endLine: 10,
      category: "path-traversal",
      cwe: ["CWE-22"],
      attackerSource: "requested_entry from archive entry names",
      sinkOrBrokenControl: "filesystem write without containment check",
      closestControl: "none; os.path.join preserves ../ segments",
      impact: "arbitrary file write outside output_dir",
      whyPlausible: "requested_entry flows unchecked into extract()",
      relevantLines: [9, 10],
      supportingPaths: [],
    },
  ],
};

const VERDICT = {
  disposition: "reportable",
  survives: "yes",
  method: "static",
  summary: "Confirmed: no canonicalization between input and write.",
  source: "requested_entry, attacker-controlled archive entry name",
  control: "absent; join() preserves traversal segments",
  sink: "src/extract.py:10 archive.extract write",
  dataflow: "requested_entry -> join -> extract() write",
  counterevidence: "none found",
  proofGaps: [],
  confidence: "high",
  confidenceRationale: "exact source-control-sink chain",
  vector: "remote",
  preconditions: "plausible",
  attackerInputControl: "yes",
  authScope: "public",
  impact: "high",
};

function responseFor(promptText) {
  if (promptText.includes("independent validator")) return VERDICT;
  if (promptText.includes("discovery reviewer")) return DISCOVERY;
  if (promptText.includes("building a repository threat model")) {
    return THREAT_MODEL;
  }
  return { error: "unexpected prompt" };
}

function send(message) {
  process.stdout.write(`${JSON.stringify(message)}\n`);
}

function reply(id, result) {
  send({ jsonrpc: "2.0", id, result });
}

let counter = 0;

const rl = readline.createInterface({
  input: process.stdin,
  terminal: false,
});

rl.on("line", (line) => {
  if (line.trim().length === 0) return;
  let message;
  try {
    message = JSON.parse(line);
  } catch {
    return;
  }
  if (message.id === undefined) return;
  switch (message.method) {
    case "initialize":
      reply(message.id, { protocolVersion: 1, agentCapabilities: {} });
      break;
    case "session/new":
      counter += 1;
      reply(message.id, { sessionId: `fake-session-${counter}` });
      break;
    case "session/prompt": {
      const promptParts = Array.isArray(message.params.prompt)
        ? message.params.prompt
        : [{ type: "text", text: String(message.params.prompt) }];
      const promptText = promptParts
        .map((part) => part.text ?? "")
        .join("\n");
      const payload = JSON.stringify(responseFor(promptText));
      const sessionId = message.params.sessionId;
      // Stream the payload in two chunks to exercise reassembly.
      const half = Math.ceil(payload.length / 2);
      for (const chunk of [payload.slice(0, half), payload.slice(half)]) {
        send({
          jsonrpc: "2.0",
          method: "session/update",
          params: {
            sessionId,
            update: {
              sessionUpdate: "agent_message_chunk",
              content: { type: "text", text: chunk },
            },
          },
        });
      }
      reply(message.id, { stopReason: "end_turn" });
      break;
    }
    default:
      reply(message.id, {});
      break;
  }
});

rl.on("close", () => {
  process.exit(0);
});
