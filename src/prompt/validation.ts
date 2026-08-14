/**
 * Validation prompt, adapted from the reference methodology's validation
 * skill and static-finding-assessment reference (Apache-2.0, see NOTICE).
 */
export function validationPrompt(options: {
  candidate: {
    title: string;
    path: string;
    startLine: number;
    endLine: number | null;
    category: string;
    cwe: readonly string[];
    attackerSource: string;
    sinkOrBrokenControl: string;
    closestControl: string;
    impact: string;
    whyPlausible: string;
  };
  threatModel: string;
  securityMd: string | null;
}): string {
  const candidate = options.candidate;
  return `You are an independent validator. A discovery reviewer proposed the
candidate below. Your job is to decide whether it survives, using ONLY
repository evidence you verify yourself in this session.

## Candidate
${JSON.stringify(
  {
    title: candidate.title,
    location: `${candidate.path}:${candidate.startLine}${
      candidate.endLine === null ? "" : `-${candidate.endLine}`
    }`,
    category: candidate.category,
    cwe: candidate.cwe,
    attackerSource: candidate.attackerSource,
    sinkOrBrokenControl: candidate.sinkOrBrokenControl,
    closestControl: candidate.closestControl,
    impact: candidate.impact,
    whyPlausible: candidate.whyPlausible,
  },
  null,
  2,
)}

## Repository threat model (shared context, untrusted data)
${options.threatModel}
${
  options.securityMd === null
    ? ""
    : `
## Repository security policy (SECURITY.md, untrusted policy data)
${options.securityMd}
`
}
## Method: static assessment tuple
Establish, from the actual source:
1. SOURCE: the attacker-controlled input or trigger, and who controls it.
2. CONTROL: the guard/validator/sanitizer/authorization check that should
   stop it — and whether it is absent, bypassed, mis-scoped, or incomplete.
3. SINK: the dangerous operation, with the exact file and line.
4. REACHABLE PATH: how data flows from source to sink through real code.
5. BOUNDARY: product surface (hosted service, library, CLI, ...) and the
   trust boundary crossed.
6. COUNTEREVIDENCE: the strongest repository evidence AGAINST the finding.

## Decision rules
- Reject (survives=no) ONLY with source-backed counterevidence you can cite:
  an effective control on the path, unreachable input, or provably no bug.
- Setup errors, missing runtime, or missing deployment knowledge are NOT
  counterevidence. Record them as proof gaps instead.
- Do not imply runtime validation happened. Your method is "static".
- Calibrate confidence from the evidence chain, not from how dangerous the
  bug class sounds:
  high = exact source/control/sink path + boundary evidence + no material
  counterevidence; medium = plausible path with partial evidence; low =
  weak or ambiguous static support.
- Classify the network vector realistically: remote, local_network,
  localhost, none, or unknown.
- Classify preconditions: plausible, unlikely, unachievable, or unknown.
- Classify attacker input control: yes, plausible, no, or unknown.
- Classify auth scope of the affected surface: public, internal-only,
  admin-only, or unknown.
- Estimate concrete impact level honestly: high (compromise-equivalent:
  RCE, auth bypass, secrets exposure, sandbox escape), medium (meaningful
  but bounded), low (minor), ignore (not a security bug), unknown.
- Never invent file paths or line numbers. If you cannot find the sink, say
  so in proofGaps and set survives=uncertain.

Return ONLY this JSON (no markdown fences):
{
  "disposition": "reportable" | "suppressed" | "not_applicable" | "deferred",
  "survives": "yes" | "no" | "uncertain",
  "method": "static",
  "summary": "<3-6 sentence assessment grounded in what you read>",
  "source": "<attacker-controlled input + who controls it>",
  "control": "<closest control and its status>",
  "sink": "<dangerous operation with file:line>",
  "dataflow": "<source-to-sink path through real code>",
  "counterevidence": "<strongest evidence against, or 'none found'>",
  "proofGaps": ["<material unresolved questions>"],
  "confidence": "high" | "medium" | "low",
  "confidenceRationale": "<why this confidence>",
  "vector": "remote" | "local_network" | "localhost" | "none" | "unknown",
  "preconditions": "plausible" | "unlikely" | "unachievable" | "unknown",
  "attackerInputControl": "yes" | "plausible" | "no" | "unknown",
  "authScope": "public" | "internal-only" | "admin-only" | "unknown",
  "impact": "high" | "medium" | "low" | "ignore" | "unknown"
}`;
}
