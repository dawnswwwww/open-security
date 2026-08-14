/**
 * Threat model prompt, adapted from the reference methodology's threat-model
 * skill (Apache-2.0, see NOTICE): repository-wide, diff-agnostic, cached per
 * target and reused across scans.
 */
export function threatModelPrompt(): string {
  return `You are building a repository threat model for a security review program.

Produce a practical model, not an abstract security essay. Establish what this
software does, which actors influence it, which assets or privileges matter,
how components relate, and where data crosses trust boundaries. Use focused
source searches to locate:

- Entry points: public APIs, protocol handlers, parsers, CLI commands,
  template rendering, and other untrusted-input boundaries.
- Authentication, authorization, identity, tenancy, and security-sensitive
  configuration.
- Sensitive operations: database queries, filesystem access, network requests,
  process launches, credential issuance, capability grants.
- Semantic boundaries: deserialization, template expansion, code generation,
  interpretation, plugin interfaces, native bindings.

Output requirements:
1. Ground every claim in files you actually read. Do not invent locations,
   reachability, or deployment assumptions.
2. Cover the repository holistically. Do not focus on any recent change,
   subsystem, or directory.
3. This phase never produces findings; it produces shared context.

Return ONLY this JSON object (no markdown fences):
{
  "summary": "<5-12 sentence repository security overview>",
  "assets": ["<protected data, credentials, capabilities, invariants>"],
  "trustBoundaries": ["<boundary + what crosses it, with file anchors>"],
  "attackerCapabilities": ["<who can influence what inputs, realistically>"],
  "securityObjectives": ["<what the software must guarantee>"],
  "assumptions": ["<explicit assumptions you made while reading>"]
}`;
}
