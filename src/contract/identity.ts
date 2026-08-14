import { createHash, randomUUID } from "node:crypto";

/**
 * Deterministic identities, structurally adapted from the reference
 * methodology's scan contract (Apache-2.0, see NOTICE):
 * - primary fingerprint = sha256(targetId + ruleId + anchor + instance)
 * - findingId derived from the fingerprint
 * - occurrenceId derived from scanId + fingerprint
 * The anchor carries no line numbers so the fingerprint survives line drift.
 */
export function anchorFor(ruleId: string, path: string, summary: string): string {
  const raw = `${ruleId}:${path}:${summary}`
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 64);
  return raw.length === 0 ? "finding" : raw;
}

export function primaryFingerprint(
  targetId: string,
  ruleId: string,
  anchor: string,
  instance: string,
): string {
  const digest = createHash("sha256")
    .update(`${targetId}\0${ruleId}\0${anchor}\0${instance}`)
    .digest("hex");
  return `open-security/v1:sha256:${digest}`;
}

export function findingIdFrom(primary: string): string {
  return `osf_${createHash("sha256").update(primary).digest("hex").slice(0, 24)}`;
}

export function newScanId(): string {
  return `scan_${randomUUID().replace(/-/gu, "").slice(0, 20)}`;
}
