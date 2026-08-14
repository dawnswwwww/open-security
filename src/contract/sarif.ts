import type { Finding, FindingsDocument } from "./types.js";
import type { SeverityLevel } from "../config.js";

/**
 * SARIF 2.1.0 export, adapted from the reference methodology's adapter
 * rules (Apache-2.0, see NOTICE): deterministic export (not the source of
 * truth), repository-relative POSIX paths, the semantic fingerprint
 * preserved under partialFingerprints, severity mapped to level.
 */

const SARIF_LEVEL: Record<SeverityLevel, "error" | "warning" | "note" | "none"> =
  {
    critical: "error",
    high: "error",
    medium: "warning",
    low: "note",
    informational: "none",
  };

export interface SarifLog {
  $schema: string;
  version: "2.1.0";
  runs: SarifRun[];
}

export interface SarifRun {
  tool: {
    driver: {
      name: string;
      version: string;
      informationUri: string;
      rules: {
        id: string;
        shortDescription: { text: string };
      }[];
    };
  };
  originalUriBaseIds: Record<string, string>;
  results: SarifResult[];
}

export interface SarifResult {
  ruleId: string;
  level: "error" | "warning" | "note" | "none";
  message: { text: string };
  locations: {
    physicalLocation: {
      artifactLocation: { uri: string; uriBaseId: string };
      region: { startLine: number; endLine?: number };
    };
  }[];
  partialFingerprints: { "openSecurity/v1": string };
  properties?: Record<string, unknown>;
}

export function toSarif(
  document: FindingsDocument,
  toolVersion: string,
  rootUri: string,
): SarifLog {
  const rules = new Map<string, { text: string }>();
  const results: SarifResult[] = document.findings.map((finding) => {
    if (!rules.has(finding.ruleId)) {
      rules.set(finding.ruleId, { text: finding.title });
    }
    return {
      ruleId: finding.ruleId,
      level: SARIF_LEVEL[finding.severity.level],
      message: { text: finding.summary },
      locations: finding.locations.map((location, index) => ({
        physicalLocation: {
          artifactLocation: {
            uri: location.path.split("\\").join("/"),
            uriBaseId: "SRCROOT",
          },
          region: {
            startLine: location.startLine,
            ...(location.endLine === undefined
              ? {}
              : { endLine: location.endLine }),
          },
        },
      })),
      partialFingerprints: {
        "openSecurity/v1": finding.fingerprints.primary,
      },
      properties: {
        confidence: finding.confidence.level,
        priority: finding.priority,
        category: finding.taxonomy.category,
        ...(finding.taxonomy.cwe.length === 0
          ? {}
          : { cwe: finding.taxonomy.cwe.join(", ") }),
      },
    };
  });
  return {
    $schema:
      "https://json.schemastore.org/sarif-2.1.0.json",
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: "open-security",
            version: toolVersion,
            informationUri: "https://github.com/dawnswwwww/open-security",
            rules: [...rules.entries()].map(([id, description]) => ({
              id,
              shortDescription: description,
            })),
          },
        },
        originalUriBaseIds: { SRCROOT: rootUri },
        results,
      },
    ],
  };
}
