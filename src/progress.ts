/**
 * Scan progress events, reported to stderr by the CLI and available to SDK
 * consumers via the scanDiff callback. Scans of large repositories can run
 * for many minutes per phase; these events are how callers tell "working"
 * from "stuck".
 */
export type ScanProgressEvent =
  | { phase: "inventory"; filesInScope: number; excluded: number }
  | { phase: "threat-model"; status: "cached" | "running" | "done" }
  | {
      phase: "discovery";
      status: "running" | "done";
      files?: number;
      candidates?: number;
      batch?: number;
      batches?: number;
    }
  | {
      phase: "validation";
      status: "running" | "done";
      completed?: number;
      total?: number;
    }
  | { phase: "assemble"; findings: number; deferred: number }
  | { phase: "complete"; findings: number; outputDir: string };

export type ScanProgressCallback = (event: ScanProgressEvent) => void;
