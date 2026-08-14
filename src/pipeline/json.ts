import type { z } from "zod";
import type {
  AgentRunRequest,
  AgentRuntime,
} from "../runtime/types.js";

const SNIPPET_LIMIT = 400;
const MAX_OBJECT_CANDIDATES = 64;

/**
 * Extracts the JSON object from model output. Models wrap JSON in fences,
 * prose, or per-file narration; this extractor is string-aware (braces
 * inside JSON strings do not confuse it) and prefers the LAST balanced
 * top-level object, because narrating models put their final answer at the
 * end. Parse failures quote the beginning of the raw output for diagnosis.
 */
export function extractJsonObject(text: string): unknown {
  const fenced = /```(?:json)?\s*([\s\S]*?)```/u.exec(text);
  if (fenced !== null) {
    try {
      return JSON.parse(fenced[1]!.trim());
    } catch {
      // Fall through to the balanced-object scanner.
    }
  }
  for (const candidate of balancedObjects(text).reverse()) {
    try {
      return JSON.parse(candidate);
    } catch {
      // Try the next object span.
    }
  }
  const snippet =
    text.trim().length === 0
      ? "<empty model output>"
      : text.trim().slice(0, SNIPPET_LIMIT);
  throw new Error(
    `Model output did not contain a parsable JSON object. Output began with: ${snippet}`,
  );
}

/**
 * Returns every top-level balanced `{...}` span in the text. String literals
 * are skipped (quotes and escapes), so braces inside strings never open or
 * close an object.
 */
function balancedObjects(text: string): string[] {
  const spans: string[] = [];
  const stack: number[] = [];
  let inString = false;
  let escaped = false;
  for (let index = 0; index < text.length; index += 1) {
    const character = text[index]!;
    if (inString) {
      if (escaped) escaped = false;
      else if (character === "\\") escaped = true;
      else if (character === '"') inString = false;
      continue;
    }
    if (character === '"') {
      inString = true;
      continue;
    }
    if (character === "{") {
      stack.push(index);
    } else if (character === "}" && stack.length > 0) {
      const start = stack.pop()!;
      if (stack.length === 0) {
        spans.push(text.slice(start, index + 1));
        if (spans.length >= MAX_OBJECT_CANDIDATES) break;
      }
    }
  }
  return spans;
}

const CORRECTION =
  "\n\nIMPORTANT: Your previous response could not be parsed. It began with " +
  "narration instead of JSON. Do the analysis silently, then respond with " +
  "ONLY the raw JSON object matching the required schema — no prose before " +
  "or after it, no markdown fences, no per-file commentary.";

/**
 * Runs an agent prompt and parses the reply against a zod schema. A parse
 * failure triggers exactly one corrective retry (models often narrate
 * instead of emitting JSON); a second failure throws an error that includes
 * the parse failure and the provided context so long scans fail
 * diagnosably at the exact candidate or batch that broke.
 */
export async function runStructured<Schema extends z.ZodTypeAny>(options: {
  runtime: AgentRuntime;
  request: AgentRunRequest;
  schema: Schema;
  /** Human-readable location of this step, for error messages. */
  context: string;
}): Promise<z.infer<Schema>> {
  let lastError: unknown = null;
  for (let attempt = 0; attempt < 2; attempt += 1) {
    const result = await options.runtime.run(
      attempt === 0
        ? options.request
        : { ...options.request, prompt: `${options.request.prompt}${CORRECTION}` },
    );
    try {
      return options.schema.parse(extractJsonObject(result.text));
    } catch (error) {
      lastError = error;
    }
  }
  throw new Error(
    `Structured agent output failed after retry (${options.context}): ${
      lastError instanceof Error ? lastError.message : String(lastError)
    }`,
    { cause: lastError instanceof Error ? lastError : undefined },
  );
}
