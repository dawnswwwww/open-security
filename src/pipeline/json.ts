import type { z } from "zod";
import type {
  AgentRunRequest,
  AgentRuntime,
} from "../runtime/types.js";

const SNIPPET_LIMIT = 400;

/**
 * Extracts the first JSON object from model output. Models occasionally wrap
 * JSON in markdown fences or prose; the pipeline tolerates both but never
 * repairs malformed JSON silently — parse failures surface as errors that
 * quote the beginning of the raw output for diagnosis.
 */
export function extractJsonObject(text: string): unknown {
  const fenced = /```(?:json)?\s*([\s\S]*?)```/u.exec(text);
  const candidates: string[] = [];
  if (fenced !== null) candidates.push(fenced[1]!.trim());
  const start = text.indexOf("{");
  const end = text.lastIndexOf("}");
  if (start >= 0 && end > start) candidates.push(text.slice(start, end + 1));
  candidates.push(text.trim());
  for (const candidate of candidates) {
    try {
      return JSON.parse(candidate);
    } catch {
      // Try the next candidate shape.
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

const CORRECTION =
  "\n\nIMPORTANT: Your previous response was not valid JSON for the required " +
  "schema and could not be parsed. Respond again with ONLY the raw JSON " +
  "object — no prose before or after, no markdown fences.";

/**
 * Runs an agent prompt and parses the reply against a zod schema. A parse
 * failure triggers exactly one corrective retry (models often wrap JSON in
 * prose); a second failure throws an error that includes the parse failure
 * and the provided context so long scans fail diagnosably at the exact
 * candidate or batch that broke.
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
