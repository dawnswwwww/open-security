/**
 * Extracts the first JSON object from model output. Models occasionally wrap
 * JSON in markdown fences or prose; the pipeline tolerates both but never
 * repairs malformed JSON silently — parse failures surface as errors.
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
  throw new Error("Model output did not contain a parsable JSON object.");
}
