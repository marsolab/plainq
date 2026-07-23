/**
 * Message bodies are opaque bytes — the server never interprets them, and
 * neither does Houston. Every helper here *proves* a decoding before it is
 * offered: a Text or JSON view is only ever reachable once the bytes have been
 * shown to support it, so nothing is silently corrupted by a lossy decode.
 */

const ENCODER = new TextEncoder();

export function encodeUtf8(text: string): Uint8Array {
  return ENCODER.encode(text);
}

/** The decoded string, or null when the bytes are not valid UTF-8. */
export function decodeUtf8(bytes: Uint8Array): string | null {
  try {
    // fatal: a replacement character would be a silent lie about the payload.
    return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    return null;
  }
}

export function toBase64(bytes: Uint8Array): string {
  let binary = "";
  for (let i = 0; i < bytes.length; i += 1) {
    binary += String.fromCharCode(bytes[i]!);
  }
  return btoa(binary);
}

/** Decoded bytes, or null when the input is not well-formed Base64. */
export function fromBase64(value: string): Uint8Array | null {
  const trimmed = value.replace(/\s+/g, "");
  if (trimmed.length === 0) return new Uint8Array(0);
  if (!/^[A-Za-z0-9+/]+={0,2}$/.test(trimmed) || trimmed.length % 4 !== 0) return null;

  try {
    const binary = atob(trimmed);
    const out = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i += 1) out[i] = binary.charCodeAt(i);
    return out;
  } catch {
    return null;
  }
}

export function toHex(bytes: Uint8Array): string {
  const parts: string[] = [];
  for (let i = 0; i < bytes.length; i += 1) {
    parts.push(bytes[i]!.toString(16).padStart(2, "0"));
  }
  return parts.join(" ");
}

export interface JsonCheck {
  valid: boolean;
  /** Parser message, lower-cased, ready to follow "invalid JSON — ". */
  message?: string;
}

export function checkJson(text: string): JsonCheck {
  if (text.trim().length === 0) return { valid: false, message: "empty body" };
  try {
    JSON.parse(text);
    return { valid: true };
  } catch (err) {
    const raw = err instanceof Error ? err.message : "could not be parsed";
    return { valid: false, message: raw.replace(/^JSON\.parse:\s*/i, "").toLowerCase() };
  }
}

/** Re-indented JSON, or null when the text does not parse. */
export function prettyJson(text: string): string | null {
  try {
    return JSON.stringify(JSON.parse(text), null, 2);
  } catch {
    return null;
  }
}

/**
 * One line for a table cell. Whitespace is collapsed so a pretty-printed body
 * does not read as an empty one; the caller states the size and whether the
 * decode was lossy alongside, so the preview never has to imply either.
 */
export function previewOf(body: string, max = 42): string {
  const collapsed = body.replace(/\s+/g, " ").trim();
  if (collapsed === "") return "(empty)";
  return collapsed.length > max ? `${collapsed.slice(0, max)}…` : collapsed;
}
