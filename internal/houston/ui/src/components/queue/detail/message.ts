/**
 * The message model the Messages surface renders, adapted from what the
 * transport actually returns.
 *
 * `/api/v1/queue/{id}/messages` (browse), `…/receive` and `…/ack` are real
 * endpoints; nothing here is simulated. The two responses carry different
 * amounts of truth, and that difference is modelled rather than smoothed over:
 * a browse row knows its creation time, visibility deadline and receive count,
 * while a receive response carries only an id and a body. Fields the response
 * does not carry are `null`, and every surface renders `null` as "not carried"
 * instead of as zero.
 */

import type { PeekMessage, ReceiveMessage } from "@/lib/types";

import { encodeUtf8 } from "./payload";

/** U+FFFD — the marker a UTF-8 decode leaves behind where bytes did not fit. */
const REPLACEMENT = "�";

/**
 * The storage casts its timestamps to text, so they arrive as
 * `2026-07-18 09:14:02` (SQLite, always UTC) or with an offset appended
 * (Postgres). Neither form is what `Date` treats as unambiguous: the first has
 * no zone at all and is read as *local* time, which is an hours-wide lie on a
 * screen that labels everything UTC.
 */
const SQL_TIMESTAMP = /^(\d{4}-\d{2}-\d{2})[ T](\d{2}:\d{2}:\d{2}(?:\.\d+)?)(.*)$/;

function normalizeZone(zone: string): string {
  const trimmed = zone.trim();
  // No zone means UTC: that is what both storages write.
  if (trimmed === "") return "Z";
  // `+00` — a bare hour offset, which Date does not accept.
  if (/^[+-]\d{2}$/.test(trimmed)) return `${trimmed}:00`;
  return trimmed;
}

/**
 * An unambiguous timestamp string, or null when the value cannot be understood.
 * Null is rendered as "—"; a guessed date would be a number nobody sent.
 */
export function normalizeTimestamp(raw: string | undefined | null): string | null {
  const value = (raw ?? "").trim();
  if (value === "") return null;

  const match = SQL_TIMESTAMP.exec(value);
  const candidate = match
    ? `${match[1]}T${match[2]}${normalizeZone(match[3]!)}`
    : value;

  return Number.isNaN(Date.parse(candidate)) ? null : candidate;
}

/**
 * What `POST …/messages/ack` reported. The endpoint answers per id, so a
 * partial result is normal and the two halves are never collapsed into one
 * count — an operator has to know *which* ids the server did not remove.
 */
export interface AcknowledgeOutcome {
  acknowledged: string[];
  failed: { messageId: string; error: string }[];
}

export interface QueueMessage {
  messageId: string;
  /**
   * The payload as the API client delivered it. The client base64-decodes the
   * wire value and reads the result as UTF-8 text, so this is text even when
   * the stored bytes were not.
   */
  body: string;
  /**
   * `body` re-encoded to UTF-8. Byte-exact for a UTF-8 payload, which is
   * exactly what `lossy` records — sizes are only quoted as exact when it is
   * false.
   */
  bytes: Uint8Array;
  /**
   * The decode replaced bytes it could not represent, so the payload is not
   * recoverable from this response and its byte count is not the stored one.
   */
  lossy: boolean;
  /** null when the response carries no creation time (receive does not). */
  createdAt: string | null;
  /** null when the response carries no visibility deadline. */
  visibleAt: string | null;
  /** null when the response carries no receive count (receive does not). */
  receiveAttempts: number | null;
  /** Whether the server reports the message hidden from receivers. */
  inFlight: boolean;
}

function bodyOf(body: string): Pick<QueueMessage, "body" | "bytes" | "lossy"> {
  return {
    body,
    bytes: encodeUtf8(body),
    lossy: body.includes(REPLACEMENT),
  };
}

/** A browse row: every field the peek response defines. */
export function fromPeek(message: PeekMessage): QueueMessage {
  return {
    messageId: message.id,
    ...bodyOf(message.body),
    createdAt: normalizeTimestamp(message.createdAt),
    visibleAt: normalizeTimestamp(message.visibleAt),
    receiveAttempts: Number.isFinite(message.retries) ? message.retries : null,
    inFlight: Boolean(message.inFlight),
  };
}

/**
 * A claimed message. The receive response is an id and a body and nothing
 * else, so the attempt count and timestamps stay null rather than being
 * reconstructed — the claim itself is the only thing this response proves, and
 * that is why `inFlight` is true.
 */
export function fromReceive(message: ReceiveMessage): QueueMessage {
  return {
    messageId: message.id,
    ...bodyOf(message.body),
    createdAt: null,
    visibleAt: null,
    receiveAttempts: null,
    inFlight: true,
  };
}
