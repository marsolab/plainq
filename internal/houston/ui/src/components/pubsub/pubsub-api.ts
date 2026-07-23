import { api } from "@/lib/api-client";
import { API_BASE } from "@/lib/constants";
import type { ApiError, PublishResponse, Queue } from "@/lib/types";

/**
 * Two Pub/Sub calls the shared client does not carry: deleting a topic, and
 * publishing a batch of already-encoded bodies. Both are narrow enough to sit
 * beside the only screen that makes them, so this module mirrors `apiFetch`'s
 * cookie + 401-refresh contract rather than widening the shared client.
 */
async function pubsubFetch<T>(
  path: string,
  options: RequestInit,
  refreshed = false,
): Promise<T> {
  const response = await fetch(`${API_BASE}${path}`, {
    credentials: "include",
    headers: { "Content-Type": "application/json", ...options.headers },
    ...options,
  });

  if (response.status === 401) {
    // One refresh, then give up: a refresh that returns 401 too would
    // otherwise retry forever.
    if (refreshed) {
      window.location.href = "/login";
      throw new Error("Session expired");
    }

    try {
      await fetch(`${API_BASE}/account/refresh`, { method: "POST", credentials: "include" });
    } catch {
      window.location.href = "/login";
      throw new Error("Session expired");
    }

    return pubsubFetch<T>(path, options, true);
  }

  if (!response.ok) {
    const error: ApiError = await response
      .json()
      .catch(() => ({ message: response.statusText }));
    throw new Error(error.message || "Request failed");
  }

  if (response.status === 204) return undefined as T;
  return response.json();
}

/** `DELETE /queue/topics/{topicID}` — answers 200 with an empty object. */
export function deleteTopic(topicId: string): Promise<void> {
  return pubsubFetch<void>(`/queue/topics/${encodeURIComponent(topicId)}`, {
    method: "DELETE",
  });
}

/**
 * One request carries every message: the transport takes `messages[]` and
 * sends the whole batch to each subscribed queue in a single write, so
 * splitting them client-side would only add round trips. Bodies are already
 * Base64 — the Go field is `[]byte`, which is what it looks like on the wire.
 */
export function publishMessages(
  topicId: string,
  base64Bodies: string[],
): Promise<PublishResponse> {
  return pubsubFetch<PublishResponse>(
    `/queue/topics/${encodeURIComponent(topicId)}/publish`,
    {
      method: "POST",
      body: JSON.stringify({ messages: base64Bodies.map((body) => ({ body })) }),
    },
  );
}

const QUEUE_PAGE_LIMIT = 100;
const QUEUE_PAGE_CAP = 50;

/**
 * The connect-a-queue picker searches this list and says "no queue matches"
 * when it comes up empty, so it has to be every queue rather than the first
 * page. A server that repeats a cursor would loop forever, so repeats end the
 * walk.
 */
export async function loadAllQueues(): Promise<Queue[]> {
  const queues: Queue[] = [];
  const seen = new Set<string>();
  let cursor = "";

  for (let page = 0; page < QUEUE_PAGE_CAP; page += 1) {
    const response = await api.queues.list({ cursor, limit: QUEUE_PAGE_LIMIT });
    queues.push(...(response.queues ?? []));

    const next = response.nextCursor;
    if (!response.hasMore || !next || seen.has(next)) break;
    seen.add(next);
    cursor = next;
  }

  return queues;
}
