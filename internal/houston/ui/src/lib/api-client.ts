import { API_BASE } from "./constants";
import type {
  ApiError,
  DashboardOverviewResponse,
  DeleteResponse,
  InFlightMetricsResponse,
  MultiMetricsChartResponse,
  PeekResponse,
  PublishResponse,
  Queue,
  QueueListResponse,
  QueueMetricsSummary,
  ReceiveResponse,
  SendResponse,
  TopicListResponse,
  TopicMetricsOverview,
  TopicMetricsSummary,
} from "./types";

/**
 * The server authenticates with `Authorization: Bearer` and never sets a
 * cookie, so the browser is the only place a session can live. Sign-in ends in
 * a full-page navigation, which rules out memory; localStorage is what is left.
 * An HttpOnly cookie would be the better store, but the server issues none.
 */
const SESSION_KEY = "plainq.session";

export interface Session {
  accessToken: string;
  refreshToken: string;
  /** ISO-8601 exactly as the server sent it. Absent if it sent none. */
  expiresAt?: string;
}

function pick(source: Record<string, unknown>, ...keys: string[]): string {
  for (const key of keys) {
    const value = source[key];
    if (typeof value === "string" && value !== "") return value;
  }

  return "";
}

/**
 * Two endpoints hand back the same session and spell it differently: the
 * account service serialises its struct without JSON tags (`AccessToken`),
 * while onboarding tags the same fields snake_case and nests them under
 * `session`. Both are the server's own shapes, so read either rather than
 * betting on one.
 */
export function readSession(payload: unknown): Session | null {
  if (typeof payload !== "object" || payload === null) return null;

  const record = payload as Record<string, unknown>;
  const nested = record.session;
  const source =
    typeof nested === "object" && nested !== null
      ? (nested as Record<string, unknown>)
      : record;

  const accessToken = pick(source, "AccessToken", "access_token", "accessToken");
  if (!accessToken) return null;

  return {
    accessToken,
    refreshToken: pick(source, "RefreshToken", "refresh_token", "refreshToken"),
    // Optional everywhere: the account service states no expiry, so an absent
    // value must read as "unknown", never as "already expired".
    expiresAt:
      pick(source, "ExpiresAt", "expires_at", "expiresAt") || undefined,
  };
}

/**
 * Protobuf's JSON mapping serialises 64-bit integers as strings, so retention,
 * visibility timeout and friends arrive as `"604800"` rather than `604800`.
 * Coerce at the boundary — every consumer downstream expects a real number,
 * and a silent NaN would render as "no value" instead of the truth.
 */
function toNumber(value: unknown): number {
  if (typeof value === "number") return value;
  if (typeof value === "string" && value.trim() !== "") return Number(value);
  return Number.NaN;
}

function normalizeQueue(queue: Queue): Queue {
  return {
    ...queue,
    retentionPeriodSeconds: toNumber(queue.retentionPeriodSeconds),
    visibilityTimeoutSeconds: toNumber(queue.visibilityTimeoutSeconds),
    maxReceiveAttempts: toNumber(queue.maxReceiveAttempts),
  };
}

export function getSession(): Session | null {
  if (typeof window === "undefined") return null;

  try {
    const raw = window.localStorage.getItem(SESSION_KEY);
    return raw ? (JSON.parse(raw) as Session) : null;
  } catch {
    return null;
  }
}

export function storeSession(session: Session): void {
  if (typeof window === "undefined") return;

  try {
    window.localStorage.setItem(SESSION_KEY, JSON.stringify(session));
  } catch {
    // A browser refusing storage still gets a working session for this
    // document; only persistence across a reload is lost.
  }
}

export function clearSession(): void {
  if (typeof window === "undefined") return;

  try {
    window.localStorage.removeItem(SESSION_KEY);
  } catch {
    // Nothing to recover from: there is no session left to clear.
  }
}

/**
 * Whether a credential is held — not whether the server will accept it. An
 * access token past its stated expiry still counts while a refresh token can
 * renew it; without one it is dropped, so a dead token never poses as a
 * session.
 */
export function hasSession(): boolean {
  const session = getSession();
  if (!session) return false;
  if (session.refreshToken) return true;

  const expiry = session.expiresAt ? Date.parse(session.expiresAt) : NaN;
  if (Number.isNaN(expiry)) return true;
  if (expiry > Date.now()) return true;

  clearSession();
  return false;
}

/** One refresh attempt against the token the browser holds. Never loops. */
async function refreshSession(): Promise<boolean> {
  const session = getSession();
  if (!session?.refreshToken) return false;

  try {
    const response = await fetch(`${API_BASE}/account/refresh`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ refresh_token: session.refreshToken }),
    });
    if (!response.ok) return false;

    const next = readSession(await response.json());
    if (!next) return false;

    storeSession(next);

    return true;
  } catch {
    return false;
  }
}

/**
 * Carries the reason and the intended destination, so /login can say what
 * happened and send the operator back where they were going.
 */
function redirectToSignIn(): void {
  if (typeof window === "undefined") return;
  if (window.location.pathname === "/login") return;

  const next = `${window.location.pathname}${window.location.search}`;
  window.location.href = `/login?reason=expired&next=${encodeURIComponent(next)}`;
}

async function apiFetch<T>(
  path: string,
  options?: RequestInit,
  mayRefresh = true,
): Promise<T> {
  const session = getSession();

  const response = await fetch(`${API_BASE}${path}`, {
    ...options,
    headers: {
      "Content-Type": "application/json",
      ...(session ? { Authorization: `Bearer ${session.accessToken}` } : {}),
      ...options?.headers,
    },
  });

  if (response.status === 401) {
    // Exactly one deterministic refresh before giving up. fetch does not throw
    // on 4xx, so a retry driven by a failed refresh would recurse forever.
    if (mayRefresh && (await refreshSession())) {
      return apiFetch<T>(path, options, false);
    }

    clearSession();
    redirectToSignIn();

    throw new Error("Session expired");
  }

  if (!response.ok) {
    const error: ApiError = await response
      .json()
      .catch(() => ({ message: response.statusText }));
    throw new Error(`${response.status}: ${error.message || response.statusText}`);
  }

  // Not every success carries JSON: signup answers 201 with an empty body, and
  // parsing that unconditionally turns a created account into a thrown error.
  if (response.status === 204) return undefined as T;

  const body = await response.text();
  if (body === "") return undefined as T;

  return JSON.parse(body) as T;
}

function utf8ToBase64(input: string): string {
  const bytes = new TextEncoder().encode(input);
  let binary = "";
  bytes.forEach((byte) => {
    binary += String.fromCharCode(byte);
  });
  return btoa(binary);
}

function base64ToUtf8(input: string): string {
  if (!input) return "";
  try {
    const binary = atob(input);
    const bytes = Uint8Array.from(binary, (c) => c.charCodeAt(0));
    return new TextDecoder().decode(bytes);
  } catch {
    return input;
  }
}

export interface CreateQueueInput {
  queueName: string;
  retentionPeriodSeconds?: number;
  visibilityTimeoutSeconds?: number;
  maxReceiveAttempts?: number;
  evictionPolicy?: string;
  deadLetterQueueId?: string;
}

export const api = {
  queues: {
    list: (params: { limit?: number; cursor?: string } = {}) =>
      apiFetch<QueueListResponse>(
        `/queue?limit=${params.limit ?? 10}&cursor=${params.cursor ?? ""}`,
      ).then((response) => ({
        ...response,
        queues: (response.queues ?? []).map(normalizeQueue),
      })),
    get: (id: string) => apiFetch<Queue>(`/queue/${id}`).then(normalizeQueue),
    create: (data: CreateQueueInput) =>
      apiFetch<{ queueId: string }>("/queue", {
        method: "POST",
        body: JSON.stringify(data),
      }),
    delete: (id: string) =>
      apiFetch<void>(`/queue/${id}`, { method: "DELETE" }),
    purge: (id: string) =>
      apiFetch<void>(`/queue/${id}/purge`, { method: "POST" }),

    messages: {
      // Browse messages without consuming them (visibility/retries untouched).
      peek: async (
        id: string,
        params: { limit?: number; offset?: number } = {},
      ): Promise<PeekResponse> => {
        const res = await apiFetch<Partial<PeekResponse>>(
          `/queue/${id}/messages?limit=${params.limit ?? 50}&offset=${params.offset ?? 0}`,
        );
        return {
          messages: (res.messages ?? []).map((m) => ({
            ...m,
            body: base64ToUtf8(m.body),
          })),
          total: res.total ?? 0,
        };
      },
      // Enqueue one or more text bodies.
      send: async (id: string, bodies: string[]): Promise<SendResponse> => {
        // Responses are marshaled with protojson (UseProtoNames: false), so
        // the key is camelCase `messageIds`, not snake_case.
        const res = await apiFetch<{ messageIds?: string[] }>(
          `/queue/${id}/messages`,
          {
            method: "POST",
            body: JSON.stringify({
              messages: bodies.map((b) => ({ body: utf8ToBase64(b) })),
            }),
          },
        );
        return { messageIds: res.messageIds ?? [] };
      },
      // Consume a batch, making messages invisible for the visibility timeout.
      receive: async (
        id: string,
        batch = 1,
      ): Promise<ReceiveResponse> => {
        const res = await apiFetch<{ messages?: { id: string; body: string }[] }>(
          `/queue/${id}/messages/receive?batch=${batch}`,
          { method: "POST" },
        );
        return {
          messages: (res.messages ?? []).map((m) => ({
            id: m.id,
            body: base64ToUtf8(m.body),
          })),
        };
      },
      // Acknowledge (delete) messages by id. Request and response both use
      // protojson camelCase field names.
      ack: async (id: string, ids: string[]): Promise<DeleteResponse> => {
        const res = await apiFetch<{
          successful?: string[];
          failed?: { messageId: string; error: string }[];
        }>(`/queue/${id}/messages/ack`, {
          method: "POST",
          body: JSON.stringify({ messageIds: ids }),
        });
        return {
          successful: res.successful ?? [],
          failed: (res.failed ?? []).map((f) => ({
            messageId: f.messageId,
            error: f.error,
          })),
        };
      },
    },
  },
  topics: {
    list: () => apiFetch<TopicListResponse>("/queue/topics"),
    create: (data: { topicName: string }) =>
      apiFetch<{ topicId: string }>("/queue/topics", {
        method: "POST",
        body: JSON.stringify(data),
      }),
    subscribe: (topicId: string, queueId: string) =>
      apiFetch<{ subscriptionId: string }>(`/queue/topics/${topicId}/subscriptions`, {
        method: "POST",
        body: JSON.stringify({ queueId }),
      }),
    unsubscribe: (topicId: string, subscriptionId: string) =>
      apiFetch<void>(`/queue/topics/${topicId}/subscriptions/${subscriptionId}`, { method: "DELETE" }),
    publish: (topicId: string, body: string) =>
      apiFetch<PublishResponse>(`/queue/topics/${topicId}/publish`, {
        method: "POST",
        body: JSON.stringify({ messages: [{ body: utf8ToBase64(body) }] }),
      }),
  },
  metrics: {
    overview: () => apiFetch<DashboardOverviewResponse>("/metrics/overview"),
    queue: (id: string, range = "1h") =>
      apiFetch<QueueMetricsSummary>(`/metrics/queue/${id}?range=${range}`),
    queueRates: (id: string, range = "1h") =>
      apiFetch<MultiMetricsChartResponse>(`/metrics/queue/${id}/rates?range=${range}`),
    queueInFlight: (id: string, range = "1h") =>
      apiFetch<InFlightMetricsResponse>(`/metrics/queue/${id}/inflight?range=${range}`),
    topicOverview: () => apiFetch<TopicMetricsOverview>("/metrics/topics/overview"),
    topic: (id: string, range = "1h") =>
      apiFetch<TopicMetricsSummary>(`/metrics/topic/${id}?range=${range}`),
    topicRates: (id: string, range = "1h") =>
      apiFetch<MultiMetricsChartResponse>(`/metrics/topic/${id}/rates?range=${range}`),
  },
  auth: {
    // Sign-in and sign-up only count as succeeding once the session they
    // return is actually held: navigating into the app without one lands on a
    // page that can only 401.
    signin: async (data: { email: string; password: string }) => {
      const session = readSession(
        await apiFetch<unknown>("/account/signin", {
          method: "POST",
          body: JSON.stringify(data),
        }),
      );
      if (!session) throw new Error("Sign in did not return a session");

      storeSession(session);

      return session;
    },
    // Registration may establish no session at all: the server can answer 201
    // with an empty body, which reads back as null rather than as a failure.
    signup: async (data: { email: string; password: string; name?: string }) => {
      const session = readSession(
        await apiFetch<unknown>("/account/signup", {
          method: "POST",
          body: JSON.stringify(data),
        }),
      );
      if (session) storeSession(session);

      return session;
    },
    signout: async () => {
      try {
        await apiFetch<void>("/account/signout", { method: "POST" });
      } finally {
        // Local credentials go regardless: a failed server revocation must not
        // strand the operator in a session they asked to end.
        clearSession();
      }
    },
    refresh: () => refreshSession(),
  },
};
