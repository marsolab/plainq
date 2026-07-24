import { API_BASE } from "./constants";
import type {
  ApiError,
  ConfigResponseDTO,
  DashboardOverviewResponse,
  DeleteResponse,
  DirectoryPageDTO,
  InFlightMetricsResponse,
  MultiMetricsChartResponse,
  OrganizationsResponse,
  PeekResponse,
  ProviderDTO,
  ProviderInput,
  ProviderListResponse,
  PublishResponse,
  Queue,
  QueueGrantInput,
  QueueListResponse,
  QueueMetricsSummary,
  QueueRolePermissionDTO,
  ReceiveResponse,
  RoleDTO,
  RolePermissionsDTO,
  RoleWithUsageDTO,
  SendResponse,
  TeamDTO,
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

/**
 * Reads the roles the server signed into the access token.
 *
 * These are the server's own claim about the operator, not a guess: it puts
 * them in the token at sign-in and the same list is what its authorization
 * middleware checks. Reading them lets the UI show a blocked control with its
 * reason instead of offering a write that will come back 403. It is never the
 * enforcement — the server rejects the request regardless.
 *
 * Returns null when nothing can be established: no session, or a token whose
 * payload will not decode. Null means "unknown", never "denied".
 */
export function sessionRoles(): string[] | null {
  const session = getSession();
  if (!session?.accessToken) return null;

  const payload = session.accessToken.split(".")[1];
  if (!payload) return null;

  try {
    // JWT payloads are base64url; atob wants base64, and padding is optional
    // in the encoding but not in the decoder.
    const base64 = payload.replace(/-/g, "+").replace(/_/g, "/");
    const padded = base64.padEnd(base64.length + ((4 - (base64.length % 4)) % 4), "=");
    const claims = JSON.parse(base64ToUtf8(padded)) as Record<string, unknown>;
    const roles = claims.roles;

    if (!Array.isArray(roles)) return null;

    return roles.filter((role): role is string => typeof role === "string");
  } catch {
    return null;
  }
}

/** The role name the server's authorization middleware checks for. */
export const ADMIN_ROLE = "admin";

/**
 * Whether the held session may change access configuration. Null when the
 * token says nothing — with authentication disabled there is no token at all,
 * and pre-blocking every control on that basis would hide working ones.
 */
export function isAdministrator(): boolean | null {
  const roles = sessionRoles();
  if (roles === null) return null;

  return roles.includes(ADMIN_ROLE);
}

/**
 * A failed request, carrying the status the server answered with.
 *
 * The server's error bodies are status text — it deliberately does not return
 * internal error strings — so the status code is the whole of what it said.
 * Callers that want to explain a refusal have to key off this, not off prose.
 */
export class ApiRequestError extends Error {
  readonly status: number;

  constructor(status: number, message: string) {
    super(message);
    this.name = "ApiRequestError";
    this.status = status;
  }
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

    throw new ApiRequestError(response.status, "Session expired");
  }

  if (!response.ok) {
    const error: ApiError = await response
      .json()
      .catch(() => ({ message: response.statusText }));
    throw new ApiRequestError(
      response.status,
      `${response.status}: ${error.message || response.statusText}`,
    );
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
  /**
   * The account directory. Reads only: PlainQ has no invite, suspend, delete
   * or password-reset API, and the client does not pretend otherwise.
   */
  directory: {
    users: (params: { limit?: number; cursor?: string; search?: string } = {}) => {
      const query = new URLSearchParams();
      if (params.limit !== undefined) query.set("limit", String(params.limit));
      if (params.cursor) query.set("cursor", params.cursor);
      if (params.search) query.set("search", params.search);

      const suffix = query.toString();

      return apiFetch<DirectoryPageDTO>(`/directory/users${suffix ? `?${suffix}` : ""}`);
    },
  },
  rbac: {
    roles: {
      list: () => apiFetch<RoleWithUsageDTO[]>("/rbac/roles"),
      create: (roleName: string) =>
        apiFetch<RoleDTO>("/rbac/roles", {
          method: "POST",
          body: JSON.stringify({ role_name: roleName }),
        }),
      rename: (roleId: string, roleName: string) =>
        apiFetch<RoleDTO>(`/rbac/roles/${encodeURIComponent(roleId)}`, {
          method: "PUT",
          body: JSON.stringify({ role_name: roleName }),
        }),
      delete: (roleId: string) =>
        apiFetch<void>(`/rbac/roles/${encodeURIComponent(roleId)}`, { method: "DELETE" }),
    },
    userRoles: {
      list: (userId: string) =>
        apiFetch<RoleDTO[]>(`/rbac/users/${encodeURIComponent(userId)}/roles`),
      assign: (userId: string, roleId: string) =>
        apiFetch<void>(
          `/rbac/users/${encodeURIComponent(userId)}/roles/${encodeURIComponent(roleId)}`,
          { method: "POST" },
        ),
      remove: (userId: string, roleId: string) =>
        apiFetch<void>(
          `/rbac/users/${encodeURIComponent(userId)}/roles/${encodeURIComponent(roleId)}`,
          { method: "DELETE" },
        ),
    },
    permissions: {
      /** One queue's grants across every role — the per-queue Access matrix. */
      forQueue: (queueId: string) =>
        apiFetch<QueueRolePermissionDTO[]>(
          `/rbac/permissions/queues/${encodeURIComponent(queueId)}`,
        ),
      /** One role's whole grant set — the role editor's matrix. */
      forRole: (roleId: string) =>
        apiFetch<RolePermissionsDTO>(`/rbac/permissions/roles/${encodeURIComponent(roleId)}`),
      /**
       * Stores a role's grants as a whole. The server applies them in one
       * transaction and answers with what it stored, so the response is what a
       * reload will show rather than an echo of the request.
       */
      replaceForRole: (roleId: string, grants: QueueGrantInput[]) =>
        apiFetch<RolePermissionsDTO>(`/rbac/permissions/roles/${encodeURIComponent(roleId)}`, {
          method: "PUT",
          body: JSON.stringify({ grants }),
        }),
    },
  },
  oauth: {
    providers: {
      list: () => apiFetch<ProviderListResponse>("/oauth/providers"),
      get: (providerId: string) =>
        apiFetch<ProviderDTO>(`/oauth/providers/${encodeURIComponent(providerId)}`),
      create: (input: ProviderInput) =>
        apiFetch<ProviderDTO>("/oauth/providers", {
          method: "POST",
          body: JSON.stringify(input),
        }),
      /**
       * Secrets the server withheld cannot be sent back, so a key it reports
       * as redacted keeps its stored value unless this request names it. That
       * is the server's rule; the client only has to avoid sending blanks.
       */
      update: (providerId: string, input: Partial<ProviderInput>) =>
        apiFetch<ProviderDTO>(`/oauth/providers/${encodeURIComponent(providerId)}`, {
          method: "PUT",
          body: JSON.stringify(input),
        }),
      delete: (providerId: string) =>
        apiFetch<void>(`/oauth/providers/${encodeURIComponent(providerId)}`, {
          method: "DELETE",
        }),
    },
    organizations: {
      list: () => apiFetch<OrganizationsResponse>("/oauth/organizations"),
      teams: (orgId: string) =>
        apiFetch<TeamDTO[]>(`/oauth/organizations/${encodeURIComponent(orgId)}/teams`),
    },
    userTeams: {
      list: (userId: string) =>
        apiFetch<TeamDTO[]>(`/oauth/users/${encodeURIComponent(userId)}/teams`),
      add: (userId: string, teamId: string) =>
        apiFetch<void>(
          `/oauth/users/${encodeURIComponent(userId)}/teams/${encodeURIComponent(teamId)}`,
          { method: "POST" },
        ),
      remove: (userId: string, teamId: string) =>
        apiFetch<void>(
          `/oauth/users/${encodeURIComponent(userId)}/teams/${encodeURIComponent(teamId)}`,
          { method: "DELETE" },
        ),
    },
  },
  system: {
    /** The running instance's sanitized configuration. Administrator-only. */
    config: () => apiFetch<ConfigResponseDTO>("/system/config"),
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
