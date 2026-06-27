import { API_BASE } from "./constants";
import type {
  Queue,
  QueueListResponse,
  TopicListResponse,
  PublishResponse,
  AuthTokens,
  ApiError,
  PeekResponse,
  ReceiveResponse,
  SendResponse,
  DeleteResponse,
} from "./types";

async function apiFetch<T>(path: string, options?: RequestInit): Promise<T> {
  const response = await fetch(`${API_BASE}${path}`, {
    credentials: "include",
    headers: {
      "Content-Type": "application/json",
      ...options?.headers,
    },
    ...options,
  });

  if (response.status === 401) {
    try {
      await fetch(`${API_BASE}/account/refresh`, {
        method: "POST",
        credentials: "include",
      });
      return apiFetch(path, options);
    } catch {
      window.location.href = "/login";
      throw new Error("Session expired");
    }
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
      ),
    get: (id: string) => apiFetch<Queue>(`/queue/${id}`),
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
        const res = await apiFetch<{ message_ids?: string[] }>(
          `/queue/${id}/messages`,
          {
            method: "POST",
            body: JSON.stringify({
              messages: bodies.map((b) => ({ body: utf8ToBase64(b) })),
            }),
          },
        );
        return { messageIds: res.message_ids ?? [] };
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
      // Acknowledge (delete) messages by id.
      ack: async (id: string, ids: string[]): Promise<DeleteResponse> => {
        const res = await apiFetch<{
          successful?: string[];
          failed?: { message_id: string; error: string }[];
        }>(`/queue/${id}/messages/ack`, {
          method: "POST",
          body: JSON.stringify({ message_ids: ids }),
        });
        return {
          successful: res.successful ?? [],
          failed: (res.failed ?? []).map((f) => ({
            messageId: f.message_id,
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
  auth: {
    signin: (data: { email: string; password: string }) =>
      apiFetch<AuthTokens>("/account/signin", {
        method: "POST",
        body: JSON.stringify(data),
      }),
    signup: (data: { email: string; password: string; name?: string }) =>
      apiFetch<AuthTokens>("/account/signup", {
        method: "POST",
        body: JSON.stringify(data),
      }),
    signout: () =>
      apiFetch<void>("/account/signout", { method: "POST" }),
    refresh: () =>
      apiFetch<AuthTokens>("/account/refresh", { method: "POST" }),
  },
};
