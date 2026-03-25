import { API_BASE } from "./constants";
import type { Queue, QueueListResponse, AuthTokens, ApiError } from "./types";

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
