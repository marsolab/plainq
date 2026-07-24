import { afterEach, beforeEach, describe, expect, test } from "bun:test";

import { ApiRequestError, api, isAdministrator, sessionRoles } from "./api-client";

const SESSION_KEY = "plainq.session";

interface RecordedCall {
  url: string;
  method: string;
  body: string | null;
}

const calls: RecordedCall[] = [];
let originalFetch: typeof globalThis.fetch;

/**
 * The API client keeps its session in `window.localStorage`, and the test
 * runner has no DOM. A byte-for-byte store is enough: the client only reads and
 * writes one key, and what matters here is that it round-trips.
 */
function installWindow() {
  const store = new Map<string, string>();

  const localStorage = {
    getItem: (key: string) => store.get(key) ?? null,
    setItem: (key: string, value: string) => void store.set(key, value),
    removeItem: (key: string) => void store.delete(key),
    clear: () => store.clear(),
  };

  (globalThis as { window?: unknown }).window = {
    localStorage,
    location: { pathname: "/access", search: "", href: "" },
  };
}

/**
 * Answers every request with `body` so a test can assert on what was sent.
 * Status 204 is how the server answers deletes, and it is worth exercising:
 * parsing an empty body as JSON would turn a successful delete into a throw.
 */
function stubFetch(body: unknown, status = 200) {
  globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
    calls.push({
      url: String(input),
      method: init?.method ?? "GET",
      body: typeof init?.body === "string" ? init.body : null,
    });

    if (status === 204) return new Response(null, { status });

    return new Response(JSON.stringify(body), {
      status,
      headers: { "Content-Type": "application/json" },
    });
  }) as typeof fetch;
}

/** A JWT is three base64url segments; only the middle one is ever read. */
function tokenWithClaims(claims: Record<string, unknown>): string {
  const payload = btoa(JSON.stringify(claims))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");

  return `header.${payload}.signature`;
}

beforeEach(() => {
  calls.length = 0;
  originalFetch = globalThis.fetch;
  installWindow();
});

afterEach(() => {
  globalThis.fetch = originalFetch;
  delete (globalThis as { window?: unknown }).window;
});

describe("sessionRoles", () => {
  test("reads the roles the server signed into the access token", () => {
    window.localStorage.setItem(
      SESSION_KEY,
      JSON.stringify({
        accessToken: tokenWithClaims({ uid: "u1", email: "a@b.test", roles: ["admin", "consumer"] }),
        refreshToken: "r",
      }),
    );

    expect(sessionRoles()).toEqual(["admin", "consumer"]);
    expect(isAdministrator()).toBe(true);
  });

  test("a token without the role is not an administrator", () => {
    window.localStorage.setItem(
      SESSION_KEY,
      JSON.stringify({
        accessToken: tokenWithClaims({ roles: ["consumer"] }),
        refreshToken: "r",
      }),
    );

    expect(isAdministrator()).toBe(false);
  });

  test("no session and an unreadable token are both unknown, never denied", () => {
    expect(sessionRoles()).toBeNull();
    expect(isAdministrator()).toBeNull();

    window.localStorage.setItem(
      SESSION_KEY,
      JSON.stringify({ accessToken: "not-a-jwt", refreshToken: "r" }),
    );

    expect(sessionRoles()).toBeNull();
    expect(isAdministrator()).toBeNull();
  });

  test("a token whose claims carry no roles says nothing rather than none", () => {
    window.localStorage.setItem(
      SESSION_KEY,
      JSON.stringify({ accessToken: tokenWithClaims({ uid: "u1" }), refreshToken: "r" }),
    );

    // "The token did not say" and "the operator holds no roles" are different
    // facts; only the second may block a control.
    expect(sessionRoles()).toBeNull();
  });
});

describe("api.directory", () => {
  test("sends only the parameters that were given", async () => {
    stubFetch({ users: [], next_cursor: "", has_more: false, total: 0 });

    await api.directory.users();
    expect(calls[0]!.url).toBe("/api/v1/directory/users");

    await api.directory.users({ limit: 25, cursor: "01ABC", search: "ana@" });
    expect(calls[1]!.url).toBe("/api/v1/directory/users?limit=25&cursor=01ABC&search=ana%40");
  });
});

describe("api.rbac", () => {
  test("role writes address the documented routes", async () => {
    stubFetch({ role_id: "role-1", role_name: "auditor", created_at: "" });

    await api.rbac.roles.create("auditor");
    expect(calls[0]).toMatchObject({
      url: "/api/v1/rbac/roles",
      method: "POST",
      body: '{"role_name":"auditor"}',
    });

    await api.rbac.userRoles.assign("user-1", "role-1");
    expect(calls[1]).toMatchObject({
      url: "/api/v1/rbac/users/user-1/roles/role-1",
      method: "POST",
    });
  });

  test("a bulk grant save sends the whole matrix in one request", async () => {
    stubFetch({ role: { role_id: "role-1" }, grants: [] });

    await api.rbac.permissions.replaceForRole("role-1", [
      { queue_id: "queue-1", can_send: true, can_receive: false, can_purge: false, can_delete: false },
      { queue_id: "queue-2", can_send: false, can_receive: true, can_purge: false, can_delete: false },
    ]);

    expect(calls).toHaveLength(1);
    expect(calls[0]!.method).toBe("PUT");
    expect(calls[0]!.url).toBe("/api/v1/rbac/permissions/roles/role-1");
    expect(JSON.parse(calls[0]!.body!).grants).toHaveLength(2);
  });

  test("identifiers are escaped rather than pasted into the path", async () => {
    stubFetch([]);

    await api.rbac.permissions.forQueue("queue/../admin");

    expect(calls[0]!.url).toBe("/api/v1/rbac/permissions/queues/queue%2F..%2Fadmin");
  });
});

describe("api.oauth", () => {
  test("a delete accepts the server's empty 204 body", async () => {
    stubFetch(null, 204);

    await expect(api.oauth.providers.delete("idp-1")).resolves.toBeUndefined();
    expect(calls[0]).toMatchObject({
      url: "/api/v1/oauth/providers/idp-1",
      method: "DELETE",
    });
  });

  test("an update sends only the fields it was given", async () => {
    stubFetch({ provider_id: "idp-1", config: {}, redacted_keys: [] });

    await api.oauth.providers.update("idp-1", { is_active: false });

    expect(JSON.parse(calls[0]!.body!)).toEqual({ is_active: false });
  });
});

describe("api.system", () => {
  test("reads the sanitized configuration", async () => {
    stubFetch({ groups: [], read_at: "2026-07-24T09:00:00Z" });

    const response = await api.system.config();

    expect(calls[0]!.url).toBe("/api/v1/system/config");
    expect(response.read_at).toBe("2026-07-24T09:00:00Z");
  });

  test("a refusal arrives as an error carrying the status", async () => {
    stubFetch({ message: "Forbidden" }, 403);

    // The status is the whole of what the server said, so it has to survive
    // the throw for a caller to explain the refusal.
    await expect(api.system.config()).rejects.toBeInstanceOf(ApiRequestError);

    try {
      await api.system.config();
      throw new Error("expected the request to reject");
    } catch (error) {
      expect((error as ApiRequestError).status).toBe(403);
    }
  });
});
