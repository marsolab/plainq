import { afterEach, describe, expect, test } from "bun:test";
import { api } from "./api-client";

const originalFetch = globalThis.fetch;

afterEach(() => {
  globalThis.fetch = originalFetch;
});

function stubFetch(handler: (url: string) => Response): void {
  globalThis.fetch = (async (input: RequestInfo | URL) =>
    handler(String(input))) as typeof fetch;
}

describe("auth.signin", () => {
  // A wrong password must reach the form as an error. Public identity requests
  // opt out of the 401 refresh/redirect path, so the status-prefixed message
  // surfaces instead of a "Session expired" bounce to /login.
  test("surfaces a 401 as an error rather than redirecting", async () => {
    stubFetch((url) => {
      if (url.includes("/account/signin")) {
        return new Response(JSON.stringify({ message: "invalid credentials" }), {
          status: 401,
          headers: { "Content-Type": "application/json" },
        });
      }

      return new Response(JSON.stringify({}), { status: 200 });
    });

    await expect(
      api.auth.signin({ email: "user@example.com", password: "wrong" }),
    ).rejects.toThrow("401: invalid credentials");
  });
});

describe("auth.signup", () => {
  // Registration answers 201 with an empty body and no session. signup must
  // report that as "no session" so the caller sends the user to sign in rather
  // than into the app, where the first request would 401.
  test("returns null when the server answers 201 with no body", async () => {
    stubFetch((url) => {
      if (url.includes("/account/signup")) {
        return new Response("", { status: 201 });
      }

      return new Response(JSON.stringify({}), { status: 200 });
    });

    const session = await api.auth.signup({
      email: "user@example.com",
      password: "supersecret",
    });

    expect(session).toBeNull();
  });
});
