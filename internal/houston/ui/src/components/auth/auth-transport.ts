import { API_BASE } from "@/lib/constants";
import { hasSession, readSession, storeSession } from "@/lib/api-client";
import type { ApiError } from "@/lib/types";

/**
 * Auth requests deliberately do not go through `api-client`'s `apiFetch`, even
 * though they hit the same endpoints with the same credential. Two reasons,
 * both load-bearing on these screens:
 *
 *  - `apiFetch` answers any 401 by refreshing and, failing that, redirecting to
 *    /login. On a sign-in form a wrong password *is* a 401, so that path would
 *    bounce the operator off the page they are trying to use.
 *  - it collapses the response to a message string. These screens must branch
 *    on the status itself: a rejected credential pair reads one fixed way, 503
 *    is the degraded state, and setup has to tell "already configured" apart
 *    from "the server disliked this input".
 *
 * The session the server hands back is stored through `api-client`, so every
 * later request carries it as a bearer token.
 */

export type ServiceState =
  /**
   * The service answered. `needsSetup` is the server's own onboarding signal,
   * `null` when it made no claim; `session` is whether this browser holds a
   * credential to present.
   */
  | { kind: "ready"; session: boolean; needsSetup: boolean | null }
  | { kind: "degraded"; ref?: string }
  | { kind: "unreachable"; endpoint: string };

export type AuthResult =
  | { ok: true }
  /** Any rejection of a credential pair. Never differentiated. */
  | { ok: false; kind: "credentials" }
  | { ok: false; kind: "verification" }
  | { ok: false; kind: "conflict" }
  | { ok: false; kind: "registration-disabled" }
  /** The server stated a rule of its own — surfaced verbatim, never guessed. */
  | { ok: false; kind: "rejected"; message: string }
  /** The request failed and the server gave no reason worth repeating. */
  | { ok: false; kind: "failed" }
  | { ok: false; kind: "degraded"; ref?: string }
  | { ok: false; kind: "unreachable"; endpoint: string };

/** The address the browser actually calls, for the "can't reach it" copy. */
export function serviceEndpoint(): string {
  if (typeof window === "undefined") return API_BASE;
  return new URL(API_BASE, window.location.origin).toString().replace(/\/$/, "");
}

/**
 * The default error responder writes `http.StatusText(code)` as a plain-text
 * body, so a body that is just the status phrase says nothing the status code
 * did not. Those are dropped; anything else — a JSON envelope or a real
 * sentence — is the server speaking and is kept as it was written.
 */
const STATUS_PHRASES = new Set([
  "bad request",
  "unauthorized",
  "forbidden",
  "not found",
  "method not allowed",
  "conflict",
  "internal server error",
  "service unavailable",
]);

async function readError(response: Response): Promise<ApiError | null> {
  const body = (await response.text().catch(() => "")).trim();
  if (!body) return null;

  try {
    return JSON.parse(body) as ApiError;
  } catch {
    const phrase = body.toLowerCase();
    if (phrase === response.statusText.trim().toLowerCase()) return null;
    return STATUS_PHRASES.has(phrase) ? null : { message: body };
  }
}

async function readOnboardingStatus(response: Response): Promise<boolean | null> {
  try {
    const body = (await response.json()) as { needs_onboarding?: unknown };
    return typeof body.needs_onboarding === "boolean" ? body.needs_onboarding : null;
  } catch {
    return null;
  }
}

/**
 * Reachability is read off `/onboarding/status`: it is public, mounted
 * unconditionally, and it is the one endpoint that answers a question the gate
 * actually needs — whether this server has an administrator yet.
 *
 * Session state is *not* read off a queue listing. Those routes carry no
 * authentication at all, so a 200 there says nothing about who is asking. The
 * only honest signal is whether this browser holds a credential to present.
 */
export async function probeService(): Promise<ServiceState> {
  let response: Response;
  try {
    response = await fetch(`${API_BASE}/onboarding/status`, {
      headers: { Accept: "application/json" },
    });
  } catch {
    return { kind: "unreachable", endpoint: serviceEndpoint() };
  }

  if (response.status >= 500) {
    const error = await readError(response);
    return { kind: "degraded", ref: error?.code };
  }

  // Left null when the server made no claim — a missing answer is not evidence
  // either way, and the gate treats it as one.
  const needsSetup = response.ok ? await readOnboardingStatus(response) : null;

  return { kind: "ready", session: hasSession(), needsSetup };
}

/** Re-reads the onboarding signal on its own, for disambiguating a rejection. */
async function stillNeedsSetup(): Promise<boolean | null> {
  try {
    const response = await fetch(`${API_BASE}/onboarding/status`, {
      headers: { Accept: "application/json" },
    });
    if (!response.ok) return null;
    return await readOnboardingStatus(response);
  } catch {
    return null;
  }
}

function postJson(path: string, body: unknown): Promise<Response> {
  return fetch(`${API_BASE}${path}`, {
    method: "POST",
    headers: { "Content-Type": "application/json", Accept: "application/json" },
    body: JSON.stringify(body),
  });
}

/**
 * The only signal for an unverified address is what the server called the
 * failure. Match narrowly — anything unrecognised falls back to the
 * non-enumerating credential message.
 */
function indicatesUnverifiedEmail(error: ApiError | null): boolean {
  const text = `${error?.code ?? ""} ${error?.message ?? ""}`.toLowerCase();
  return text.includes("verif");
}

/** Persists the session the endpoint returned. False when it returned none. */
async function keepSession(response: Response): Promise<boolean> {
  let payload: unknown;
  try {
    payload = await response.json();
  } catch {
    return false;
  }

  const session = readSession(payload);
  if (!session) return false;

  storeSession(session);
  return true;
}

export async function signIn(input: {
  email: string;
  password: string;
}): Promise<AuthResult> {
  let response: Response;
  try {
    response = await postJson("/account/signin", input);
  } catch {
    return { ok: false, kind: "unreachable", endpoint: serviceEndpoint() };
  }

  if (response.ok) {
    // The screen may not report success before the credential is in hand: the
    // server sets no cookie, so a navigation without the token lands in the app
    // signed out.
    return (await keepSession(response))
      ? { ok: true }
      : { ok: false, kind: "failed" };
  }

  const error = await readError(response);

  // 503 is the service saying it is unavailable — the one status here that is
  // never produced by a bad credential pair. Every other failure collapses into
  // one message: an unknown address and a wrong password must not be told
  // apart, and this server answers them with different statuses.
  if (response.status === 503) return { ok: false, kind: "degraded", ref: error?.code };
  if (indicatesUnverifiedEmail(error)) return { ok: false, kind: "verification" };

  return { ok: false, kind: "credentials" };
}

export async function signUp(input: {
  email: string;
  password: string;
  name?: string;
}): Promise<AuthResult> {
  let response: Response;
  try {
    response = await postJson("/account/signup", input);
  } catch {
    return { ok: false, kind: "unreachable", endpoint: serviceEndpoint() };
  }

  if (response.ok) return { ok: true };

  const error = await readError(response);
  if (response.status === 503) return { ok: false, kind: "degraded", ref: error?.code };
  if (response.status === 403) return { ok: false, kind: "registration-disabled" };
  if (response.status === 409) return { ok: false, kind: "conflict" };
  if (error?.message) return { ok: false, kind: "rejected", message: error.message };

  // A duplicate address and an internal fault both arrive here as an unlabelled
  // 500. Calling that "the service is unavailable" would be a claim about the
  // service the response does not support.
  return { ok: false, kind: "failed" };
}

/**
 * First-run administrator. `/onboarding/complete` is the endpoint built for it:
 * public, mounted whether or not auth is enabled, and the only one that creates
 * a verified account with the admin role and returns a session for it.
 */
export async function completeOnboarding(input: {
  email: string;
  password: string;
  name?: string;
}): Promise<AuthResult> {
  let response: Response;
  try {
    response = await postJson("/onboarding/complete", input);
  } catch {
    return { ok: false, kind: "unreachable", endpoint: serviceEndpoint() };
  }

  if (response.ok) {
    return (await keepSession(response))
      ? { ok: true }
      : { ok: false, kind: "failed" };
  }

  const error = await readError(response);
  if (response.status === 503) return { ok: false, kind: "degraded", ref: error?.code };

  // "Already completed" and "bad input" are both a bare 400 here, so the
  // difference is settled by asking the server which one it is rather than by
  // reading tea leaves in the body.
  if (response.status === 400 && (await stillNeedsSetup()) === false) {
    return { ok: false, kind: "conflict" };
  }

  if (error?.message) return { ok: false, kind: "rejected", message: error.message };

  return { ok: false, kind: "failed" };
}
