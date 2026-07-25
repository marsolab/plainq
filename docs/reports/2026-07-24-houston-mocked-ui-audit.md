# Houston Mocked-UI Functionality Audit

**Audit date:** 2026-07-24
**Scope:** The shipped Houston UI in `internal/houston/ui`, its browser API client,
and the HTTP routes mounted by `internal/server`. This is a source-level audit; it
does not claim that a particular deployment has a given feature flag or data set.

> **Status: remediated.** The findings below describe the code as it stood on the
> audit date. Every capability classified as mocked has since been implemented
> against real endpoints; see [Remediation](#remediation-2026-07-24) at the end of
> this document for what was built, what is deliberately still absent, and which
> statements below no longer describe the code.

## Executive summary

Houston has two surfaces that render server-shaped data without reading it:

1. **Access** (`/access`) is a complete local simulation. Its users, roles, queue
   grants, organisations, teams, and identity providers are seeded browser state.
   User changes, role-grant saves, team membership changes, and provider creation
   or deletion disappear on reload. Its query-string `scenario` values manufacture
   loading, empty, stale, unavailable, and read-only states rather than reflecting
   a server response.
2. **System configuration** (`/system`) displays example startup settings marked
   `Not live`. They are not read from the running instance. The same page's
   **Health** panel is not mocked: it performs a live one-row queue-list request,
   but it can only infer API/datastore reachability and cannot report GC or
   telemetry health.

There is an important implementation mismatch behind the Access UI. The backend
already mounts authenticated RBAC and OAuth HTTP subtrees, and several operations
the UI simulates have real server endpoints. Houston's API client has no `rbac` or
`oauth` methods and the Access components make no network requests, so those
server capabilities are currently invisible to the UI. Conversely, the backend
still lacks a user-directory API, configuration read API, a browser OAuth callback
flow, and complete provider/organisation APIs. The report separates these two
failure modes so remediation does not duplicate backend work.

## Method and classification

The audit traced every UI route, state source, and mutation handler, then compared
the requested paths with the routes mounted under `/api/v1`. A capability is:

| Classification | Meaning |
| --- | --- |
| **Mocked / no usable backend** | The UI renders or mutates local/example data and the required server capability is absent or explicitly incomplete. |
| **Mocked / backend available but not wired** | The UI uses local state even though the backend mounts a broadly corresponding endpoint. Contract mapping, authorization, and error handling still need implementation. |
| **Read-only example data** | The UI deliberately labels values as non-live; there is no mutation to persist. |
| **Live, limited** | The UI performs a real request but only supports the stated narrower claim. |

## Findings

### P0 — Access is a local simulation, including security-sensitive mutations

**User-visible surface:** `/access`, with Users, Roles, Organizations & Teams, and
Identity providers tabs.

**Evidence:** `mock-data.ts` explicitly states that Access has no transport and
exports fixture collections for all four domains. `AccessPage` initializes its
state from those collections and calls `loadDirectory`, which returns mocked rows
after a fixed timeout. The page keeps changes only in React state.

**Impact:** Operators can believe they are managing authorization or identities
when they are only changing the current browser tab. The fabricated `stale` and
`unavailable` states also cannot exercise real HTTP error handling, session expiry,
authorization, or response validation.

**Affected interactions:**

| UI interaction | Present behavior | Classification | Required remediation |
| --- | --- | --- | --- |
| View/search/filter users; view account type, verification, organization, roles, and sync time | Reads `MOCK_USERS`; directory retries re-run the timed mock. | Mocked / no usable backend | Add an authorized, paginated account-directory API with a deliberately safe response shape, then replace `loadDirectory` and fixture-derived details. Account storage currently exposes lookup by ID/email but no list operation or HTTP route. |
| Assign/remove a user's role in the user sheet | Updates local `roleIds`; reload discards it. | Mocked / backend available but not wired | Wire `GET /api/v1/rbac/users/{userID}/roles`, `POST` and `DELETE /api/v1/rbac/users/{userID}/roles/{roleID}`, then refresh/invalidate affected users and roles. The UI must also obtain its user list from a real directory. |
| Edit a role's queue permission matrix and save | Stages local grants, waits 400 ms, then writes React state and displays success. | Mocked / backend available but not wired | Read roles and queues from server; use the RBAC queue permission routes per changed row. Define a bulk/transactional endpoint if atomic multi-row save is a requirement. Do not retain the fake success path. |
| View per-queue Access matrix | Renders `SAMPLE_ROLE_GRANTS` with an explicit Sample badge. | Mocked / backend available but not wired | Request `GET /api/v1/rbac/permissions/queues/{queueID}` and map its role/permission response. Add write controls only after deciding the authorization policy. |
| View organizations and teams; add/remove membership | Uses fixture organizations/rosters; membership actions wait locally and mutate React state. | Mocked / backend partly available but not wired | Wire team list and user-team membership endpoints after obtaining real users and organizations. The organisation list endpoint is currently placeholder-only and there are no organization create/update/delete routes, so organization administration also needs backend completion. |
| List/create/delete identity providers | Uses fixture providers; create generates a browser timestamp ID and discards issuer/client credentials; delete only removes local state. | Mocked / backend partly available but not wired | Wire provider list/create/delete endpoints and return only secret-safe provider fields. Implement provider lookup/update before enabling edit. Never fake a successful secret write. |
| Edit a provider and use "Sign in with…" / callback | UI disables edit and says no browser flow exists. | Mocked / no usable backend | Implement provider-by-ID retrieval/update and a browser authorization-code/callback flow, including state/PKCE, credential protection, identity validation, session issuance, and tests. |
| Invite/suspend/delete user; reset password | The UI says these APIs do not exist. | No UI implementation / no backend | Decide product scope, then add audited account-management operations with authorization, self-lockout protections, and notification/reset semantics before exposing controls. |

### P1 — Backend/UI integration mismatch in Access

The Access source comments are no longer fully accurate. The server mounts both
`/api/v1/rbac` and `/api/v1/oauth` behind authentication. RBAC implements role
CRUD, user-role assignment, and queue-permission reads/writes. OAuth implements
provider list/create/delete, team list, and user-team membership routes. The
browser API client exposes queues, topics, metrics, and auth only; it contains no
`rbac` or `oauth` namespace. This proves the present mock state is primarily an
unwired client for several operations, rather than evidence that every backend
endpoint is absent.

However, this backend is not sufficient to turn on the whole screen unchanged:

* The account service has no list-users method or route, so the user directory
  cannot be populated safely from the existing public API.
* `GET /oauth/providers/{providerID}` and `PUT /oauth/providers/{providerID}`
  intentionally return “not implemented yet”.
* `GET /oauth/organizations` authenticates the request but returns an empty list
  and empty user organization as a placeholder. There are no organization-write
  routes.
* OAuth synchronization is a service API, not a browser sign-in flow. No Houston
  callback page/route exists.
* The RBAC service's per-queue endpoint is available, but RBAC enforcement is not
  attached to queue HTTP routes in the server route assembly; it should not be
  presented as proof that UI grants currently govern queue operations.

### P1 — System configuration is intentionally non-live

**User-visible surface:** `/system` Startup configuration panels.

**Present behavior:** The configuration module contains concrete example values
such as a PostgreSQL DSN, token TTLs, ports, and telemetry retention. The page
places a `Not live` badge on every configuration panel and warns that it is showing
the shape of configuration rather than the running instance.

**Classification:** Read-only example data. This is honest presentation rather
than a deceptive mutation flow, but it is still mocked information that must not
be relied on operationally.

**Required remediation:** Add a sanitized, authenticated, read-only configuration
endpoint that derives values from the effective runtime configuration. Return
explicit redaction metadata for secrets/DSNs. Replace `STARTUP_CONFIG` only once
the endpoint and contract tests exist; retain the no-copy rule for redacted values.

### Not findings: live or deliberately bounded functionality

These elements should **not** be reported as mocked:

* Queues, messages, topics/subscriptions/publishing, authentication, and metrics
  use the shared API client and issue `/api/v1` requests.
* The System Health panel reads `api.queues.list({ limit: 1 })`. It accurately
  labels GC and telemetry as “Not reported”; it does not invent component health.
* The per-queue Access panel calls its rows sample data and says no server read is
  made. It is included above because it looks like an authorization view, not
  because it hides the limitation.

## Recommended delivery plan

1. **Remove the access-control illusion first.** Until persistence is wired,
   hide mutating Access controls or place an unmissable page-level non-persistent
   banner on the route. Do not represent local saves as server-side success.
2. **Define and test contracts.** Add typed frontend DTOs and endpoint tests for
   user directory, RBAC roles/grants, OAuth providers, organizations, and teams.
   Use API responses as the single source of truth, including 401/403/409/5xx
   behavior. Do not expose provider secrets in list/read responses.
3. **Wire existing backend capability.** Add `api.rbac` and `api.oauth` modules;
   replace fixtures with asynchronous queries, loading/error/empty states, and
   post-mutation refetches. Start with read-only server data, then enable one
   mutation at a time.
4. **Close backend gaps.** Implement paginated user directory, provider get/update,
   organization reads/writes as product requirements demand, and a genuine OAuth
   browser callback flow. Add server-side RBAC middleware to queue operations if
   queue grants are meant to enforce them.
5. **Make System configuration live separately.** It is a distinct operational
   concern: add a sanitized configuration read endpoint, not write controls.

## Acceptance criteria for removing this report's P0/P1 findings

* A reload after every enabled Access mutation shows the persisted server value.
* No Access component imports fixture records or uses timeout-based pretend API
  calls for production states.
* The browser API client contains typed, authenticated `rbac` and `oauth` calls;
  tests cover success, authorization failure, validation failure, and server error.
* The user table is backed by a paginated, authorization-scoped directory API; it
  never exposes password hashes, provider secrets, or unrestricted tenant data.
* Provider edit stays disabled until server get/update and an end-to-end browser
  OAuth callback flow are implemented and tested.
* Every displayed System configuration fact is either returned by the sanitized
  runtime endpoint with redaction metadata or remains explicitly labeled example
  data. No redacted secret is copyable.

## Remediation (2026-07-24)

Every capability the table above classifies as **mocked** now reads and writes
real server state. What follows records what was added, what deliberately was
not, and the two claims in this report that the change makes obsolete.

### New server capability

| Endpoint | Purpose |
| --- | --- |
| `GET /api/v1/directory/users` | Paginated account directory: keyset cursor, server-side email search, a real `count(*)` total, and each account's roles, teams and organization. Built from an explicit safe-column list, so no password hash or OAuth subject can reach it. |
| `GET /api/v1/rbac/permissions/roles/{roleID}` | One role's whole grant set. |
| `PUT /api/v1/rbac/permissions/roles/{roleID}` | Replaces that grant set in one transaction, so a half-applied permission matrix is never observable. Answers with what was stored, not with what was sent. |
| `GET /api/v1/oauth/providers/{providerID}` | Implemented; previously answered "not implemented yet". |
| `PUT /api/v1/oauth/providers/{providerID}` | Implemented, with the merge rule below for secrets. |
| `GET /api/v1/oauth/organizations` | Returns the organizations the server actually stores; previously a placeholder empty list. |
| `GET /api/v1/oauth/sync/user/{userID}` | Returns the recorded synchronization state; previously a hard-coded `is_synced: false`. |
| `GET /api/v1/system/config` | Sanitized, administrator-only view of the effective runtime configuration, with explicit redaction metadata. |

### Authorization

Reading the authorization model is open to any authenticated caller — that is
what makes a truthful read-only view possible — while every RBAC and OAuth write
now requires the `admin` role. Before this change any authenticated account could
call `POST /api/v1/rbac/users/{self}/roles/{admin}` and grant itself the whole
model; that is now `403`.

Four guards are enforced server-side rather than described in the UI:

* the last account holding `admin` cannot lose it (`409`);
* the `admin` role cannot be deleted or renamed (`400`) — authorization resolves
  it by name;
* a role still held by accounts cannot be deleted (`409`);
* a duplicate role assignment answers `409` rather than reporting a change that
  did not happen.

### Secrets

Providers are returned through one projection that drops credential material and
names what it withheld in `redacted_keys`. A redacted value is *absent*, never
masked into a lookalike string. An update that does not mention a secret key
keeps the stored value, so an edit form that cannot display a secret cannot erase
one either; sending the key with an empty value is how a caller clears it
deliberately.

The configuration endpoint reports secrets as `set` / `not set` with
`redacted: true`, and returns database DSNs with the credentials removed rather
than masked.

### Houston

`access/mock-data.ts` and `system/mock-data.ts` are deleted. The Access screens,
the per-queue Access panel and the System configuration panels now issue
requests through typed `api.directory`, `api.rbac`, `api.oauth` and `api.system`
clients, with real loading, empty, error and stale states and a refetch after
every mutation. The `?scenario=` switch is gone: loading, empty and stale are
what the transport does, and read-only is derived from the roles the server
signed into the access token — a signal the server itself enforces.

### Deliberately still absent

* **No browser OAuth sign-in flow.** There is no authorization-code redirect and
  no callback route, so provider configuration serves the synchronization API and
  nothing else. The Identity providers screen says exactly that.
* **Queue grants are not enforced.** `middleware.RequireQueuePermission` exists
  but is not mounted on the queue routes. Mounting it would deny every queue
  operation on deployments that have configured no grants, so it stays a
  deliberate decision rather than a side effect of this work. Both the role
  editor and the per-queue panel state that grants are stored but not consulted.
* **No account lifecycle.** Invite, suspend, delete and password reset still have
  no API, and Houston still offers no control for them.
* **Organizations and teams remain read-only.** Membership is writable; create,
  rename and delete have no API.

### Statements above that no longer hold

* "OAuth ... `GET`/`PUT /oauth/providers/{providerID}` intentionally return 'not
  implemented yet'" and "`GET /oauth/organizations` ... returns an empty list" —
  both are implemented.
* "The account service has no list-users method or route" — it has both.
