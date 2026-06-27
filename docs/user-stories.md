# PlainQ User Stories

This document captures the product's user stories, **grouped by role**, with
acceptance criteria and a mapping to where each story is implemented (gRPC API,
CLI, TUI, and the Houston admin UI). It is the source of truth for "who can do
what" in PlainQ and is kept in sync with the RBAC model.

PlainQ ships three built-in roles plus two operational personas:

| Persona | Role(s) | Primary surface |
| --- | --- | --- |
| **Producer** | `producer`, `admin` | gRPC, CLI, TUI |
| **Consumer** | `consumer`, `admin` | gRPC, CLI, TUI |
| **Admin** | `admin` | Houston UI, CLI, gRPC |
| **Operator / DevOps** | n/a (infra) | Helm, Docker, `/health`, `/metrics` |
| **AI Agent / Integrator** | scoped token | CLI `--json`, gRPC |

Permissions are enforced per queue (`send`, `receive`, `purge`, `delete`) with
an `admin` bypass — see [`docs/authentication-rbac.md`](authentication-rbac.md).

Legend for status: ✅ implemented · 🟡 partial · ⬜ planned.

---

## Producer

A producer is an application (or person) that publishes messages to a queue.

### P1 — Send a message to a queue ✅
> As a producer, I want to send one or more messages to a queue so that
> consumers can process them asynchronously.

**Acceptance criteria**
- A message with an arbitrary byte body is accepted and assigned a unique ID.
- Multiple messages can be sent in a single batched request.
- The returned message IDs are stable and can be referenced later.

**Implemented in**
- gRPC: `PlainQService.Send` ([schema](../schema/v1/schema.proto))
- CLI: `plainq send <queue-id> --message <text>` / `--file` / stdin
- TUI: `s` (send) action in the queue detail view
- Houston: queue detail → **Messages** tab (Send a message)

### P2 — Send a batch from a file or stdin ✅
> As a producer, I want to pipe message bodies from a file or stdin so that I
> can script bulk publishing.

**Acceptance criteria**
- `--file -` reads newline-delimited bodies from stdin.
- Each non-empty line becomes one message; IDs are reported per message.

**Implemented in**
- CLI: `plainq send <queue-id> --file <path|->`

### P3 — Choose delivery semantics per queue ✅
> As a producer, I want queues to retry, dead-letter, or drop messages so that
> failures are handled according to my durability needs.

**Acceptance criteria**
- `visibility-timeout`, `max-receive-attempts`, `retention-period`, and an
  eviction policy (`drop`, `dead-letter`, `reorder`) are configurable at create
  time.
- Dead-letter routes evicted messages to a named DLQ.

**Implemented in**
- gRPC: `CreateQueue` (`EvictionPolicy`, timeouts)
- CLI: `plainq create` flags
- Houston: create-queue dialog

---

## Consumer

A consumer is an application (or person) that reads and acknowledges messages.

### C1 — Receive a batch of messages ✅
> As a consumer, I want to receive up to N messages at once so that I can
> process them efficiently.

**Acceptance criteria**
- Batch size 1–10 is honored; messages become invisible for the visibility
  timeout once received.
- Each message includes its ID and body.

**Implemented in**
- gRPC: `Receive`
- CLI: `plainq receive <queue-id> --batch <n>`
- TUI: `r` (receive) action in the queue detail view
- Houston: queue detail → **Messages** tab (Receive with batch 1–10)

### C2 — Acknowledge (delete) processed messages ✅
> As a consumer, I want to delete messages I have processed so that they are
> not redelivered.

**Acceptance criteria**
- One or more message IDs can be deleted in a single call.
- The response distinguishes successful deletes from failures (with reasons).

**Implemented in**
- gRPC: `Delete`
- CLI: `plainq delete-message <queue-id> <message-id>...`
- TUI: `d` (delete) action in the message list
- Houston: queue detail → **Messages** tab (Ack on in-flight or browsed rows)

### C3 — Receive-then-delete in one step ✅
> As a consumer, I want a convenience flow that receives and immediately
> acknowledges so that I can drain a queue quickly in scripts.

**Acceptance criteria**
- `plainq receive --ack` deletes each received message after printing it.

**Implemented in**
- CLI: `plainq receive <queue-id> --ack`

### C4 — Browse messages without consuming them ✅
> As a consumer (or admin), I want to inspect what is sitting in a queue from
> the web UI without claiming or hiding the messages, so that I can debug a
> backlog safely.

**Acceptance criteria**
- A browse (peek) returns messages oldest-first with id, body, retry count, and
  an in-flight indicator, paginated by limit/offset.
- Peeking never changes a message's visibility deadline or retry count, so it is
  safe to refresh repeatedly while consumers are running.

**Implemented in**
- HTTP: `GET /api/v1/queue/{id}/messages` (non-consuming `Storage.Peek` in both
  the SQLite and Postgres backends)
- Houston: queue detail → **Messages** tab (Browse table with pagination)

---

## Admin

An admin manages queues, users, roles, and per-queue permissions.

### A1 — Create, describe, list, purge, and delete queues ✅
> As an admin, I want full lifecycle control over queues so that I can manage
> the messaging topology.

**Acceptance criteria**
- List supports prefix filter, ordering, sort direction, and pagination.
- Describe returns all queue properties (timeouts, attempts, policy, DLQ).
- Purge removes all messages; delete removes the queue (with `--force`).

**Implemented in**
- gRPC: `ListQueues`, `DescribeQueue`, `CreateQueue`, `PurgeQueue`, `DeleteQueue`
- CLI: `list`, `describe`, `create`, `purge`, `delete`
- TUI: queue list with create/purge/delete actions
- Houston: queues pages

### A2 — Onboard the first admin securely ✅
> As an admin, I want a one-time secure onboarding instead of default
> credentials so that the system is never shipped with a known password.

**Acceptance criteria**
- Until an admin exists, protected endpoints return `428 Precondition Required`.
- `POST /onboarding/complete` creates exactly one admin with a strong password.

**Implemented in**
- HTTP: onboarding service · Houston: signup flow

### A3 — Manage users, roles, and queue permissions ✅
> As an admin, I want to assign roles and grant per-queue permissions so that I
> can apply least privilege.

**Acceptance criteria**
- Roles (`admin`, `producer`, `consumer`) can be assigned/removed per user.
- Per-queue `send`/`receive`/`purge`/`delete` permissions can be granted.

**Implemented in**
- HTTP: RBAC service · Houston: users page

### A4 — Authenticate via JWT or OAuth/OIDC ✅
> As an admin, I want built-in JWT sessions and pluggable OAuth so that I can
> integrate with Kinde/Auth0/Okta/WorkOS.

**Implemented in**
- HTTP: account + oauth services · middleware: `auth`, `oauth`, `rbac`

---

## Operator / DevOps

An operator deploys, scales, observes, and secures the server.

### O1 — Run the whole thing as a single binary or container ✅
> As an operator, I want one self-contained artifact so that there is no broker
> fleet to manage.

**Implemented in**
- `plainq serve` · optimized multi-stage [`Dockerfile`](../Dockerfile)

### O2 — Deploy to Kubernetes with Helm ✅
> As an operator, I want a Helm chart so that I can deploy and configure PlainQ
> declaratively, with persistence for SQLite or an external Postgres.

**Acceptance criteria**
- StatefulSet + PVC for SQLite; Deployment + HPA for Postgres.
- JWT secret sourced from a Kubernetes Secret.

**Implemented in**
- [`deploy/helm/plainq`](../deploy/helm/plainq)

### O3 — Observe health and metrics ✅
> As an operator, I want `/health` and Prometheus `/metrics` so that I can wire
> probes, dashboards, and alerts.

**Implemented in**
- HTTP: `-health.route` (`/health`), `-metrics.route` (`/metrics`)
- Helm: liveness/readiness probes; optional Prometheus Operator `ServiceMonitor`
  (`metrics.serviceMonitor.enabled`)

### O4 — Pick the right storage backend ✅
> As an operator, I want embedded SQLite for small/local deployments and
> Postgres for shared/scaled deployments.

**Implemented in**
- `-storage.driver=sqlite|postgres`

### O5 — Build, test, and lint in CI ✅
> As an operator, I want CI to build the binary and image, run tests, and lint
> so that regressions are caught before merge.

**Implemented in**
- `.github/workflows/pr.yml`, `main.yml`, `docker.yml`

---

## AI Agent / Integrator

An automated agent or service drives PlainQ programmatically.

### AI1 — Machine-readable output from every command ✅
> As an AI agent, I want `--json` on every CLI command so that I can parse
> results deterministically without scraping human text.

**Acceptance criteria**
- Every command supports `--json` and emits a single JSON object/array.
- Errors are reported on stderr; exit codes are non-zero on failure.

**Implemented in**
- CLI: `--json` on all client commands

### AI2 — Self-describing CLI ✅
> As an AI agent, I want discoverable help and a stable command surface so that
> I can plan tool calls.

**Implemented in**
- CLI: `-h`/`--help` on root and subcommands; `plainq schema` prints the surface

### AI3 — Generate clients from the published schema ✅
> As an integrator, I want the protobuf schema published so that I can generate
> a client in any language.

**Implemented in**
- [Buf Schema Registry: buf.build/plainq/schema](https://buf.build/plainq/schema)

### AI4 — Stable IDs and idempotent-friendly operations ✅
> As an integrator, I want stable message/queue IDs so that I can build
> idempotent pipelines.

**Implemented in**
- XID-based queue IDs; ULID-based message IDs

---

## Traceability matrix

| Story | gRPC | CLI | TUI | Houston |
| --- | :--: | :--: | :--: | :--: |
| P1 Send | ✅ | ✅ | ✅ | ✅ |
| P2 Batch/stdin | — | ✅ | — | — |
| P3 Delivery semantics | ✅ | ✅ | — | ✅ |
| C1 Receive | ✅ | ✅ | ✅ | ✅ |
| C2 Delete message | ✅ | ✅ | ✅ | ✅ |
| C3 Receive+ack | — | ✅ | — | — |
| C4 Browse (peek) | — | — | — | ✅ |
| A1 Queue lifecycle | ✅ | ✅ | ✅ | ✅ |
| A2 Onboarding | ✅ | — | — | ✅ |
| A3 RBAC | ✅ | — | — | ✅ |
| A4 Auth | ✅ | — | — | ✅ |
| O1 Single binary | — | ✅ | — | — |
| O2 Helm | — | — | — | — |
| O3 Health/metrics | — | — | — | ✅ |
| AI1 JSON output | — | ✅ | — | — |
