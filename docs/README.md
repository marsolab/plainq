# PlainQ Documentation

Welcome to the PlainQ documentation. PlainQ is a truly simple queue service: a
single Go binary that gives you a gRPC API, a CLI, and a built-in admin web UI
(Houston), backed by either embedded SQLite or PostgreSQL.

This documentation is organized so you can move from "never heard of it" to
"running it in production" without leaving the page tree.

## Start here

| If you want to…                                  | Read this                                            |
| ------------------------------------------------ | ---------------------------------------------------- |
| Get a message round-trip in under a minute       | [Quick start](getting-started/quickstart.md)         |
| Install or build PlainQ                          | [Installation](getting-started/installation.md)      |
| Understand queues, messages, and the model       | [Core concepts](getting-started/core-concepts.md)    |

## Guides

| Guide                                                          | What it covers                                                      |
| -------------------------------------------------------------- | ------------------------------------------------------------------- |
| [CLI](guides/cli.md)                                           | Every `plainq` command, flags, and scripting patterns.              |
| [Terminal UI (TUI)](guides/tui.md)                             | The interactive Bubble Tea queue browser.                           |
| [User stories](user-stories.md)                                | What each role can do, with a traceability matrix.                  |
| [Queues & messages](guides/queues-and-messages.md)             | Visibility timeout, retries, retention, eviction, dead-letter.      |
| [gRPC API](guides/grpc-api.md)                                 | The wire protocol, the eight RPCs, generating clients.              |
| [Configuration](guides/configuration.md)                       | Every `serve` flag, grouped and explained.                          |
| [Advanced topics](guides/advanced.md)                          | Pub/sub fan-out, throughput tuning, scaling, GC, delivery guarantees. |
| [Deployment](guides/deployment.md)                             | SQLite + Litestream, PostgreSQL, containers, hardening.             |
| [Observability](guides/observability.md)                       | Health, Prometheus metrics, telemetry, logs.                        |
| [Houston (admin UI)](guides/houston.md)                        | The bundled dashboard and onboarding flow.                          |
| [Troubleshooting & FAQ](guides/troubleshooting.md)             | Common errors, fixes, and frequent questions.                       |
| [Authentication & RBAC](authentication-rbac.md)                | JWT sessions, roles, queue permissions, onboarding.                 |
| [OAuth, organizations & teams](oauth-organizations-teams.md)   | External identity providers and multi-tenancy.                      |

## Examples

| Example                                                        | Pattern                                                             |
| -------------------------------------------------------------- | ------------------------------------------------------------------- |
| [Examples & recipes](examples/README.md)                       | Worker loops, dead-letter queues, batching, JSON scripting, Go SDK. |

## Reference

| Reference                                                      | Contents                                                            |
| -------------------------------------------------------------- | ------------------------------------------------------------------- |
| [CLI reference](reference/cli.md)                              | Command + flag tables for quick lookup.                             |
| [Configuration reference](reference/configuration.md)          | Full `serve` flag table with defaults.                              |

## The 30-second mental model

```
                    ┌──────────────────────────────────────────┐
                    │                plainq serve              │
                    │                                          │
  CLI / gRPC  ─────▶│  gRPC :8080 ── Queue service             │
  clients           │                                          │
                    │  HTTP :8081 ── Houston UI                │
  Browser     ─────▶│              ── /health  /metrics        │
                    │              ── REST: account, rbac,     │
                    │                 oauth, onboarding        │
                    │                                          │
                    │  Storage ── SQLite (default) | Postgres  │
                    └──────────────────────────────────────────┘
```

- **Producers** `Send` messages to a **queue**.
- **Consumers** `Receive` a batch, do their work, then `Delete` (acknowledge).
- If a consumer never deletes, the message reappears after the **visibility
  timeout** — delivery is **at-least-once**.
- Messages that exhaust their **retry budget** or **retention period** are
  **evicted**: dropped, or moved to a **dead-letter queue**.

If you only read one page after this, read
[Core concepts](getting-started/core-concepts.md).
</content>
