# Houston (admin UI)

Houston is PlainQ's bundled web dashboard — an Astro + React + TypeScript app
served by the same binary on the HTTP listener. There's nothing extra to deploy:
when you run `plainq serve`, Houston is already there.

| Property        | Value                                  |
| --------------- | -------------------------------------- |
| URL             | `http://localhost:8081` (the `--http.addr` listener) |
| Tech            | Astro + React + TypeScript, embedded into the Go binary |
| Build           | `make houston` → `internal/houston/ui/dist` (embedded at compile time) |

## What it does

- **Queues** — browse queues, inspect settings, and view per-queue metrics.
- **Accounts** — manage users and the onboarding flow.
- **RBAC** — create roles, assign them, and set per-queue permissions.
- **OAuth** — configure external identity providers and organizations/teams.
- **Metrics** — charts and rate/in-flight views backed by the
  [telemetry subsystem](observability.md#telemetry--houston-dashboards).

## First run: onboarding

On a fresh server there are no users yet. The first time you open Houston it
enters **onboarding mode** and walks you through creating the initial **admin**
account.

```
open http://localhost:8081
        │
        ▼
  onboarding flow ── create the first admin (email + password)
        │
        ▼
  signed in as admin ── full dashboard
```

Under the hood:

- Onboarding status is checked at `/onboarding/status`.
- Completing onboarding (`/onboarding/complete`) creates the admin, marks it
  verified, assigns the `admin` role, and returns a session.
- Once an admin exists, onboarding is closed — the endpoints stop creating new
  admins.

Only **one** admin is created via onboarding; manage additional users and roles
through the RBAC screens afterward. For the full account/role model see
[Authentication & RBAC](../authentication-rbac.md).

## Serving and routing

Houston is a single-page app served from an embedded filesystem with SPA
fallback: unknown paths resolve to the app's `index.html` so client-side routing
works on refresh and deep links. The API routes it calls (account, RBAC, OAuth,
onboarding, metrics) are served by the same HTTP listener, with **CORS** enabled
for those routes (toggle with `--cors`).

## Building Houston

`make build` builds Houston automatically. To rebuild just the UI:

```shell
make houston    # bun install --frozen-lockfile && bun run build
```

The output in `internal/houston/ui/dist` is embedded into the binary at compile
time, so you must rebuild the Go binary afterward to pick up UI changes. If you
build the server without Houston (see
[Installation](../getting-started/installation.md#building-without-houston)), the
API and CLI still work — only the dashboard is absent.

## Production notes

- Put Houston behind a **TLS-terminating reverse proxy** — it's a browser app
  handling credentials. See [Deployment](deployment.md#network-exposure).
- Houston and the queue gRPC API are separate listeners. Exposing Houston
  (`:8081`) does **not** expose the privileged gRPC port (`:8080`); keep the
  latter private.

## Next steps

- [Authentication & RBAC](../authentication-rbac.md) — the model behind the
  account and RBAC screens.
- [Observability](observability.md) — the metrics behind Houston's charts.
- [Deployment](deployment.md) — fronting Houston with a proxy.
</content>
