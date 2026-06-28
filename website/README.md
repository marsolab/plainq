# PlainQ website

The marketing landing page and documentation site for
[PlainQ](https://github.com/marsolab/plainq), built with **Astro + Tailwind
CSS v4 + React + Shadcn UI**, with documentation powered by **Starlight** and
deployed to **Cloudflare Workers** (static assets).

This is the public-facing site. It is separate from **Houston**, the admin UI
embedded in the `plainq` server binary (`internal/houston`).

## Stack

| Concern        | Choice                                                    |
| -------------- | -------------------------------------------------------- |
| Framework      | [Astro](https://astro.build) (static output)            |
| Styling        | [Tailwind CSS v4](https://tailwindcss.com) (`@theme`)    |
| Interactivity  | [React](https://react.dev) islands                       |
| Components     | [Shadcn UI](https://ui.shadcn.com) (new-york, neutral)   |
| Docs           | [Starlight](https://starlight.astro.build), mounted at `/docs` |
| Dev feedback   | [Agentation](https://www.agentation.com) (dev-only)      |
| Hosting        | Cloudflare Workers static assets (`wrangler.jsonc`)      |
| Toolchain      | [Bun](https://bun.sh)                                     |

The design mirrors the Houston admin UI: a minimal, monochrome neutral palette
with Inter + JetBrains Mono. Light is the default theme, with a dark-mode
toggle (persisted to `localStorage`).

## Develop

```shell
bun install
bun run dev        # http://localhost:4321
```

The [Agentation](https://www.agentation.com) widget loads **only** in the dev
server (`import.meta.env.DEV`). Click its toolbar (bottom-right) to annotate
any element on the page and copy structured context for an AI coding agent. It
is tree-shaken out of the production build entirely.

## Build & check

```shell
bun run build      # static output → ./dist
bun run preview    # serve ./dist locally
bun run check      # astro type check
```

## Project layout

```
website/
├── astro.config.mjs        # Astro + React + Starlight + Tailwind
├── wrangler.jsonc          # Cloudflare Worker manifest (static assets)
├── components.json         # Shadcn UI config
├── public/                 # static assets (favicon)
└── src/
    ├── assets/             # Starlight logos
    ├── components/         # Astro sections + React islands + ui/ (shadcn)
    ├── content/docs/docs/  # Starlight docs → served at /docs/**
    ├── layouts/            # base Layout (theme script, dev widget)
    ├── lib/                # cn() helper
    ├── pages/              # index.astro (landing page)
    └── styles/             # globals.css (theme) + starlight.css
```

Routing: `src/pages/index.astro` owns `/`; Starlight content under
`src/content/docs/docs/**` is served under `/docs/**`.

## Deploy (Cloudflare Workers)

The site is fully static and served by
[Workers Static Assets](https://developers.cloudflare.com/workers/static-assets/) —
no Worker script is required. The `wrangler.jsonc` manifest points at `./dist`
and serves the generated `404.html` for unmatched routes.

```shell
# Build the site and deploy in one step
bun run deploy

# …or run the steps individually
bun run build
bunx wrangler deploy

# Preview the production build on Cloudflare's local runtime
bun run cf-preview
```

Requires Wrangler ≥ 4.24.4 and a Cloudflare account (`wrangler login`). The
Worker is named `plainq-website`.

### Custom domain

`wrangler.jsonc` attaches the Worker to **`plainq.dev`** and **`www.plainq.dev`**
as [custom domains](https://developers.cloudflare.com/workers/configuration/routing/custom-domains/):

```jsonc
"routes": [
  { "pattern": "plainq.dev", "custom_domain": true },
  { "pattern": "www.plainq.dev", "custom_domain": true }
]
```

The `plainq.dev` zone must already exist on your Cloudflare account (it does).
On the first `wrangler deploy`, Cloudflare automatically creates the proxied
DNS records and provisions the edge TLS certificate — no manual DNS step is
needed. These patterns must match the `site` in `astro.config.mjs`.

To deploy from your machine:

```shell
cd website
bun install
wrangler login          # one-time, interactive OAuth
bun run deploy          # astro build + wrangler deploy
```
