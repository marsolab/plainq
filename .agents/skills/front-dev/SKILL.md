---
name: front-dev
description: Build production-ready web applications using Bun, Astro, React, Tailwind CSS v4, and Shadcn UI. Use this skill when (1) creating new frontend projects or components, (2) building landing pages, dashboards, or web apps, (3) setting up Astro with islands architecture, (4) implementing React/Preact components with proper patterns, (5) styling with Tailwind v4 and Shadcn UI, (6) optimizing frontend performance and accessibility, (7) implementing state management, (8) setting up testing strategies, (9) configuring build tooling with Bun, (10) implementing security best practices, (11) setting up forms with validation, (12) building data tables and complex UI patterns. Covers architecture, performance, accessibility, testing, security, and developer experience.
version: 1.0.0
---

# Web Frontend Stack

Build modern, performant web applications using **Bun + Astro + React/Preact +
Tailwind v4 + Shadcn UI**.

## Core Philosophy

**Astro is always the foundation.** We don't choose between Astro and React — we
use them together:

- **Astro** handles routing, pages, layouts, and static content (zero JS by
  default)
- **React/Preact** powers interactive islands within Astro pages
- **Tailwind v4** provides utility-first styling with CSS variables
- **Shadcn UI** gives us accessible, customizable React components
- **Bun** accelerates development with fast installs, builds, and testing

```text
┌─────────────────────────────────────────────────────────────────┐
│                         Astro (Foundation)                       │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────┐  │
│  │ Static Page  │  │ Static Page  │  │    Dynamic Page      │  │
│  │   (0 JS)     │  │   (0 JS)     │  │  ┌────────────────┐  │  │
│  │              │  │              │  │  │  React Island  │  │  │
│  │  Hero.astro  │  │ About.astro  │  │  │  client:load   │  │  │
│  │  Footer.astro│  │              │  │  └────────────────┘  │  │
│  │              │  │              │  │  ┌────────────────┐  │  │
│  │              │  │              │  │  │ Preact Island  │  │  │
│  │              │  │              │  │  │ client:visible │  │  │
│  └──────────────┘  └──────────────┘  │  └────────────────┘  │  │
│                                       └──────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
```

## Master Decision Tree

### 1. Project Type → Astro Configuration

```bash
What are you building? (Astro is always the base)
│
├── Content-heavy site (blog, docs, marketing)?
│   └── Astro static (default) + Tailwind
│       ├── Pure Astro components for static content
│       ├── Content Collections + Zod for structured content
│       ├── Add React islands only for interactive widgets
│       └── Preact islands for bundle-critical pages
│
├── Web application (dashboard, SaaS, admin)?
│   └── Astro + React islands + Shadcn UI
│       ├── SEO critical? → Astro SSR adapter
│       ├── Heavy interactivity? → More React islands
│       ├── Real-time data? → Preact Signals in islands
│       └── Forms-heavy? → Shadcn Form + react-hook-form
│
├── E-commerce?
│   └── Astro + React islands for interactivity
│       ├── Product pages → Static Astro (fast LCP)
│       ├── Cart/checkout → React island (client:load)
│       ├── Product filtering → Preact Signals (fine-grained)
│       └── Search → React island (client:idle)
│
├── Landing page / Marketing?
│   └── Astro static + minimal islands
│       ├── Hero, features, testimonials → Pure Astro
│       ├── Contact form → React island (client:visible)
│       ├── Newsletter signup → Preact island (~3KB)
│       └── Analytics → client:idle or Partytown
│
├── Documentation site?
│   └── Astro + Content Collections + MDX
│       ├── Markdown/MDX for content
│       ├── Zod schemas for frontmatter validation
│       ├── Interactive code examples → React islands
│       └── Search → React island (client:idle)
│
└── Internal tool / Dashboard?
    └── Astro + React islands + Shadcn UI (heavy)
        ├── Data tables → Shadcn DataTable + TanStack Table
        ├── Forms → Shadcn Form + react-hook-form + Zod
        ├── Command palette → Shadcn Command (cmdk)
        └── Charts → Recharts or Chart.js in React islands
```

### 2. Island Framework Decision: React vs Preact

```bash
For each interactive island, choose framework:
│
├── Need Shadcn UI components?
│   └── React (Shadcn built for React)
│
├── Complex state management needed?
│   └── React (React Query, Zustand ecosystem)
│
├── Bundle size critical (<50KB total page JS)?
│   └── Preact (~3KB vs React ~40KB)
│       └── Savings: ~37KB gzipped per island
│
├── High-frequency updates (live data, animations)?
│   └── Preact Signals (fine-grained reactivity)
│       └── Bypasses VDOM diffing for targeted DOM updates
│
├── Simple widget (counter, toggle, form)?
│   └── Preact (smaller, sufficient for simple UI)
│
├── Using React-specific libraries?
│   ├── Has Preact alternative? → Preact
│   │   ├── React Router → preact-router / wouter
│   │   ├── Redux → @preact/signals
│   │   └── React Query → Works via preact/compat
│   └── No alternative? → React
│
├── Web Component output needed?
│   └── Preact (smaller, easier to wrap)
│       └── Use preact-custom-element
│
└── Default for general islands?
    ├── With Shadcn → React
    └── Without Shadcn → Preact (smaller bundle)
```

### 3. Mixing React and Preact Islands

```html
Can I use both React and Preact in the same Astro project?

YES! Astro supports multiple frameworks simultaneously.
│
├── Add both integrations:
│   bunx astro add react
│   bunx astro add preact
│
├── File convention (recommended):
│   ├── *.tsx → React components
│   └── *.preact.tsx → Preact components
│
├── Or use explicit client directives:
│   <ReactComponent client:load />
│   <PreactComponent client:visible />
│
├── Common pattern:
│   ├── Complex UI (forms, tables) → React + Shadcn
│   ├── Simple widgets → Preact (smaller)
│   ├── Performance-critical → Preact Signals
│   └── Static content → Astro (no island)
│
└── Caution:
    └── Each framework adds to bundle
        └── Don't add both if only using one
```

### 4. Runtime Decision: Bun vs Node

```go
Use Bun when:
├── Greenfield project (no legacy constraints)
├── Serverless/CLI (fast cold starts ~μs)
├── Dev speed priority (10x faster installs)
├── TypeScript-first (native support, no tsc)
├── All-in-one tooling (bundler, test runner, package manager)
└── HTTP server (2x faster than Node for simple cases)

Stay with Node when:
├── Critical native addon dependencies (node-gyp)
├── Production stability paramount (Bun still maturing)
├── Team unfamiliar with Bun
├── Specific Node-only APIs required
└── Monitoring tools require Node (some APMs)

Hybrid approach (recommended for new projects):
├── Bun for dev/build → Fast DX
├── Test with both runtimes in CI
└── Deploy with Bun or Node based on stability needs
```

### 5. State Management Decision

```typescript
What kind of state? (In React/Preact islands)
│
├── UI State (form inputs, toggles, modals)
│   └── useState / useReducer (local)
│       └── Keep close to where used
│
├── Derived State (computed from other state)
│   └── useMemo / computed signals
│       └── DON'T duplicate in state
│
├── Server State (API data)
│   ├── Simple one-time fetch? → useFetch hook
│   ├── Caching/revalidation? → React Query / SWR
│   └── Preact? → React Query via compat or signals
│
├── Global UI State (theme, sidebar, toast)
│   ├── Few consumers (<5)? → React Context
│   ├── Many consumers? → Zustand (no provider)
│   └── Preact? → @preact/signals (best choice)
│
├── Form State
│   ├── Simple form (<5 fields)? → useState
│   └── Complex validation? → react-hook-form + Zod
│
├── URL State (filters, pagination)
│   └── Astro: Use query params, read in frontmatter
│   └── Islands: nuqs / URLSearchParams
│
└── Cross-island State
    ├── Astro nanostores (works with any framework)
    ├── Custom events (DOM-based)
    └── URL params (most portable)
```

### 6. Hydration Strategy Decision (Astro Islands)

```text
When should island hydrate?
│
├── User interaction required immediately?
│   └── client:load
│       └── Examples: navbar dropdown, auth UI, critical CTAs
│
├── Enhances but not critical?
│   └── client:idle
│       └── Examples: analytics, chat widget, tooltips
│
├── Below the fold / not immediately visible?
│   └── client:visible
│       └── Examples: comments, related posts, footer widgets
│
├── Only on certain devices?
│   └── client:media="(min-width: 768px)"
│       └── Examples: desktop-only features
│
├── Uses browser-only APIs (no SSR possible)?
│   └── client:only="react"
│       └── Examples: WebGL, canvas, localStorage on init
│
└── Static content, no JS needed?
    └── No directive (default)
        └── Renders to HTML, ships zero JS
```

### 7. Testing Strategy Decision

```text
What to test?
│
├── Business logic (utils, hooks)?
│   └── Unit tests: bun test / Vitest
│
├── Component behavior (React/Preact)?
│   └── Component tests: Testing Library
│       ├── @testing-library/react or /preact
│       └── Mock API with MSW
│
├── Astro pages integration?
│   └── Build + serve + test with Playwright
│
├── User flows (critical paths)?
│   └── E2E tests: Playwright
│
└── Accessibility?
    ├── Automated: jest-axe, axe-core
    └── Manual: Screen reader, keyboard
```

## Quick Start

### New Astro + React + Tailwind + Shadcn Project

```bash
# Initialize Astro project
bun create astro@latest my-project
cd my-project

# Add React integration (for islands)
bunx astro add react

# Add Tailwind CSS v4
bunx astro add tailwind

# Initialize Shadcn UI
bunx shadcn@latest init

# Add commonly used Shadcn components
bunx shadcn@latest add button card form input dialog

# Start dev server
bun run dev
```

### Astro Page with React Islands

```astro
---
// src/pages/index.astro
import Layout from '../layouts/Layout.astro';
import Hero from '../components/Hero.astro';           // Static
import Counter from '../components/Counter';           // React
import Comments from '../components/Comments';         // React
---

<Layout title="Home">
  <Hero />                              <!-- Static: Zero JS -->
  <Counter client:load />               <!-- Immediate hydration -->
  <Comments client:visible />           <!-- Hydrate when visible -->
</Layout>
```

## Architecture Principles

1. **Astro-First** — Every page starts static, add islands only when needed
1. **Mobile-First** — Base styles for mobile, responsive variants for larger
1. **Accessibility-First** — Semantic HTML, keyboard nav, ARIA when needed
1. **Performance Budget** — <100KB JS per page, LCP <2.5s, CLS <0.1

## Hydration Quick Reference

| Directive | When | Use Case |
|-----------|------|----------|
| (none) | Never | Static content |
| `client:load` | Page load | Critical interactivity |
| `client:idle` | Browser idle | Non-critical features |
| `client:visible` | In viewport | Below-fold content |
| `client:media` | Media match | Responsive features |
| `client:only` | Page load | No SSR (browser APIs) |

## Reference Files

| Topic | Reference |
|-------|-----------|
| Bun runtime, scaling, security | [references/bun.md](references/bun.md) |
| Astro architecture, content, SSR | [references/astro.md](references/astro.md) |
| React patterns, hooks, performance | [references/react.md](references/react.md) |
| Preact, signals, migration | [references/preact.md](references/preact.md) |
| Tailwind v4, theming, queries | [references/tailwind.md](references/tailwind.md) |
| Shadcn UI, forms, tables | [references/shadcn.md](references/shadcn.md) |
| Testing strategies | [references/testing.md](references/testing.md) |
| Security best practices | [references/security.md](references/security.md) |
| Accessibility guide | [references/accessibility.md](references/accessibility.md) |

## Common Pitfalls

| Area | Pitfall | Solution |
|------|---------|----------|
| Astro | Making everything an island | Only `client:*` for interactivity |
| Astro | `client:load` everywhere | Use `idle`/`visible` for non-critical |
| React | React libs for simple widgets | Use Preact for small islands |
| Preact | Mixing signals with useState | Signals outside components |
| Tailwind | Hardcoded colors | Use semantic tokens |
| Shadcn | Not customizing | Own the code, modify freely |
