# Houston design system

A quiet message-traffic instrument. Square geometry, outlined panels, colour
reserved for meaning. Source of truth: `PlainQ Houston Design Master`, screen
S00 (tokens) and S06 (shell).

## Rules that decide arguments

1. **0 radius, everywhere.** Switches and avatars included. The `--radius-*`
   tokens all resolve to `0`, so a stray `rounded-md` is inert rather than
   wrong — but don't write one.
2. **Focus is one thing:** 2px black outline, 2px offset. Set globally on
   `:focus-visible`; never restyle it per component.
3. **Colour never carries meaning alone.** Every status pairs a square marker
   with a word. Use `<Status tone>` rather than a coloured dot or coloured text.
4. **Absolute values first, relative second.** `Jul 18, 09:14` on top,
   `3 days ago` underneath. Use `<Timestamp>`; never ship a bare "3 days ago".
5. **Mono for machine values.** IDs, counts, durations, rates, timestamps —
   `font-mono` + `tabular`. Inter for prose and labels.
6. **Never invent a number.** No totals the transport doesn't return, no
   rounded rates presented as exact. Cursor pagination has no page count.
7. **Permission-blocked actions stay visible** with the reason attached
   (`<Button blockedReason>`). Irrelevant *sections* are hidden entirely — a
   restricted operator never sees Access at all.
8. **Failure keeps the last good data**, labelled `STALE`, with a retry. Don't
   blank a table because a refresh failed.
9. **Never `confirm()`.** Inline alert = local validation. Banner = page-level
   impact. Toast = a background action that finished. Dialog = explicit
   confirmation.

## Tokens

Defined in `src/styles/globals.css` under `@theme`. Use the Tailwind names, not
raw hex.

| Purpose        | Token                                             |
| -------------- | ------------------------------------------------- |
| App background | `background` `#fafafa`                            |
| Panel surface  | `surface` `#ffffff`                               |
| Muted fill     | `muted` `#f5f5f5`                                 |
| Hairline       | `border` `#e5e5e5`                                |
| Text           | `foreground` `#0a0a0a`, `strong` `#404040`, `muted-foreground` `#737373`, `subtle` `#a3a3a3` |
| Action         | `primary` `#0a0a0a` / `primary-hover` `#262626`   |
| Destructive    | `destructive` + `-border` `-surface` `-text`      |
| Warning        | `warning` + `-surface` `-text`                    |
| Success        | `success`                                         |

Message lifecycle — the only hues allowed to mean something, each always
labelled: `send` (blue, send/publish/in-flight), `receive` (green,
receive/delivery), `acknowledge` (purple, acknowledge/delete), `retry` (amber,
retry/warning).

## Type scale

| Role          | Spec                                        |
| ------------- | ------------------------------------------- |
| Page title    | Inter 24/600, `tracking-[-0.02em]`          |
| Section title | Inter 13/600                                |
| Body          | Inter 13/400                                |
| Label         | Inter 12/500, `text-strong`                 |
| Value         | JetBrains Mono 13/400, tabular              |
| Micro         | JetBrains Mono 11/400, `text-muted-foreground` |
| Caption       | JetBrains Mono 10, `tracking-[0.1em]`, uppercase — use the `caption` utility |

## Metrics

- Buttons and inputs: **32px** (`h-8`); compact variants 28px (`h-7`).
- Sidebar 224px (`w-56`); sidebar and top bar headers both **56px** (`h-14`).
- Page padding 24px (`p-6`). Table header row 36px (`h-9`), cells `px-4 py-3`.

## Components

Foundation lives in `src/components/ui`:

- `panel.tsx` — `Panel`, `PanelHeader` (mono caption bar), `PanelTitleBar`,
  `PanelBody`, `PanelFooter`, `DangerZone`. **The only container.** There is no
  elevated card; depth comes from borders, never shadow.
- `status.tsx` — `Status`, `StatusMarker`, `StatusTone`.
- `value.tsx` — `MonoValue`, `Micro`, `Timestamp`, `CopyableId`, `Field`,
  `DefinitionRow`.
- `feedback.tsx` — `InlineAlert`, `Banner`. Toasts come from `sonner`.
- `page-header.tsx` — `PageHeader`, `SectionHeader`.
- `empty-state.tsx` — `EmptyState`, `LifecycleLegend`.
- `badge.tsx` — `Badge`, `ScopeBadge` (EXP / STALE), `AttemptsBadge`.
- `table.tsx` — adds `TableIdentityCell` (name over mono ID) and a `numeric`
  prop on `TableHead`/`TableCell` for right-aligned tabular columns.
- `button.tsx` — variants `default | outline | ghost | destructive |
  destructive-outline | link`; props `loading` (keeps label and width) and
  `blockedReason`.

Formatting helpers live in `src/lib/format.ts` — always format through them so
units stay consistent. `formatBytes` is strictly binary (KiB/MiB); the payload
inspector must never mislabel bytes.

## Shell

`AppShell` owns the frame: 224px sidebar (wordmark, nav, service health +
version, account row) and the 56px top bar (page title, freshness stamp,
refresh, account menu). Nav is Queues / Pub·Sub `EXP` / Metrics / Access /
System. Pass `canManageAccess={false}` to hide Access, `authEnabled={false}` to
drop every account affordance, and `banner` for page-level notices.
