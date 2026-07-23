/**
 * Value formatting for the Houston instrument surface.
 *
 * Two rules from S00 drive everything here: absolute values come first and
 * relative ones are secondary, and a value is never rounded into a claim the
 * server did not make.
 */

const MONTHS = [
  "Jan", "Feb", "Mar", "Apr", "May", "Jun",
  "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];

function pad(n: number): string {
  return n.toString().padStart(2, "0");
}

function toDate(value: string | number | Date): Date | null {
  const d = value instanceof Date ? value : new Date(value);
  return Number.isNaN(d.getTime()) ? null : d;
}

/** `Jul 18, 09:14` — the compact absolute form used in table cells. */
export function formatDateShort(value: string | number | Date): string {
  const d = toDate(value);
  if (!d) return "—";
  return `${MONTHS[d.getUTCMonth()]} ${d.getUTCDate()}, ${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())}`;
}

/** `Jul 18, 2026 09:14:02 UTC` — the full absolute form used in detail views. */
export function formatDateFull(value: string | number | Date): string {
  const d = toDate(value);
  if (!d) return "—";
  return (
    `${MONTHS[d.getUTCMonth()]} ${d.getUTCDate()}, ${d.getUTCFullYear()} ` +
    `${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())}:${pad(d.getUTCSeconds())} UTC`
  );
}

/** `14:32:07 UTC` — the freshness stamp in the top bar. */
export function formatClock(value: string | number | Date): string {
  const d = toDate(value);
  if (!d) return "—";
  return `${pad(d.getUTCHours())}:${pad(d.getUTCMinutes())}:${pad(d.getUTCSeconds())} UTC`;
}

/** `3 days ago` — always secondary to an absolute timestamp, never alone. */
export function formatRelative(value: string | number | Date, now: Date = new Date()): string {
  const d = toDate(value);
  if (!d) return "";

  const seconds = Math.round((now.getTime() - d.getTime()) / 1000);
  const future = seconds < 0;
  const abs = Math.abs(seconds);

  const say = (n: number, unit: string) => {
    const label = `${n} ${unit}${n === 1 ? "" : "s"}`;
    return future ? `in ${label}` : `${label} ago`;
  };

  if (abs < 45) return future ? "in a moment" : "just now";
  if (abs < 5400) return say(Math.round(abs / 60), "minute");
  if (abs < 86400) return say(Math.round(abs / 3600), "hour");
  if (abs < 2592000) return say(Math.round(abs / 86400), "day");
  if (abs < 31536000) return say(Math.round(abs / 2592000), "month");
  return say(Math.round(abs / 31536000), "year");
}

/**
 * `30 s`, `7 d`, `604 800 s` — durations keep the unit the server speaks in
 * when it is already legible, and only step up when the number stops being so.
 */
export function formatDuration(seconds: number): string {
  if (!Number.isFinite(seconds)) return "—";
  if (seconds === 0) return "0 s";

  if (seconds % 86400 === 0 && seconds >= 86400) return `${seconds / 86400} d`;
  if (seconds % 3600 === 0 && seconds >= 3600) return `${seconds / 3600} h`;
  if (seconds % 60 === 0 && seconds >= 60) return `${seconds / 60} min`;
  return `${seconds} s`;
}

/** `604 800 s` — the exact value, thin-space grouped, for tooltips and detail rows. */
export function formatSecondsExact(seconds: number): string {
  if (!Number.isFinite(seconds)) return "—";
  return `${groupDigits(seconds)} s`;
}

/** Thin-space digit grouping so long values stay scannable in mono columns. */
export function groupDigits(value: number): string {
  if (!Number.isFinite(value)) return "—";
  return Math.trunc(value)
    .toString()
    .replace(/\B(?=(\d{3})+(?!\d))/g, " ");
}

/**
 * Byte sizes. The payload inspector must never mislabel bytes, so this is
 * strictly binary (KiB/MiB) and never says "KB" for 1024.
 */
export function formatBytes(bytes: number): string {
  if (!Number.isFinite(bytes) || bytes < 0) return "—";
  if (bytes < 1024) return `${bytes} B`;

  const units = ["KiB", "MiB", "GiB", "TiB"];
  let value = bytes / 1024;
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024;
    unit += 1;
  }
  return `${value.toFixed(value < 10 ? 1 : 0)} ${units[unit]}`;
}

/** `12.4/s` — a rate, with the denominator always visible. */
export function formatRate(perSecond: number): string {
  if (!Number.isFinite(perSecond)) return "—";
  if (perSecond === 0) return "0/s";
  if (perSecond < 0.01) return "<0.01/s";
  if (perSecond < 10) return `${perSecond.toFixed(2)}/s`;
  if (perSecond < 100) return `${perSecond.toFixed(1)}/s`;
  return `${groupDigits(perSecond)}/s`;
}

/** Counts in mono columns get the same thin-space grouping as other values. */
export function formatCount(value: number): string {
  return groupDigits(value);
}

/** `01K0Q6XN…R1D5CV` — only for places too narrow for the full ULID. */
export function truncateId(id: string, head = 8, tail = 6): string {
  if (id.length <= head + tail + 1) return id;
  return `${id.slice(0, head)}…${id.slice(-tail)}`;
}

/** Initial used by the square avatar tiles in the sidebar and top bar. */
export function initialOf(value: string | undefined | null): string {
  const trimmed = (value ?? "").trim();
  return trimmed ? trimmed[0]!.toUpperCase() : "?";
}
