import { formatDuration, formatSecondsExact } from "@/lib/format";

/**
 * Startup configuration — INTEGRATION-DEPENDENT.
 *
 * PlainQ exposes no sanitized configuration endpoint, so not one value below
 * is read from the running server. These rows describe the shape of a PlainQ
 * configuration; the System page says so above them and marks every panel
 * `NOT LIVE`, rather than letting them pass for live settings.
 *
 * None of these facts carries a status tone. A green marker plus a word is how
 * the Health panel reports what it actually probed, one column over — spending
 * that same treatment on a value nothing verified would make a fabrication
 * indistinguishable from a measurement.
 *
 * Two constraints survive whatever endpoint eventually backs this: secrets and
 * DSN passwords arrive already masked, and a masked value is never copyable —
 * a copy action that emits `••••••` is worse than no copy action.
 */

export interface ConfigFact {
  label: string;
  value: string;
  /** Withheld on purpose (redacted, or simply not exposed) — shown subdued. */
  withheld?: boolean;
}

export interface ConfigGroup {
  title: string;
  facts: ConfigFact[];
}

const MINUTE = 60;
const HOUR = 60 * MINUTE;
const DAY = 24 * HOUR;

export const STARTUP_CONFIG: ConfigGroup[] = [
  {
    title: "Storage",
    facts: [
      { label: "Driver", value: "postgres" },
      { label: "DSN", value: "postgres://plainq:••••••@db:5432/plainq" },
      { label: "Access mode", value: "read-write" },
      { label: "GC interval", value: formatSecondsExact(60) },
    ],
  },
  {
    title: "Authentication",
    facts: [
      { label: "Status", value: "enabled" },
      { label: "Registration", value: "enabled" },
      { label: "Access token TTL", value: formatDuration(15 * MINUTE) },
      { label: "Refresh token TTL", value: formatDuration(720 * HOUR) },
      { label: "Email verification", value: "required" },
      { label: "Signing secret", value: "never shown", withheld: true },
    ],
  },
  {
    title: "Telemetry",
    facts: [
      { label: "Status", value: "enabled" },
      { label: "Provider", value: "embedded" },
      { label: "Collection interval", value: formatSecondsExact(10) },
      { label: "Retention", value: formatDuration(30 * DAY) },
      { label: "Metrics endpoint", value: "/metrics" },
    ],
  },
  {
    title: "Network",
    facts: [
      { label: "HTTP listen", value: ":8080" },
      { label: "gRPC listen", value: ":9090" },
      {
        label: "Read / write timeout",
        value: `${formatSecondsExact(30)} / ${formatSecondsExact(30)}`,
      },
      { label: "CORS", value: "same-origin" },
      { label: "Health endpoint", value: "/healthz" },
      { label: "Profiler", value: "not exposed", withheld: true },
    ],
  },
  {
    title: "Logging",
    facts: [
      { label: "Level", value: "info" },
      { label: "Access log", value: "enabled" },
      { label: "Some values", value: "redacted / unavailable", withheld: true },
    ],
  },
];
