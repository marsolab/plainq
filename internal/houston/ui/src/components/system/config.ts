/**
 * Startup configuration, read from the running instance.
 *
 * Every value on the System page comes from `GET /api/v1/system/config`, which
 * derives it from the configuration the process was started with. Two rules
 * outlive whatever the endpoint returns: a secret is named and marked redacted
 * rather than masked into a lookalike string, and a redacted fact is never
 * copyable — a copy action that emits `••••••` is worse than none.
 *
 * None of these facts carries a status tone. A green marker plus a word is how
 * the Health panel reports what it actually probed, one column over — spending
 * that same treatment on a value nothing verified would make a setting
 * indistinguishable from a measurement.
 */

import { formatDuration } from "@/lib/format";
import type { ConfigFactDTO, ConfigGroupDTO, ConfigResponseDTO } from "@/lib/types";

export interface ConfigFact {
  label: string;
  value: string;
  /** Withheld on purpose (redacted, or simply not exposed) — shown subdued. */
  withheld: boolean;
  note?: string;
}

export interface ConfigGroup {
  title: string;
  facts: ConfigFact[];
}

/** The `format` the server sets on a fact whose value is a count of seconds. */
const DURATION = "duration";

/**
 * Renders one fact for display.
 *
 * A duration arrives as a whole number of seconds so the browser formats it
 * with the same rules it uses everywhere else. A value that will not parse is
 * shown as it arrived rather than as a dash: the server said something, and
 * replacing it with "no value" would lose that.
 */
export function factValue(fact: ConfigFactDTO): string {
  const raw = fact.value ?? "";

  if (fact.format !== DURATION) return raw;

  const seconds = Number(raw);
  if (!Number.isFinite(seconds)) return raw;

  return formatDuration(seconds);
}

export function toConfigFact(fact: ConfigFactDTO): ConfigFact {
  return {
    label: fact.label,
    value: factValue(fact),
    withheld: fact.redacted === true,
    note: fact.note,
  };
}

export function toConfigGroup(group: ConfigGroupDTO): ConfigGroup {
  return {
    title: group.title,
    facts: (group.facts ?? []).map(toConfigFact),
  };
}

export function toConfigGroups(response: ConfigResponseDTO): ConfigGroup[] {
  return (response.groups ?? []).map(toConfigGroup);
}
