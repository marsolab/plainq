import { api } from "@/lib/api-client";
import { isTelemetryUnavailableError, transformRateMetrics } from "@/lib/metrics";
import type { TopicMetricsOverview, TopicMetricsRow } from "@/lib/types";

/**
 * Pub/Sub telemetry.
 *
 * The server does collect topic series — publish rate, delivery rate, and the
 * published/delivered/subscription counters, per topic and system-wide — so
 * this module reads them rather than explaining their absence. It only mounts
 * the metrics API when telemetry is enabled, which is why `unavailable` is a
 * state of its own: a 404 or 503 means the readings are off, not zero, and an
 * operator who saw "0/s" would conclude the topic is idle when it is only
 * unmeasured.
 */
export type TopicMetricsState =
  | { status: "loading" }
  | { status: "ready"; overview: TopicMetricsOverview }
  /** Telemetry is switched off on this server — management still works. */
  | { status: "unavailable" }
  | { status: "error"; message: string };

export async function loadTopicMetrics(): Promise<TopicMetricsState> {
  try {
    return { status: "ready", overview: await api.metrics.topicOverview() };
  } catch (error) {
    if (isTelemetryUnavailableError(error)) return { status: "unavailable" };
    return {
      status: "error",
      message: error instanceof Error ? error.message : "Failed to load topic metrics",
    };
  }
}

/** The row the overview holds for one topic, or null when it has none yet. */
export function topicMetricsFor(
  state: TopicMetricsState,
  topicId: string,
): TopicMetricsRow | null {
  if (state.status !== "ready") return null;
  return state.overview.topicMetrics.find((row) => row.topicId === topicId) ?? null;
}

/**
 * One sample of the two series the plot draws, keyed as the chart wants them.
 * A key the sample did not carry is left off rather than set to 0.
 */
export type PublishDeliveryRow = { t: number } & Record<string, number>;

export type TopicRatesState =
  | { status: "loading" }
  | { status: "ready"; rows: PublishDeliveryRow[] }
  | { status: "unavailable" }
  | { status: "error"; message: string };

/**
 * A missing reading stays missing. `transformRateMetrics` only writes the keys
 * a sample actually carried, and a key it left out is left out here too, so
 * the line breaks — filling it with 0 would draw a dip the collector never
 * recorded.
 */
export async function loadTopicRates(
  topicId: string,
  range: string,
): Promise<TopicRatesState> {
  try {
    const response = await api.metrics.topicRates(topicId, range);
    const rows = transformRateMetrics(response.metrics ?? []).map((sample) => {
      const row: PublishDeliveryRow = { t: sample.timestamp };
      if (sample.publish !== undefined) row.publish = sample.publish;
      if (sample.delivery !== undefined) row.delivery = sample.delivery;
      return row;
    });

    return { status: "ready", rows };
  } catch (error) {
    if (isTelemetryUnavailableError(error)) return { status: "unavailable" };
    return {
      status: "error",
      message: error instanceof Error ? error.message : "Failed to load topic rates",
    };
  }
}

/**
 * Why the plot has nothing to draw. Every branch says something the operator
 * can act on; none of them claims the rate was zero.
 */
export function plotReason(state: TopicRatesState): string {
  switch (state.status) {
    case "unavailable":
      return "Telemetry is disabled on this server. Enable it with --telemetry and restart.";
    case "error":
      return state.message;
    case "ready":
      return "The collector recorded no publish or delivery samples in this window.";
    default:
      return "";
  }
}
