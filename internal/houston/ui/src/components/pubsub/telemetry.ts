import { api } from "@/lib/api-client";
import { isTelemetryUnavailableError } from "@/lib/metrics";
import type {
  TopicMetricsOverview,
  TopicMetricsRow,
  TopicSeriesResponse,
  TopicSubscriptionsResponse,
} from "@/lib/types";

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

export type TopicTelemetryRange = "5m" | "15m" | "1h" | "6h" | "24h";

export type Ranged<T> = { data: T; range: TopicTelemetryRange };

/**
 * Every retained payload carries the range that produced it. That provenance
 * is what prevents a slow or failed 24h request from relabelling a 1h graph.
 */
export type SeriesLoad<T> =
  | { status: "loading"; lastGood?: Ranged<T> }
  | ({ status: "ready" } & Ranged<T>)
  | ({ status: "refreshing" } & Ranged<T>)
  | { status: "unavailable"; lastGood?: Ranged<T> }
  | { status: "error"; message: string; lastGood?: Ranged<T> };

export interface TopicTelemetryLoads {
  rates: SeriesLoad<TopicSeriesResponse>;
  subscriptions: SeriesLoad<TopicSubscriptionsResponse>;
}

export interface TopicTelemetryLastGood {
  rates?: Ranged<TopicSeriesResponse>;
  subscriptions?: Ranged<TopicSubscriptionsResponse>;
}

export interface TopicTelemetryRequests {
  rates: Promise<SeriesLoad<TopicSeriesResponse>>;
  subscriptions: Promise<SeriesLoad<TopicSubscriptionsResponse>>;
}

export type TopicTelemetryApi = Pick<
  typeof api.metrics,
  "topicRates" | "topicSubscriptions"
>;

export function lastGoodFor<T>(
  load: SeriesLoad<T>,
  range: TopicTelemetryRange,
): Ranged<T> | undefined {
  const retained =
    load.status === "ready" || load.status === "refreshing"
      ? { data: load.data, range: load.range }
      : load.lastGood;

  return retained?.range === range ? retained : undefined;
}

function beginSeriesLoad<T>(
  load: SeriesLoad<T>,
  range: TopicTelemetryRange,
): SeriesLoad<T> {
  const retained = lastGoodFor(load, range);
  return retained
    ? { status: "refreshing", ...retained }
    : { status: "loading" };
}

export function beginTopicTelemetryLoad(
  current: TopicTelemetryLoads,
  range: TopicTelemetryRange,
): TopicTelemetryLoads {
  return {
    rates: beginSeriesLoad(current.rates, range),
    subscriptions: beginSeriesLoad(current.subscriptions, range),
  };
}

async function settleSeries<T>(
  request: () => Promise<T>,
  range: TopicTelemetryRange,
  lastGood?: Ranged<T>,
): Promise<SeriesLoad<T>> {
  const retained = lastGood?.range === range ? lastGood : undefined;

  try {
    return { status: "ready", data: await request(), range };
  } catch (error) {
    if (isTelemetryUnavailableError(error)) {
      return retained
        ? { status: "unavailable", lastGood: retained }
        : { status: "unavailable" };
    }

    const message =
      error instanceof Error ? error.message : "Failed to load topic telemetry";
    return retained
      ? { status: "error", message, lastGood: retained }
      : { status: "error", message };
  }
}

/**
 * The two routes settle independently. A subscription-store failure does not
 * throw away delivery history, and vice versa.
 */
export function loadTopicTelemetry(
  metricsApi: TopicTelemetryApi,
  topicId: string,
  range: TopicTelemetryRange,
  lastGood: TopicTelemetryLastGood = {},
): TopicTelemetryRequests {
  return {
    rates: settleSeries(
      () => metricsApi.topicRates(topicId, range),
      range,
      lastGood.rates,
    ),
    subscriptions: settleSeries(
      () => metricsApi.topicSubscriptions(topicId, range),
      range,
      lastGood.subscriptions,
    ),
  };
}
