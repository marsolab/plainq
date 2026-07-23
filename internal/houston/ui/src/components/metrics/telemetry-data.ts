/**
 * The telemetry surface's read model, built strictly out of what the server
 * actually returns.
 *
 * Four real routes back this page, and their shapes decide what it may claim:
 *
 *   - `GET /metrics/overview`        process-current system counters and one
 *                                    row per queue the collector has seen.
 *   - `GET /metrics/topics/overview` the same for topics.
 *   - `GET /metrics/queue/{id}/rates` and `/inflight` — the only *history* the
 *     client can ask for, and only per queue.
 *   - `GET /metrics/topic/{id}/rates` — per-topic history.
 *
 * Two consequences are load-bearing and stated on screen rather than papered
 * over: the overview routes take no range (they are process-current, not
 * window-scoped), and only the per-entity routes return a series, so there is
 * no system-wide chart to draw. Summing the per-queue rows into a system total
 * would be a number the server never returned.
 */

import { api } from "@/lib/api-client";
import { isTelemetryUnavailableError, transformRateMetrics } from "@/lib/metrics";
import type {
  DashboardOverviewResponse,
  MetricDataPoint,
  Queue,
  Topic,
  TopicMetricsOverview,
} from "@/lib/types";
import type { ChartRow } from "./series-chart";

/**
 * The presets the server's `ParseTimeRange` understands. Anything outside this
 * list is silently coerced to one hour server-side, so the toolbar only offers
 * what the transport can honour — and there is no custom from/to control,
 * because the client exposes no route that accepts one.
 */
export const RANGE_KEYS = ["5m", "15m", "1h", "6h", "24h", "7d"] as const;
export type RangeKey = (typeof RANGE_KEYS)[number];

/* --------------------------------------------------------------- read model */

/**
 * System counters the overview handler genuinely populates. It leaves
 * `queuesExist` and the `total*` counters at their zero values, so they are
 * deliberately absent here: a hard 0 that means "not reported" must never be
 * rendered as a reading.
 */
export interface SystemCounters {
  sendRate: number;
  receiveRate: number;
  deleteRate: number;
  inFlight: number;
}

export type QueueActivity = "active" | "in-flight" | "idle";

export interface QueueHealthRow {
  queueId: string;
  /** The overview omits names; resolved against the queue list where possible. */
  queueName: string | null;
  inFlight: number;
  sendRate: number;
  receiveRate: number;
  deleteRate: number;
  messagesSent: number;
  messagesReceived: number;
  messagesDeleted: number;
  emptyReceives: number;
  activity: QueueActivity;
}

export interface TopicHealthRow {
  topicId: string;
  topicName: string | null;
  publishRate: number;
  deliveryRate: number;
  /** Counters since process start. Never a lifetime total. */
  published: number;
  deliveries: number;
  /** `null` — the transport does not report it. Reads "Unknown", never 0. */
  subscriptions: number | null;
  updatedAt: number;
}

export interface TelemetrySnapshot {
  capturedAt: number;
  counters: SystemCounters;
  queues: QueueHealthRow[];
  topics: TopicHealthRow[];
  /** True once the topic overview answered; false when only queues did. */
  topicsReporting: boolean;
}

/* ------------------------------------------------------------ normalisation */

function num(source: Record<string, unknown>, key: string): number {
  const value = source[key];
  return typeof value === "number" && Number.isFinite(value) ? value : 0;
}

function text(source: Record<string, unknown>, key: string): string {
  const value = source[key];
  return typeof value === "string" ? value : "";
}

function activityOf(row: {
  sendRate: number;
  receiveRate: number;
  deleteRate: number;
  inFlight: number;
}): QueueActivity {
  if (row.sendRate > 0 || row.receiveRate > 0 || row.deleteRate > 0) return "active";
  if (row.inFlight > 0) return "in-flight";
  return "idle";
}

export function readSystemCounters(overview: DashboardOverviewResponse): SystemCounters {
  const system = (overview.systemMetrics ?? {}) as Record<string, unknown>;

  return {
    sendRate: num(system, "sendRate"),
    receiveRate: num(system, "receiveRate"),
    deleteRate: num(system, "deleteRate"),
    inFlight: num(system, "totalInFlight"),
  };
}

export function readQueueRows(
  overview: DashboardOverviewResponse,
  names: Map<string, string>,
): QueueHealthRow[] {
  return (overview.queueMetrics ?? []).map((entry) => {
    const source = entry as Record<string, unknown>;
    const queueId = text(source, "queueId");
    const measured = {
      inFlight: num(source, "inFlight"),
      sendRate: num(source, "sendRate"),
      receiveRate: num(source, "receiveRate"),
      deleteRate: num(source, "deleteRate"),
    };

    return {
      queueId,
      // The handler leaves `queueName` unset, so the managed queue list is the
      // only place a human-readable name exists. A queue the collector has seen
      // but the list does not return keeps its ID rather than inventing one.
      queueName: text(source, "queueName") || names.get(queueId) || null,
      ...measured,
      messagesSent: num(source, "messagesSent"),
      messagesReceived: num(source, "messagesReceived"),
      messagesDeleted: num(source, "messagesDeleted"),
      emptyReceives: num(source, "emptyReceives"),
      activity: activityOf(measured),
    };
  });
}

export function readTopicRows(
  overview: TopicMetricsOverview,
  names: Map<string, string>,
): TopicHealthRow[] {
  return (overview.topicMetrics ?? []).map((row) => ({
    topicId: row.topicId,
    topicName: names.get(row.topicId) ?? null,
    publishRate: row.publishRate,
    deliveryRate: row.deliveryRate,
    published: row.messagesPublished,
    deliveries: row.deliveries,
    subscriptions: row.subscriptionsCurrent ?? null,
    updatedAt: row.updatedAt,
  }));
}

/* ------------------------------------------------------------------ loading */

export type TelemetryOverviewApi = Pick<typeof api.metrics, "overview" | "topicOverview">;

export interface TelemetryDirectory {
  queues: Map<string, string>;
  topics: Map<string, string>;
}

export type TelemetryLoadState =
  | { status: "loaded"; snapshot: TelemetrySnapshot }
  /** Telemetry storage is off. Queue and Pub/Sub management are unaffected. */
  | { status: "unavailable" }
  | { status: "error"; message: string };

/**
 * One read of both overview routes. The topic route failing does not fail the
 * page — topic telemetry is a separate collector, and losing it should cost the
 * Pub/Sub table, not the queue counters above it.
 */
export async function loadTelemetrySnapshot(
  metricsApi: TelemetryOverviewApi,
  directory: TelemetryDirectory,
): Promise<TelemetryLoadState> {
  let overview: DashboardOverviewResponse;

  try {
    overview = await metricsApi.overview();
  } catch (error) {
    if (isTelemetryUnavailableError(error)) return { status: "unavailable" };

    return {
      status: "error",
      message: error instanceof Error ? error.message : "Failed to load metrics",
    };
  }

  let topics: TopicHealthRow[] = [];
  let topicsReporting = false;

  try {
    topics = readTopicRows(await metricsApi.topicOverview(), directory.topics);
    topicsReporting = true;
  } catch {
    // Left as "not reporting" — the Pub/Sub table says so rather than
    // rendering an empty table that would read as "no topics".
  }

  return {
    status: "loaded",
    snapshot: {
      capturedAt: Date.now(),
      counters: readSystemCounters(overview),
      queues: readQueueRows(overview, directory.queues),
      topics,
      topicsReporting,
    },
  };
}

/**
 * Names for the IDs the metrics routes return. Best effort by design: a
 * directory lookup that fails costs readability, never the numbers.
 */
export async function loadTelemetryDirectory(): Promise<TelemetryDirectory> {
  const [queues, topics] = await Promise.all([
    api.queues
      .list({ limit: 100 })
      .then((response) => response.queues ?? [])
      .catch((): Queue[] => []),
    api.topics
      .list()
      .then((response) => response.topics ?? [])
      .catch((): Topic[] => []),
  ]);

  return {
    queues: new Map(queues.map((queue) => [queue.queueId, queue.queueName])),
    topics: new Map(topics.map((topic) => [topic.topicId, topic.topicName])),
  };
}

/* ------------------------------------------------------------------- series */

export type SeriesLoadState =
  | { status: "loaded"; rows: ChartRow[] }
  | { status: "unavailable" }
  | { status: "error"; message: string };

function toSeriesState(load: () => Promise<ChartRow[]>): Promise<SeriesLoadState> {
  return load().then(
    (rows) => ({ status: "loaded", rows }) as SeriesLoadState,
    (error: unknown) => {
      if (isTelemetryUnavailableError(error)) return { status: "unavailable" } as SeriesLoadState;

      return {
        status: "error",
        message: error instanceof Error ? error.message : "Failed to load samples",
      } as SeriesLoadState;
    },
  );
}

/**
 * `transformRateMetrics` keys rows by the metric names the server sends
 * (`send`, `receive`, `delete`, `publish`, `delivery`) and stamps each with
 * `timestamp`; the chart primitives want `t`. Renaming here keeps that shape
 * detail out of every panel.
 */
function toChartRows(rows: ReturnType<typeof transformRateMetrics>): ChartRow[] {
  return rows.map(({ timestamp, ...rest }) => ({ t: timestamp, ...rest }) as ChartRow);
}

export type QueueSeriesApi = Pick<typeof api.metrics, "queueRates">;
export type TopicSeriesApi = Pick<typeof api.metrics, "topicRates">;
export type InFlightApi = Pick<typeof api.metrics, "queueInFlight">;

export function loadQueueRateSeries(
  metricsApi: QueueSeriesApi,
  queueId: string,
  range: RangeKey,
): Promise<SeriesLoadState> {
  return toSeriesState(async () =>
    toChartRows(transformRateMetrics((await metricsApi.queueRates(queueId, range)).metrics ?? [])),
  );
}

export function loadTopicRateSeries(
  metricsApi: TopicSeriesApi,
  topicId: string,
  range: RangeKey,
): Promise<SeriesLoadState> {
  return toSeriesState(async () =>
    toChartRows(transformRateMetrics((await metricsApi.topicRates(topicId, range)).metrics ?? [])),
  );
}

/** In-flight is a count of messages, so its samples carry no rate denominator. */
export function loadInFlightSeries(
  metricsApi: InFlightApi,
  queueId: string,
  range: RangeKey,
): Promise<SeriesLoadState> {
  return toSeriesState(async () => {
    const response = await metricsApi.queueInFlight(queueId, range);
    return (response.history ?? []).map((point: MetricDataPoint) => ({
      t: point.timestamp,
      inflight: point.value,
    }));
  });
}
