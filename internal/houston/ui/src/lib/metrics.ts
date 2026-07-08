import type { MetricsChartResponse } from "./types";

export interface RateChartRow {
  timestamp: number;
  send?: number;
  receive?: number;
  delete?: number;
  publish?: number;
  delivery?: number;
}

const RATE_KEYS: Record<string, keyof RateChartRow> = {
  plainq_send_rate: "send",
  plainq_receive_rate: "receive",
  plainq_delete_rate: "delete",
  plainq_topic_publish_rate: "publish",
  plainq_topic_delivery_rate: "delivery",
};

export function transformRateMetrics(
  metrics: Pick<MetricsChartResponse, "metricName" | "dataPoints">[],
): RateChartRow[] {
  const rows = new Map<number, RateChartRow>();

  for (const metric of metrics) {
    const key =
      RATE_KEYS[metric.metricName] ??
      metric.metricName.replace(/^plainq_/, "").replace(/_rate$/, "");

    for (const point of metric.dataPoints ?? []) {
      const existing = rows.get(point.timestamp) ?? { timestamp: point.timestamp };
      (existing as unknown as Record<string, number>)[key] = point.value;
      rows.set(point.timestamp, existing);
    }
  }

  return Array.from(rows.values()).sort((a, b) => a.timestamp - b.timestamp);
}

export function formatMetricNumber(value?: number | null): string {
  if (value === undefined || value === null) return "0";
  if (value >= 1_000_000_000) return `${(value / 1_000_000_000).toFixed(2)}B`;
  if (value >= 1_000_000) return `${(value / 1_000_000).toFixed(2)}M`;
  if (value >= 1_000) return `${(value / 1_000).toFixed(2)}K`;
  return String(value);
}

export function formatMetricRate(value?: number | null): string {
  if (value === undefined || value === null) return "0.00";
  if (value >= 1_000_000) return `${(value / 1_000_000).toFixed(2)}M`;
  if (value >= 1_000) return `${(value / 1_000).toFixed(2)}K`;
  return value.toFixed(2);
}

export function formatMetricTimestamp(timestamp: number): string {
  return new Date(timestamp).toLocaleTimeString([], {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });
}

export function isTelemetryUnavailableError(error: unknown): boolean {
  if (!(error instanceof Error)) return false;
  return /^(404|503):/.test(error.message);
}
