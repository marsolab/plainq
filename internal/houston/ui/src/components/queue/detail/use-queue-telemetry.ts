"use client";

import { useCallback, useEffect, useRef, useState } from "react";

import { api } from "@/lib/api-client";
import {
  isTelemetryUnavailableError,
  transformRateMetrics,
  type RateChartRow,
} from "@/lib/metrics";
import type { MetricDataPoint, QueueMetricsSummary } from "@/lib/types";

/**
 * `unavailable` is its own state, not an error: a server started without
 * telemetry storage answers 404/503 on these routes while queue management
 * keeps working perfectly. Saying "metrics failed" there would send an
 * operator hunting a fault that does not exist.
 */
export type TelemetryStatus = "loading" | "ready" | "unavailable" | "failed";

export interface QueueTelemetry {
  status: TelemetryStatus;
  /** The last good read, kept across a failed refresh. */
  summary: QueueMetricsSummary | null;
  rates: RateChartRow[];
  inFlight: MetricDataPoint[];
  error: string | null;
  /** When the data on screen was read, for the STALE label. */
  readAt: number | null;
  refreshing: boolean;
  reload: () => void;
}

/**
 * The three per-queue telemetry endpoints, read together so a range change
 * never leaves the tiles and the plots describing different windows.
 *
 * A failure keeps the last good data on screen and reports the reason beside
 * it; it never blanks the panel.
 */
export function useQueueTelemetry(
  queueId: string,
  range: string,
  withSeries: boolean,
): QueueTelemetry {
  const [status, setStatus] = useState<TelemetryStatus>("loading");
  const [summary, setSummary] = useState<QueueMetricsSummary | null>(null);
  const [rates, setRates] = useState<RateChartRow[]>([]);
  const [inFlight, setInFlight] = useState<MetricDataPoint[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [readAt, setReadAt] = useState<number | null>(null);
  const [refreshing, setRefreshing] = useState(false);

  // A range switched twice in quick succession must not let the slower first
  // response land on top of the faster second one.
  const generation = useRef(0);

  const load = useCallback(async () => {
    const run = (generation.current += 1);
    setRefreshing(true);

    try {
      const [nextSummary, nextRates, nextInFlight] = await Promise.all([
        api.metrics.queue(queueId, range),
        withSeries ? api.metrics.queueRates(queueId, range) : Promise.resolve(null),
        withSeries ? api.metrics.queueInFlight(queueId, range) : Promise.resolve(null),
      ]);

      if (run !== generation.current) return;

      setSummary(nextSummary);
      if (nextRates) setRates(transformRateMetrics(nextRates.metrics ?? []));
      if (nextInFlight) setInFlight(nextInFlight.history ?? []);
      setError(null);
      setReadAt(Date.now());
      setStatus("ready");
    } catch (err) {
      if (run !== generation.current) return;

      if (isTelemetryUnavailableError(err)) {
        setStatus("unavailable");
        setError(null);
        return;
      }

      setStatus("failed");
      setError(err instanceof Error ? err.message : "Failed to read queue metrics");
    } finally {
      if (run === generation.current) setRefreshing(false);
    }
  }, [queueId, range, withSeries]);

  useEffect(() => {
    void load();
  }, [load]);

  return {
    status,
    summary,
    rates,
    inFlight,
    error,
    readAt,
    refreshing,
    reload: () => void load(),
  };
}
