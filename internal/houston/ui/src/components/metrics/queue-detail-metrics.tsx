"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import { RefreshCw } from "lucide-react";

import { api } from "@/lib/api-client";
import type {
  InFlightMetricsResponse,
  MetricDataPoint,
  MultiMetricsChartResponse,
  QueueMetricsSummary,
} from "@/lib/types";
import {
  isTelemetryUnavailableError,
  type RateChartRow,
  transformRateMetrics,
} from "@/lib/metrics";
import { formatCount, formatRate } from "@/lib/format";
import { Button } from "@/components/ui/button";
import { EmptyState } from "@/components/ui/empty-state";
import { Panel, PanelBody, PanelTitleBar } from "@/components/ui/panel";
import { SectionHeader } from "@/components/ui/page-header";
import { Skeleton } from "@/components/ui/skeleton";
import { formatRateFigure } from "./format-metrics";
import { SeriesLegend, SeriesSwatch, type LifecycleTone, type SeriesSpec } from "./lifecycle";
import { Segmented } from "./segmented";
import { describeSeries, SeriesChart, type ChartRow } from "./series-chart";

/** The presets the server's range parser understands. */
const TIME_RANGES = [
  { value: "5m", label: "5m" },
  { value: "15m", label: "15m" },
  { value: "1h", label: "1h" },
  { value: "6h", label: "6h" },
  { value: "24h", label: "24h" },
  { value: "7d", label: "7d" },
] as const;

const CHART_HEIGHT = 220;

/**
 * Keys match what `transformRateMetrics` emits for `plainq_*_rate`. Deletion is
 * the acknowledge end of the lifecycle, so it takes the acknowledge tone.
 */
const RATE_SERIES: SeriesSpec[] = [
  { key: "send", label: "sent", tone: "send" },
  { key: "receive", label: "received", tone: "receive" },
  { key: "delete", label: "deleted", tone: "acknowledge", dashed: true },
];

/** In-flight is a count of messages, not a rate — no denominator, own plot. */
const IN_FLIGHT_SERIES: SeriesSpec[] = [{ key: "value", label: "in-flight", tone: "send" }];

interface QueueDetailMetricsProps {
  queueId: string;
  queueName: string;
}

interface QueueMetricsPanelContentProps {
  queueName: string;
  timeRange: string;
  summary: QueueMetricsSummary | null;
  rateRows: RateChartRow[];
  inFlightRows: MetricDataPoint[];
  onRefresh: () => void;
  onTimeRangeChange: (value: string) => void;
  loading?: boolean;
}

type QueueMetricsApi = Pick<
  typeof api.metrics,
  "queue" | "queueRates" | "queueInFlight"
>;

type QueueMetricsLoadState =
  | {
      status: "loaded";
      summary: QueueMetricsSummary;
      rates: MultiMetricsChartResponse;
      inFlight: InFlightMetricsResponse;
    }
  | {
      status: "unavailable";
    }
  | {
      status: "error";
      message: string;
    };

export async function loadQueueMetricsState(
  metricsApi: QueueMetricsApi,
  queueId: string,
  timeRange: string,
): Promise<QueueMetricsLoadState> {
  try {
    const [summary, rates, inFlight] = await Promise.all([
      metricsApi.queue(queueId, timeRange),
      metricsApi.queueRates(queueId, timeRange),
      metricsApi.queueInFlight(queueId, timeRange),
    ]);

    return {
      status: "loaded",
      summary,
      rates,
      inFlight,
    };
  } catch (error) {
    if (isTelemetryUnavailableError(error)) {
      return { status: "unavailable" };
    }

    return {
      status: "error",
      message:
        error instanceof Error ? error.message : "Failed to load queue metrics",
    };
  }
}

export function QueueDetailMetrics({
  queueId,
  queueName,
}: QueueDetailMetricsProps) {
  const [timeRange, setTimeRange] = useState("1h");
  const [summary, setSummary] = useState<QueueMetricsSummary | null>(null);
  const [rates, setRates] = useState<MultiMetricsChartResponse | null>(null);
  const [inFlight, setInFlight] = useState<InFlightMetricsResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [unavailable, setUnavailable] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    setLoading(true);
    setError(null);
    const result = await loadQueueMetricsState(api.metrics, queueId, timeRange);

    switch (result.status) {
      case "loaded":
        setSummary(result.summary);
        setRates(result.rates);
        setInFlight(result.inFlight);
        setUnavailable(false);
        break;
      case "unavailable":
        setUnavailable(true);
        break;
      case "error":
        setUnavailable(false);
        setError(result.message);
        break;
    }

    setLoading(false);
  }, [queueId, timeRange]);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  const rateRows = useMemo(
    () => transformRateMetrics(rates?.metrics ?? []),
    [rates],
  );
  const inFlightRows = inFlight?.history ?? [];

  if (loading && !summary) {
    return <QueueMetricsSkeleton />;
  }

  if (unavailable) {
    return <QueueMetricsTelemetryDisabledState />;
  }

  // A failed refresh keeps the last good sample on screen rather than blanking
  // the panel; only a first read that never landed leaves nothing to show.
  if (error && !summary) {
    return (
      <MetricsEmptyState
        title="Metrics could not be loaded"
        body={error}
      />
    );
  }

  return (
    <QueueMetricsPanelContent
      queueName={queueName}
      timeRange={timeRange}
      summary={summary}
      rateRows={rateRows}
      inFlightRows={inFlightRows}
      onRefresh={() => void refresh()}
      onTimeRangeChange={setTimeRange}
      loading={loading}
    />
  );
}

export function QueueMetricsPanelContent({
  queueName,
  timeRange,
  summary,
  rateRows,
  inFlightRows,
  onRefresh,
  onTimeRangeChange,
  loading = false,
}: QueueMetricsPanelContentProps) {
  const rateChartRows: ChartRow[] = rateRows.map(
    ({ timestamp, ...rest }) => ({ t: timestamp, ...rest }) as ChartRow,
  );
  const inFlightChartRows: ChartRow[] = inFlightRows.map((point) => ({
    t: point.timestamp,
    value: point.value,
  }));

  return (
    <div className="mt-4 flex flex-col gap-4">
      <SectionHeader
        title="Queue metrics"
        description={queueName}
        actions={
          <>
            <Segmented
              label="Time range"
              value={timeRange}
              onChange={onTimeRangeChange}
              options={TIME_RANGES.map((range) => ({
                value: range.value as string,
                label: range.label,
              }))}
            />
            <Button
              variant="outline"
              size="icon"
              onClick={onRefresh}
              loading={loading}
              aria-label="Refresh metrics"
            >
              <RefreshCw className="size-4" aria-hidden />
            </Button>
          </>
        }
      />

      <div className="grid grid-cols-2 gap-3 xl:grid-cols-4">
        <MetricTile
          label="Send rate"
          tone="send"
          value={formatRateFigure(summary?.currentSendRate ?? 0)}
          unit="/s"
        />
        <MetricTile
          label="Receive rate"
          tone="receive"
          value={formatRateFigure(summary?.currentReceiveRate ?? 0)}
          unit="/s"
        />
        <MetricTile
          label="Delete rate"
          tone="acknowledge"
          value={formatRateFigure(summary?.currentDeleteRate ?? 0)}
          unit="/s"
        />
        <MetricTile label="In-flight" value={formatCount(summary?.currentInFlight ?? 0)} />
      </div>

      <div className="grid gap-4 xl:grid-cols-2">
        <ChartPanel
          title="Throughput"
          series={RATE_SERIES}
          rows={rateChartRows}
          timeRange={timeRange}
          formatValue={formatRate}
        />
        <ChartPanel
          title="In-flight messages"
          series={IN_FLIGHT_SERIES}
          rows={inFlightChartRows}
          timeRange={timeRange}
          formatValue={formatCount}
        />
      </div>
    </div>
  );
}

function ChartPanel({
  title,
  series,
  rows,
  timeRange,
  formatValue,
}: {
  title: string;
  series: SeriesSpec[];
  rows: ChartRow[];
  timeRange: string;
  formatValue: (value: number) => string;
}) {
  return (
    <Panel className="flex flex-col">
      <PanelTitleBar
        className="items-center py-2.5"
        title={title}
        action={<SeriesLegend series={series} />}
      />
      <PanelBody className="flex flex-1 flex-col gap-2 px-4 py-3.5">
        {rows.length === 0 ? (
          <ChartEmptyState />
        ) : (
          <SeriesChart
            data={rows}
            series={series}
            height={CHART_HEIGHT}
            formatValue={formatValue}
            summary={describeSeries(rows, series, timeRange, formatValue)}
          />
        )}
      </PanelBody>
    </Panel>
  );
}

export function QueueMetricsTelemetryDisabledState() {
  return (
    <MetricsEmptyState
      title="Telemetry is not enabled"
      body="Queue operations still work. Start PlainQ with telemetry storage configured to collect dashboard data."
    />
  );
}

function MetricTile({
  label,
  value,
  unit,
  tone,
}: {
  label: string;
  value: string;
  unit?: string;
  tone?: LifecycleTone;
}) {
  return (
    <Panel className="px-3.5 py-3">
      <div className="flex items-center gap-1.5 text-[11px] text-muted-foreground">
        {tone ? <SeriesSwatch tone={tone} /> : null}
        {label}
      </div>
      <div className="font-mono text-[18px] leading-[26px] font-medium tabular">
        {value}
        {unit ? <span className="text-[11px] text-subtle">{unit}</span> : null}
      </div>
    </Panel>
  );
}

function QueueMetricsSkeleton() {
  return (
    <div className="mt-4 flex flex-col gap-4">
      <div className="grid grid-cols-2 gap-3 xl:grid-cols-4">
        {Array.from({ length: 4 }).map((_, index) => (
          <Panel key={index} className="px-3.5 py-3">
            <Skeleton className="h-[15px] w-20" />
            <Skeleton className="mt-2 h-[18px] w-14" />
          </Panel>
        ))}
      </div>
      <div className="grid gap-4 xl:grid-cols-2">
        <Skeleton className="h-[280px]" />
        <Skeleton className="h-[280px]" />
      </div>
    </div>
  );
}

function MetricsEmptyState({ title, body }: { title: string; body: string }) {
  return (
    <Panel className="mt-4">
      <EmptyState title={title} description={body} />
    </Panel>
  );
}

function ChartEmptyState() {
  return (
    <EmptyState
      title="No samples in this range"
      description="No data for this range"
      className="px-4 py-8"
    />
  );
}
