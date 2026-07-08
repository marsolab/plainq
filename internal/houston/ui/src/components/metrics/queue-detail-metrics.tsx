import { useCallback, useEffect, useMemo, useState } from "react";
import { RefreshCw } from "lucide-react";
import {
  Area,
  AreaChart,
  CartesianGrid,
  Line,
  LineChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { api } from "@/lib/api-client";
import type {
  InFlightMetricsResponse,
  MetricDataPoint,
  MultiMetricsChartResponse,
  QueueMetricsSummary,
} from "@/lib/types";
import {
  formatMetricNumber,
  formatMetricRate,
  formatMetricTimestamp,
  isTelemetryUnavailableError,
  type RateChartRow,
  transformRateMetrics,
} from "@/lib/metrics";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import {
  Select,
  SelectItem,
  SelectPopup,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Skeleton } from "@/components/ui/skeleton";

const TIME_RANGES = [
  { value: "5m", label: "5m" },
  { value: "15m", label: "15m" },
  { value: "1h", label: "1h" },
  { value: "6h", label: "6h" },
  { value: "24h", label: "24h" },
  { value: "7d", label: "7d" },
];

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

  if (error) {
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
}: QueueMetricsPanelContentProps) {
  return (
    <div className="mt-4 space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h3 className="text-base font-semibold">Queue metrics</h3>
          <p className="text-sm text-muted-foreground">{queueName}</p>
        </div>

        <div className="flex items-center gap-2">
          <Select
            value={timeRange}
            onValueChange={(value) => {
              if (value) onTimeRangeChange(value);
            }}
          >
            <SelectTrigger className="w-28">
              <SelectValue />
            </SelectTrigger>
            <SelectPopup>
              {TIME_RANGES.map((range) => (
                <SelectItem key={range.value} value={range.value}>
                  {range.label}
                </SelectItem>
              ))}
            </SelectPopup>
          </Select>

          <Button
            variant="outline"
            size="icon"
            onClick={onRefresh}
            aria-label="Refresh metrics"
          >
            <RefreshCw className="size-4" />
          </Button>
        </div>
      </div>

      <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <MetricTile
          label="Send rate"
          value={formatMetricRate(summary?.currentSendRate)}
          unit="msg/s"
        />
        <MetricTile
          label="Receive rate"
          value={formatMetricRate(summary?.currentReceiveRate)}
          unit="msg/s"
        />
        <MetricTile
          label="Delete rate"
          value={formatMetricRate(summary?.currentDeleteRate)}
          unit="msg/s"
        />
        <MetricTile
          label="In flight"
          value={formatMetricNumber(summary?.currentInFlight)}
          unit="msgs"
        />
      </div>

      <div className="grid gap-4 xl:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle className="text-sm">Throughput</CardTitle>
          </CardHeader>
          <CardContent className="h-72">
            {rateRows.length === 0 ? (
              <ChartEmptyState />
            ) : (
              <ResponsiveContainer width="100%" height="100%">
                <LineChart data={rateRows}>
                  <CartesianGrid strokeDasharray="3 3" />
                  <XAxis
                    dataKey="timestamp"
                    tickFormatter={formatMetricTimestamp}
                  />
                  <YAxis />
                  <Tooltip
                    labelFormatter={(value) =>
                      new Date(Number(value)).toLocaleString()
                    }
                  />
                  <Line
                    type="monotone"
                    dataKey="send"
                    stroke="#2563eb"
                    dot={false}
                    name="Send"
                  />
                  <Line
                    type="monotone"
                    dataKey="receive"
                    stroke="#16a34a"
                    dot={false}
                    name="Receive"
                  />
                  <Line
                    type="monotone"
                    dataKey="delete"
                    stroke="#9333ea"
                    dot={false}
                    name="Delete"
                  />
                </LineChart>
              </ResponsiveContainer>
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="text-sm">In-flight messages</CardTitle>
          </CardHeader>
          <CardContent className="h-72">
            {inFlightRows.length === 0 ? (
              <ChartEmptyState />
            ) : (
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={inFlightRows}>
                  <CartesianGrid strokeDasharray="3 3" />
                  <XAxis
                    dataKey="timestamp"
                    tickFormatter={formatMetricTimestamp}
                  />
                  <YAxis />
                  <Tooltip
                    labelFormatter={(value) =>
                      new Date(Number(value)).toLocaleString()
                    }
                  />
                  <Area
                    type="monotone"
                    dataKey="value"
                    stroke="#2563eb"
                    fill="#bfdbfe"
                    name="In flight"
                  />
                </AreaChart>
              </ResponsiveContainer>
            )}
          </CardContent>
        </Card>
      </div>
    </div>
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
}: {
  label: string;
  value: string;
  unit: string;
}) {
  return (
    <Card>
      <CardHeader className="pb-2">
        <CardTitle className="text-sm font-medium text-muted-foreground">
          {label}
        </CardTitle>
      </CardHeader>
      <CardContent>
        <div className="flex items-baseline gap-2">
          <span className="text-2xl font-semibold">{value}</span>
          <span className="text-xs text-muted-foreground">{unit}</span>
        </div>
      </CardContent>
    </Card>
  );
}

function QueueMetricsSkeleton() {
  return (
    <div className="mt-4 space-y-4">
      <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
        {Array.from({ length: 4 }).map((_, index) => (
          <Skeleton key={index} className="h-24" />
        ))}
      </div>
      <Skeleton className="h-72" />
    </div>
  );
}

function MetricsEmptyState({ title, body }: { title: string; body: string }) {
  return (
    <div className="mt-4 flex min-h-48 flex-col items-center justify-center rounded-lg border border-dashed text-center">
      <p className="text-sm font-medium">{title}</p>
      <p className="mt-1 max-w-md text-sm text-muted-foreground">{body}</p>
    </div>
  );
}

function ChartEmptyState() {
  return (
    <div className="flex h-full items-center justify-center text-sm text-muted-foreground">
      No data for this range
    </div>
  );
}
