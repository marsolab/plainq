import { useCallback, useEffect, useMemo, useState } from "react";
import { RefreshCw } from "lucide-react";
import { api } from "@/lib/api-client";
import type { Topic, TopicMetricsOverview, TopicMetricsRow } from "@/lib/types";
import {
  formatMetricNumber,
  formatMetricRate,
  formatMetricTimestamp,
  isTelemetryUnavailableError,
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
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { TopicRateChart } from "./topic-rate-chart";

const TIME_RANGES = [
  { value: "5m", label: "5m" },
  { value: "15m", label: "15m" },
  { value: "1h", label: "1h" },
  { value: "6h", label: "6h" },
  { value: "24h", label: "24h" },
  { value: "7d", label: "7d" },
];

interface TopicMetricsDashboardProps {
  topics: Topic[];
  refreshKey: number;
}

interface TopicSelectorOption {
  value: string;
  label: string;
}

interface TopicMetricsPanelContentProps {
  overview: TopicMetricsOverview;
  timeRange: string;
  selectedTopicId: string;
  selectedTopicLabel: string;
  topicOptions: TopicSelectorOption[];
  topicNames: Map<string, string>;
  onRefresh: () => void;
  onTimeRangeChange: (value: string) => void;
  onTopicChange: (value: string) => void;
  chartRefreshKey: number;
  loading?: boolean;
}

type TopicMetricsApi = Pick<typeof api.metrics, "topicOverview">;

type TopicMetricsOverviewLoadState =
  | {
      status: "loaded";
      overview: TopicMetricsOverview;
    }
  | {
      status: "unavailable";
    }
  | {
      status: "error";
      message: string;
    };

export async function loadTopicMetricsOverviewState(
  metricsApi: TopicMetricsApi,
): Promise<TopicMetricsOverviewLoadState> {
  try {
    const overview = await metricsApi.topicOverview();

    return {
      status: "loaded",
      overview,
    };
  } catch (error) {
    if (isTelemetryUnavailableError(error)) {
      return { status: "unavailable" };
    }

    return {
      status: "error",
      message:
        error instanceof Error ? error.message : "Failed to load topic metrics",
    };
  }
}

export function buildTopicSelectorOptions(
  topics: Topic[],
  rows: TopicMetricsRow[],
): TopicSelectorOption[] {
  const topicNames = new Map(topics.map((topic) => [topic.topicId, topic.topicName]));
  const options: TopicSelectorOption[] = [];
  const seen = new Set<string>();

  for (const row of rows) {
    if (seen.has(row.topicId)) {
      continue;
    }

    seen.add(row.topicId);
    options.push({
      value: row.topicId,
      label: topicNames.get(row.topicId) ?? row.topicId,
    });
  }

  for (const topic of topics) {
    if (seen.has(topic.topicId)) {
      continue;
    }

    seen.add(topic.topicId);
    options.push({
      value: topic.topicId,
      label: topic.topicName,
    });
  }

  return options;
}

export function TopicMetricsDashboard({
  topics,
  refreshKey,
}: TopicMetricsDashboardProps) {
  const [overview, setOverview] = useState<TopicMetricsOverview | null>(null);
  const [timeRange, setTimeRange] = useState("1h");
  const [selectedTopicId, setSelectedTopicId] = useState("");
  const [chartRefreshKey, setChartRefreshKey] = useState(0);
  const [loading, setLoading] = useState(true);
  const [unavailable, setUnavailable] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const rows = overview?.topicMetrics ?? [];
  const topicOptions = useMemo(
    () => buildTopicSelectorOptions(topics, rows),
    [topics, rows],
  );

  const refresh = useCallback(async () => {
    setLoading(true);
    setError(null);

    const result = await loadTopicMetricsOverviewState(api.metrics);

    switch (result.status) {
      case "loaded": {
        setOverview(result.overview);
        setUnavailable(false);

        const nextTopicOptions = buildTopicSelectorOptions(
          topics,
          result.overview.topicMetrics,
        );
        const firstTopicId = nextTopicOptions[0]?.value ?? "";
        setSelectedTopicId((current) => {
          if (current && nextTopicOptions.some((option) => option.value === current)) {
            return current;
          }

          return firstTopicId;
        });
        setChartRefreshKey((key) => key + 1);
        break;
      }
      case "unavailable":
        setUnavailable(true);
        break;
      case "error":
        setUnavailable(false);
        setError(result.message);
        break;
    }

    setLoading(false);
  }, [topics]);

  useEffect(() => {
    void refresh();
  }, [refresh, refreshKey]);

  const topicNames = useMemo(
    () => new Map(topics.map((topic) => [topic.topicId, topic.topicName])),
    [topics],
  );
  const selectedTopic =
    topicOptions.some((option) => option.value === selectedTopicId)
      ? selectedTopicId
      : topicOptions[0]?.value ?? "";
  const selectedTopicLabel =
    topicOptions.find((option) => option.value === selectedTopic)?.label ??
    topicNames.get(selectedTopic) ??
    selectedTopic;

  if (loading && !overview) {
    return <TopicMetricsDashboardSkeleton />;
  }

  if (unavailable) {
    return <TopicMetricsTelemetryDisabledState />;
  }

  if (error) {
    return (
      <MetricsEmptyState
        title="Metrics could not be loaded"
        body={error}
      />
    );
  }

  if (!overview) {
    return (
      <MetricsEmptyState
        title="No topic metrics yet"
        body="Publish to a topic to start recording Pub/Sub metrics."
      />
    );
  }

  return (
    <TopicMetricsPanelContent
      overview={overview}
      timeRange={timeRange}
      selectedTopicId={selectedTopic}
      selectedTopicLabel={selectedTopicLabel}
      topicOptions={topicOptions}
      topicNames={topicNames}
      onRefresh={() => void refresh()}
      onTimeRangeChange={setTimeRange}
      onTopicChange={setSelectedTopicId}
      chartRefreshKey={chartRefreshKey}
      loading={loading}
    />
  );
}

export function TopicMetricsTelemetryDisabledState() {
  return (
    <div className="rounded-lg border border-dashed p-6 text-sm text-muted-foreground">
      Telemetry is not enabled. Pub/Sub management still works.
    </div>
  );
}

export function TopicMetricsPanelContent({
  overview,
  timeRange,
  selectedTopicId,
  selectedTopicLabel,
  topicOptions,
  topicNames,
  onRefresh,
  onTimeRangeChange,
  onTopicChange,
  chartRefreshKey,
  loading = false,
}: TopicMetricsPanelContentProps) {
  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h2 className="text-lg font-semibold">Pub/Sub metrics</h2>
          <p className="text-sm text-muted-foreground">
            Publish activity, deliveries, and active subscriptions by topic.
          </p>
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
            disabled={loading}
            aria-label="Refresh topic metrics"
          >
            <RefreshCw className="size-4" />
          </Button>
        </div>
      </div>

      <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-5">
        <MetricTile
          label="Publish rate"
          value={formatMetricRate(overview.systemMetrics.publishRate)}
          unit="msg/s"
        />
        <MetricTile
          label="Delivery rate"
          value={formatMetricRate(overview.systemMetrics.deliveryRate)}
          unit="msg/s"
        />
        <MetricTile
          label="Published"
          value={formatMetricNumber(overview.systemMetrics.messagesPublished)}
          unit="msgs"
        />
        <MetricTile
          label="Deliveries"
          value={formatMetricNumber(overview.systemMetrics.deliveries)}
          unit="msgs"
        />
        <MetricTile
          label="Subscriptions"
          value={formatOptionalMetricNumber(overview.systemMetrics.subscriptionsCurrent)}
          unit="active"
        />
      </div>

      {selectedTopicId ? (
        <Card>
          <CardHeader className="flex-row items-center justify-between gap-3">
            <CardTitle className="text-sm">{selectedTopicLabel}</CardTitle>
            <Select
              value={selectedTopicId}
              onValueChange={(value) => {
                if (value) onTopicChange(value);
              }}
            >
              <SelectTrigger className="w-56">
                <SelectValue />
              </SelectTrigger>
              <SelectPopup>
                {topicOptions.map((option) => (
                  <SelectItem key={option.value} value={option.value}>
                    {option.label}
                  </SelectItem>
                ))}
              </SelectPopup>
            </Select>
          </CardHeader>
          <CardContent>
            <TopicRateChart
              topicId={selectedTopicId}
              timeRange={timeRange}
              refreshKey={chartRefreshKey}
            />
          </CardContent>
        </Card>
      ) : null}

      <TopicMetricsTable rows={overview.topicMetrics} topicNames={topicNames} />
    </div>
  );
}

function TopicMetricsTable({
  rows,
  topicNames,
}: {
  rows: TopicMetricsRow[];
  topicNames: Map<string, string>;
}) {
  if (rows.length === 0) {
    return (
      <div className="rounded-lg border p-6 text-center text-sm text-muted-foreground">
        No topic metrics have been recorded yet.
      </div>
    );
  }

  return (
    <div className="rounded-lg border">
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead>Topic</TableHead>
            <TableHead>Publish rate</TableHead>
            <TableHead>Delivery rate</TableHead>
            <TableHead>Published</TableHead>
            <TableHead>Deliveries</TableHead>
            <TableHead>Subscriptions</TableHead>
            <TableHead>Last updated</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {rows.map((row) => (
            <TableRow key={row.topicId}>
              <TableCell className="font-medium">
                {topicNames.get(row.topicId) ?? row.topicId}
              </TableCell>
              <TableCell>{formatMetricRate(row.publishRate)} msg/s</TableCell>
              <TableCell>{formatMetricRate(row.deliveryRate)} msg/s</TableCell>
              <TableCell>{formatMetricNumber(row.messagesPublished)}</TableCell>
              <TableCell>{formatMetricNumber(row.deliveries)}</TableCell>
              <TableCell>{formatOptionalMetricNumber(row.subscriptionsCurrent)}</TableCell>
              <TableCell>{formatMetricTimestamp(row.updatedAt)}</TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </div>
  );
}

function TopicMetricsDashboardSkeleton() {
  return (
    <div className="space-y-4">
      <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-5">
        {Array.from({ length: 5 }).map((_, index) => (
          <Skeleton key={index} className="h-24" />
        ))}
      </div>
      <Skeleton className="h-72" />
    </div>
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

function MetricsEmptyState({ title, body }: { title: string; body: string }) {
  return (
    <div className="flex min-h-48 flex-col items-center justify-center rounded-lg border border-dashed text-center">
      <p className="text-sm font-medium">{title}</p>
      <p className="mt-1 max-w-md text-sm text-muted-foreground">{body}</p>
    </div>
  );
}

function formatOptionalMetricNumber(value: number | null | undefined) {
  if (value === null || value === undefined) {
    return "Unknown";
  }

  return formatMetricNumber(value);
}
