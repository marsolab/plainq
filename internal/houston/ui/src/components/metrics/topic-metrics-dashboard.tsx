"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import { RefreshCw } from "lucide-react";

import { api } from "@/lib/api-client";
import type { Topic, TopicMetricsOverview, TopicMetricsRow } from "@/lib/types";
import { isTelemetryUnavailableError } from "@/lib/metrics";
import { formatClock, formatCount } from "@/lib/format";
import { Button } from "@/components/ui/button";
import { EmptyState } from "@/components/ui/empty-state";
import { Panel, PanelBody, PanelTitleBar } from "@/components/ui/panel";
import { SectionHeader } from "@/components/ui/page-header";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Skeleton } from "@/components/ui/skeleton";
import { Status } from "@/components/ui/status";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableIdentityCell,
  TableRow,
} from "@/components/ui/table";
import { formatRateFigure } from "./format-metrics";
import { SeriesSwatch, type LifecycleTone } from "./lifecycle";
import { Segmented } from "./segmented";
import { TopicRateChart } from "./topic-rate-chart";

/** The presets the server's range parser understands. */
const TIME_RANGES = [
  { value: "5m", label: "5m" },
  { value: "15m", label: "15m" },
  { value: "1h", label: "1h" },
  { value: "6h", label: "6h" },
  { value: "24h", label: "24h" },
  { value: "7d", label: "7d" },
] as const;

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

  // A failed refresh keeps the last good overview on screen; only a first read
  // that never landed leaves nothing to show.
  if (error && !overview) {
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
    <MetricsEmptyState
      title="Telemetry is not enabled"
      body="Pub/Sub management still works. Start PlainQ with telemetry storage configured to collect dashboard data."
    />
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
    <div className="flex flex-col gap-4">
      <SectionHeader
        title="Pub/Sub metrics"
        description="Publish activity, deliveries, and active subscriptions by topic."
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
              aria-label="Refresh topic metrics"
            >
              <RefreshCw className="size-4" aria-hidden />
            </Button>
          </>
        }
      />

      <div className="grid grid-cols-2 gap-3 xl:grid-cols-5">
        <MetricTile
          label="Publish rate"
          tone="send"
          value={formatRateFigure(overview.systemMetrics.publishRate)}
          unit="/s"
        />
        <MetricTile
          label="Delivery rate"
          tone="receive"
          value={formatRateFigure(overview.systemMetrics.deliveryRate)}
          unit="/s"
        />
        <MetricTile
          label="Published"
          value={formatCount(overview.systemMetrics.messagesPublished)}
        />
        <MetricTile label="Deliveries" value={formatCount(overview.systemMetrics.deliveries)} />
        <MetricTile
          label="Subscriptions"
          value={formatOptionalCount(overview.systemMetrics.subscriptionsCurrent)}
        />
      </div>

      {selectedTopicId ? (
        <Panel className="flex flex-col">
          <PanelTitleBar
            className="items-center py-2.5"
            title={selectedTopicLabel}
            action={
              <Select
                value={selectedTopicId}
                onValueChange={(value) => {
                  if (value) onTopicChange(value);
                }}
              >
                <SelectTrigger className="w-56" aria-label="Topic series">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {topicOptions.map((option) => (
                    <SelectItem key={option.value} value={option.value}>
                      {option.label}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            }
          />
          <PanelBody className="px-4 py-3.5">
            <TopicRateChart
              topicId={selectedTopicId}
              timeRange={timeRange}
              refreshKey={chartRefreshKey}
            />
          </PanelBody>
        </Panel>
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
      <Panel>
        <EmptyState
          title="No topics reporting"
          description="No topic metrics have been recorded yet. Publish to a topic to start recording them."
        />
      </Panel>
    );
  }

  return (
    <Panel>
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead>Topic</TableHead>
            <TableHead numeric>Publish /s</TableHead>
            <TableHead numeric>Delivery /s</TableHead>
            <TableHead numeric>Published</TableHead>
            <TableHead numeric>Deliveries</TableHead>
            <TableHead numeric>Subscriptions</TableHead>
            <TableHead>Last updated</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {rows.map((row) => {
            // Publishing into a topic with no subscribers delivers nothing —
            // worth flagging, but it is a fact about the topic, not an error.
            const orphaned = row.subscriptionsCurrent === 0;

            return (
              <TableRow key={row.topicId}>
                <TableIdentityCell name={topicNames.get(row.topicId) ?? row.topicId} />
                <TableCell numeric>{formatRateFigure(row.publishRate)}</TableCell>
                <TableCell numeric>{formatRateFigure(row.deliveryRate)}</TableCell>
                <TableCell numeric>{formatCount(row.messagesPublished)}</TableCell>
                <TableCell numeric>{formatCount(row.deliveries)}</TableCell>
                <TableCell numeric>
                  {row.subscriptionsCurrent === null || row.subscriptionsCurrent === undefined ? (
                    <span className="text-subtle">Unknown</span>
                  ) : orphaned ? (
                    <Status tone="warning" className="justify-end font-mono tabular">
                      0
                    </Status>
                  ) : (
                    formatCount(row.subscriptionsCurrent)
                  )}
                </TableCell>
                <TableCell className="font-mono text-xs tabular">
                  {formatClock(row.updatedAt)}
                </TableCell>
              </TableRow>
            );
          })}
        </TableBody>
      </Table>
      <div className="border-t border-border px-4 py-2 text-[11px] text-subtle">
        Counters run since process start and reset on restart — never lifetime totals. A
        subscription count the transport does not report reads “Unknown”, never 0.
      </div>
    </Panel>
  );
}

function TopicMetricsDashboardSkeleton() {
  return (
    <div className="flex flex-col gap-4">
      <div className="grid grid-cols-2 gap-3 xl:grid-cols-5">
        {Array.from({ length: 5 }).map((_, index) => (
          <Panel key={index} className="px-3.5 py-3">
            <Skeleton className="h-[15px] w-20" />
            <Skeleton className="mt-2 h-[18px] w-14" />
          </Panel>
        ))}
      </div>
      <Skeleton className="h-[300px]" />
    </div>
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

function MetricsEmptyState({ title, body }: { title: string; body: string }) {
  return (
    <Panel>
      <EmptyState title={title} description={body} />
    </Panel>
  );
}

/** A subscription count the transport does not report. Never collapsed to 0. */
function formatOptionalCount(value: number | null | undefined) {
  if (value === null || value === undefined) {
    return "Unknown";
  }

  return formatCount(value);
}
