"use client";

import { useEffect, useMemo, useState } from "react";

import { api } from "@/lib/api-client";
import type { MultiMetricsChartResponse } from "@/lib/types";
import { isTelemetryUnavailableError, transformRateMetrics } from "@/lib/metrics";
import { formatRate } from "@/lib/format";
import { EmptyState } from "@/components/ui/empty-state";
import { Skeleton } from "@/components/ui/skeleton";
import { SeriesLegend, type SeriesSpec } from "./lifecycle";
import { describeSeries, SeriesChart, type ChartRow } from "./series-chart";

const CHART_HEIGHT = 240;

/** Publish is the send half of the lifecycle; delivery is the receive half. */
const TOPIC_SERIES: SeriesSpec[] = [
  { key: "publish", label: "published", tone: "send" },
  { key: "delivery", label: "delivered", tone: "receive" },
];

interface TopicRateChartProps {
  topicId: string;
  timeRange: string;
  refreshKey?: number;
  metricsApi?: TopicRateChartApi;
}

type TopicRateChartApi = Pick<typeof api.metrics, "topicRates">;

type TopicRateChartLoadState =
  | {
      status: "loaded";
      data: MultiMetricsChartResponse;
    }
  | {
      status: "unavailable";
    }
  | {
      status: "error";
      message: string;
    };

export async function loadTopicRateChartState(
  metricsApi: TopicRateChartApi,
  topicId: string,
  timeRange: string,
): Promise<TopicRateChartLoadState> {
  try {
    const data = await metricsApi.topicRates(topicId, timeRange);

    return {
      status: "loaded",
      data,
    };
  } catch (error) {
    if (isTelemetryUnavailableError(error)) {
      return { status: "unavailable" };
    }

    return {
      status: "error",
      message: error instanceof Error ? error.message : "Failed to load topic rates",
    };
  }
}

export function TopicRateChart({
  topicId,
  timeRange,
  refreshKey = 0,
  metricsApi = api.metrics,
}: TopicRateChartProps) {
  const [data, setData] = useState<MultiMetricsChartResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [unavailable, setUnavailable] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;

    setLoading(true);
    setError(null);

    void loadTopicRateChartState(metricsApi, topicId, timeRange).then((result) => {
      if (cancelled) {
        return;
      }

      switch (result.status) {
        case "loaded":
          setData(result.data);
          setUnavailable(false);
          break;
        case "unavailable":
          setData(null);
          setUnavailable(true);
          break;
        case "error":
          setData(null);
          setUnavailable(false);
          setError(result.message);
          break;
      }

      setLoading(false);
    });

    return () => {
      cancelled = true;
    };
  }, [metricsApi, topicId, timeRange, refreshKey]);

  const rows = useMemo<ChartRow[]>(
    () =>
      transformRateMetrics(data?.metrics ?? []).map(
        ({ timestamp, ...rest }) => ({ t: timestamp, ...rest }) as ChartRow,
      ),
    [data],
  );

  if (loading) {
    return <Skeleton style={{ height: CHART_HEIGHT }} className="w-full" />;
  }

  if (unavailable) {
    return (
      <ChartMessageState
        title="Telemetry is not enabled"
        body="Topic rate charts need telemetry storage configured. Pub/Sub management is unaffected."
      />
    );
  }

  if (error) {
    return <ChartMessageState title="Samples could not be loaded" body={error} />;
  }

  if (rows.length === 0) {
    return <ChartMessageState title="No samples in this range" body="No data for this range" />;
  }

  const summary = describeSeries(rows, TOPIC_SERIES, timeRange, formatRate);

  return (
    <div className="flex flex-col gap-2">
      <SeriesLegend series={TOPIC_SERIES} />
      <SeriesChart
        data={rows}
        series={TOPIC_SERIES}
        height={CHART_HEIGHT}
        formatValue={formatRate}
        summary={summary}
      />
    </div>
  );
}

function ChartMessageState({ title, body }: { title: string; body: string }) {
  return (
    <div className="flex items-center justify-center" style={{ minHeight: CHART_HEIGHT }}>
      <EmptyState title={title} description={body} />
    </div>
  );
}
