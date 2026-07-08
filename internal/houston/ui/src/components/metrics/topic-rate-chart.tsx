import { useEffect, useMemo, useState } from "react";
import {
  CartesianGrid,
  Line,
  LineChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { api } from "@/lib/api-client";
import type { MultiMetricsChartResponse } from "@/lib/types";
import {
  formatMetricTimestamp,
  isTelemetryUnavailableError,
  transformRateMetrics,
} from "@/lib/metrics";
import { Skeleton } from "@/components/ui/skeleton";

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

  const rows = useMemo(() => transformRateMetrics(data?.metrics ?? []), [data]);

  if (loading) {
    return <Skeleton className="h-72" />;
  }

  if (unavailable) {
    return (
      <ChartMessageState>
        Telemetry is not enabled. Topic rate charts are unavailable.
      </ChartMessageState>
    );
  }

  if (error) {
    return <ChartMessageState>{error}</ChartMessageState>;
  }

  if (rows.length === 0) {
    return (
      <div className="flex h-72 items-center justify-center text-sm text-muted-foreground">
        No topic metrics for this range
      </div>
    );
  }

  return (
    <div className="h-72">
      <ResponsiveContainer width="100%" height="100%">
        <LineChart data={rows}>
          <CartesianGrid strokeDasharray="3 3" />
          <XAxis
            dataKey="timestamp"
            tickFormatter={formatMetricTimestamp}
          />
          <YAxis />
          <Tooltip
            labelFormatter={(value) => new Date(Number(value)).toLocaleString()}
          />
          <Line
            type="monotone"
            dataKey="publish"
            stroke="#2563eb"
            dot={false}
            name="Publish"
          />
          <Line
            type="monotone"
            dataKey="delivery"
            stroke="#16a34a"
            dot={false}
            name="Delivery"
          />
        </LineChart>
      </ResponsiveContainer>
    </div>
  );
}

function ChartMessageState({ children }: { children: string }) {
  return (
    <div className="flex h-72 items-center justify-center text-center text-sm text-muted-foreground">
      <p className="max-w-sm">{children}</p>
    </div>
  );
}
