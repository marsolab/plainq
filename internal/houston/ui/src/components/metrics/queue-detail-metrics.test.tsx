import { describe, expect, test } from "bun:test";
import { renderToStaticMarkup } from "react-dom/server";
import type {
  InFlightMetricsResponse,
  MultiMetricsChartResponse,
  QueueMetricsSummary,
} from "@/lib/types";
import { formatCount } from "@/lib/format";
import { formatRateFigure } from "./format-metrics";
import {
  loadQueueMetricsState,
  QueueMetricsPanelContent,
  QueueMetricsTelemetryDisabledState,
} from "./queue-detail-metrics";

const summary: QueueMetricsSummary = {
  queueId: "q-123",
  totalSent: 100,
  totalReceived: 80,
  totalDeleted: 75,
  avgSendRate: 11,
  avgReceiveRate: 9,
  avgDeleteRate: 8,
  maxSendRate: 18,
  maxReceiveRate: 15,
  maxDeleteRate: 12,
  currentInFlight: 42,
  currentSendRate: 12.345,
  currentReceiveRate: 8.5,
  currentDeleteRate: 6,
  timeRange: {
    from: 1_700_000_000_000,
    to: 1_700_000_360_000,
  },
};

const rates: MultiMetricsChartResponse = {
  metrics: [],
  timeRange: summary.timeRange,
};

const inFlight: InFlightMetricsResponse = {
  current: summary.currentInFlight,
  history: [],
  timeRange: summary.timeRange,
};

describe("loadQueueMetricsState", () => {
  test("calls all three queue metrics APIs and returns loaded data", async () => {
    const calls: string[] = [];

    const metricsApi = {
      queue: async (queueId: string, range = "") => {
        calls.push(`queue:${queueId}:${range}`);
        return summary;
      },
      queueRates: async (queueId: string, range = "") => {
        calls.push(`queueRates:${queueId}:${range}`);
        return rates;
      },
      queueInFlight: async (queueId: string, range = "") => {
        calls.push(`queueInFlight:${queueId}:${range}`);
        return inFlight;
      },
    };

    const result = await loadQueueMetricsState(metricsApi, "q-123", "1h");

    expect(calls).toEqual([
      "queue:q-123:1h",
      "queueRates:q-123:1h",
      "queueInFlight:q-123:1h",
    ]);
    expect(result).toEqual({
      status: "loaded",
      summary,
      rates,
      inFlight,
    });
  });

  test("returns unavailable when telemetry storage is unavailable", async () => {
    const telemetryUnavailable = new Error("503: telemetry storage unavailable");

    const result = await loadQueueMetricsState(
      {
        queue: async () => {
          throw telemetryUnavailable;
        },
        queueRates: async () => rates,
        queueInFlight: async () => inFlight,
      },
      "q-123",
      "1h",
    );

    expect(result).toEqual({
      status: "unavailable",
    });
  });

  test("returns an error state for ordinary failures", async () => {
    const result = await loadQueueMetricsState(
      {
        queue: async () => summary,
        queueRates: async () => {
          throw new Error("boom");
        },
        queueInFlight: async () => inFlight,
      },
      "q-123",
      "1h",
    );

    expect(result).toEqual({
      status: "error",
      message: "boom",
    });
  });
});

describe("QueueMetricsTelemetryDisabledState", () => {
  test("renders the telemetry disabled guidance", () => {
    const markup = renderToStaticMarkup(<QueueMetricsTelemetryDisabledState />);

    expect(markup).toContain("Telemetry is not enabled");
    expect(markup).toContain(
      "Queue operations still work. Start PlainQ with telemetry storage configured to collect dashboard data.",
    );
  });
});

describe("QueueMetricsPanelContent", () => {
  test("renders queue summary cards and empty chart states", () => {
    const markup = renderToStaticMarkup(
      <QueueMetricsPanelContent
        queueName="orders"
        timeRange="1h"
        summary={summary}
        rateRows={[]}
        inFlightRows={[]}
        onRefresh={() => {}}
        onTimeRangeChange={() => {}}
      />,
    );

    expect(markup).toContain("Queue metrics");
    expect(markup).toContain("orders");
    // Rates render through the design system's one-decimal figure so a column
    // of them keeps its decimal points aligned; counts are exact and grouped.
    expect(markup).toContain("Send rate");
    expect(markup).toContain(formatRateFigure(summary.currentSendRate));
    expect(markup).toContain("Receive rate");
    expect(markup).toContain(formatRateFigure(summary.currentReceiveRate));
    expect(markup).toContain("Delete rate");
    expect(markup).toContain(formatRateFigure(summary.currentDeleteRate));
    expect(markup).toContain("In-flight");
    expect(markup).toContain(formatCount(summary.currentInFlight));
    expect(markup.match(/No data for this range/g)).toHaveLength(2);
  });
});
