import { describe, expect, test } from "bun:test";
import {
  formatMetricNumber,
  formatMetricRate,
  isTelemetryUnavailableError,
  transformRateMetrics,
  transformTopicSeries,
} from "./metrics";
import type { MetricsChartResponse, TopicSeriesResponse } from "./types";
import { api } from "./api-client";

describe("formatMetricNumber", () => {
  test("formats compact values", () => {
    expect(formatMetricNumber(0)).toBe("0");
    expect(formatMetricNumber(999)).toBe("999");
    expect(formatMetricNumber(1200)).toBe("1.20K");
    expect(formatMetricNumber(2_500_000)).toBe("2.50M");
  });
});

describe("formatMetricRate", () => {
  test("formats rates with two decimals", () => {
    expect(formatMetricRate(0)).toBe("0.00");
    expect(formatMetricRate(12.345)).toBe("12.35");
    expect(formatMetricRate(1500)).toBe("1.50K");
  });
});

describe("transformRateMetrics", () => {
  test("merges metric series by timestamp", () => {
    const rows = transformRateMetrics([
      {
        metricName: "plainq_topic_publish_rate",
        dataPoints: [{ timestamp: 1000, value: 2 }],
      },
      {
        metricName: "plainq_topic_delivery_rate",
        dataPoints: [{ timestamp: 1000, value: 4 }],
      },
    ]);

    expect(rows).toEqual([
      {
        timestamp: 1000,
        publish: 2,
        delivery: 4,
      },
    ]);
  });

  test("keeps the legacy queue response contract free of topic sample metadata", () => {
    const response: MetricsChartResponse = {
      metricName: "plainq_send_rate",
      queueId: "queue-1",
      dataPoints: [{ timestamp: 1000, value: 2 }],
    };

    expect(transformRateMetrics([response])).toEqual([{ timestamp: 1000, send: 2 }]);
  });
});

describe("transformTopicSeries", () => {
  test("accepts every topic sample source and preserves declared missing buckets", () => {
    const timeRange = { from: 1000, to: 5000 };
    const response: TopicSeriesResponse = {
      topicId: "topic-1",
      metrics: [
        {
          metricName: "plainq_topic_publish_rate",
          topicId: "topic-1",
          kind: "rate",
          unit: "messages/s",
          interpolation: "linear",
          timeRange,
          resolution: "raw",
          samples: {
            expectedPointCount: 4,
            returnedPointCount: 3,
            firstSampleAt: 1000,
            lastSampleAt: 3000,
            complete: false,
            missingRanges: [{ from: 3000, to: 5000, reason: "notRecorded" }],
          },
          dataPoints: [
            { timestamp: 1000, value: 4, source: "observed" },
            { timestamp: 2000, value: 0, source: "aggregated" },
            { timestamp: 3000, value: 8, source: "observed" },
          ],
        },
        {
          metricName: "plainq_topic_subscriptions_current",
          topicId: "topic-1",
          kind: "gauge",
          unit: "subscriptions",
          interpolation: "stepAfter",
          timeRange,
          resolution: "raw",
          samples: {
            expectedPointCount: 4,
            returnedPointCount: 2,
            firstSampleAt: 1000,
            lastSampleAt: 3000,
            complete: false,
            missingRanges: [{ from: 2000, to: 3000, reason: "outsideRetention" }],
          },
          dataPoints: [
            { timestamp: 1000, value: 2, source: "carriedForward" },
            { timestamp: 3000, value: 3, source: "observed" },
          ],
        },
      ],
      timeRange,
      effectiveTimeRange: timeRange,
      resolution: "raw",
      sampleIntervalMs: 1000,
      generatedAt: 5000,
    };

    expect(
      response.metrics.flatMap((metric) => metric.dataPoints.map((point) => point.source)),
    ).toEqual(["observed", "aggregated", "observed", "carriedForward", "observed"]);
    expect(
      transformTopicSeries(response, {
        plainq_topic_publish_rate: "publish",
        plainq_topic_subscriptions_current: "active",
      }),
    ).toEqual([
      { t: 1000, publish: 4, active: 2 },
      { t: 2000, publish: 0, active: null },
      { t: 3000, publish: null, active: 3 },
      { t: 4000, publish: null },
    ]);
  });
});

describe("isTelemetryUnavailableError", () => {
  test("matches disabled telemetry errors with the apiFetch status prefix", () => {
    expect(isTelemetryUnavailableError(new Error("404: not found"))).toBe(true);
    expect(isTelemetryUnavailableError(new Error("503: telemetry unavailable"))).toBe(true);
    expect(
      isTelemetryUnavailableError(
        new Error("request failed after retrying 404: telemetry unavailable"),
      ),
    ).toBe(false);
    expect(isTelemetryUnavailableError(new Error("503 telemetry unavailable"))).toBe(false);
    expect(isTelemetryUnavailableError(new Error("network failed"))).toBe(false);
  });
});

describe("api errors", () => {
  test("preserve response status in the message", async () => {
    const originalFetch = globalThis.fetch;
    globalThis.fetch = (async (input: RequestInfo | URL) => {
      if (String(input).includes("/queue/q1")) {
        return new Response(JSON.stringify({ message: "queue missing" }), {
          status: 503,
          headers: { "Content-Type": "application/json" },
        });
      }

      return new Response(JSON.stringify({}), { status: 200 });
    }) as typeof fetch;

    try {
      await expect(api.queues.get("q1")).rejects.toThrow("503: queue missing");
    } finally {
      globalThis.fetch = originalFetch;
    }
  });
});
