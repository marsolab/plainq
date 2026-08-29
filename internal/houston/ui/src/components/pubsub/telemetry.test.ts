import { describe, expect, test } from "bun:test";

import { ApiRequestError, api } from "@/lib/api-client";
import type {
  MetricSeriesResponse,
  TopicSeriesResponse,
  TopicSubscriptionsResponse,
} from "@/lib/types";
import {
  beginTopicTelemetryLoad,
  loadTopicTelemetry,
  type TopicTelemetryLoads,
} from "./telemetry";

const timeRange = { from: 1_700_000_000_000, to: 1_700_000_060_000 };

function metric(
  metricName: string,
  interpolation: MetricSeriesResponse["interpolation"] = "linear",
): MetricSeriesResponse {
  return {
    metricName,
    topicId: "topic-1",
    kind: interpolation === "stepAfter" ? "gauge" : "rate",
    unit: interpolation === "stepAfter" ? "subscriptions" : "messages_per_second",
    interpolation,
    timeRange,
    resolution: "raw",
    samples: {
      expectedPointCount: 1,
      returnedPointCount: 1,
      firstSampleAt: timeRange.from,
      lastSampleAt: timeRange.from,
      complete: true,
      missingRanges: [],
    },
    dataPoints: [
      {
        timestamp: timeRange.from,
        value: 1,
        source: "observed",
        count: 1,
      },
    ],
  };
}

const rates: TopicSeriesResponse = {
  topicId: "topic-1",
  metrics: [metric("plainq_topic_publish_rate")],
  timeRange,
  effectiveTimeRange: timeRange,
  resolution: "raw",
  sampleIntervalMs: 10_000,
  generatedAt: timeRange.to,
};

const subscriptions: TopicSubscriptionsResponse = {
  ...rates,
  metrics: [metric("plainq_topic_subscriptions_current", "stepAfter")],
  summary: {
    subscriptionsCurrent: 1,
    createdDuringWindow: 1,
    removedDuringWindow: 0,
    avgCreateRate: 0.1,
    avgRemoveRate: 0,
    maxCreateRate: 0.1,
    maxRemoveRate: 0,
    updatedAt: timeRange.to,
  },
};

describe("api.metrics.topicSubscriptions", () => {
  test("uses the exact typed subscriptions route and selected range", async () => {
    const originalFetch = globalThis.fetch;
    let requested = "";
    globalThis.fetch = (async (input: RequestInfo | URL) => {
      requested = String(input);
      return Response.json(subscriptions);
    }) as typeof fetch;

    try {
      const response = await api.metrics.topicSubscriptions("topic-1", "24h");
      expect(response).toEqual(subscriptions);
      expect(requested).toEndWith("/metrics/topic/topic-1/subscriptions?range=24h");
    } finally {
      globalThis.fetch = originalFetch;
    }
  });
});

describe("loadTopicTelemetry", () => {
  test("requests rates and subscriptions independently with the shared range", async () => {
    const calls: string[] = [];

    const requests = loadTopicTelemetry(
      {
        topicRates: async (topicId, range) => {
          calls.push(`rates:${topicId}:${range}`);
          return rates;
        },
        topicSubscriptions: async (topicId, range) => {
          calls.push(`subscriptions:${topicId}:${range}`);
          return subscriptions;
        },
      },
      "topic-1",
      "6h",
    );
    const result = {
      rates: await requests.rates,
      subscriptions: await requests.subscriptions,
    };

    expect(calls).toEqual(["rates:topic-1:6h", "subscriptions:topic-1:6h"]);
    expect(result).toEqual({
      rates: { status: "ready", data: rates, range: "6h" },
      subscriptions: { status: "ready", data: subscriptions, range: "6h" },
    });
  });

  test("keeps a successful endpoint when the other endpoint fails", async () => {
    const requests = loadTopicTelemetry(
      {
        topicRates: async () => rates,
        topicSubscriptions: async () => {
          throw new Error("subscription history failed");
        },
      },
      "topic-1",
      "1h",
    );
    const result = {
      rates: await requests.rates,
      subscriptions: await requests.subscriptions,
    };

    expect(result.rates).toEqual({ status: "ready", data: rates, range: "1h" });
    expect(result.subscriptions).toEqual({
      status: "error",
      message: "subscription history failed",
    });
  });

  test("retains same-range last-good data for typed unavailable and ordinary errors", async () => {
    const lastGood = {
      rates: { data: rates, range: "1h" as const },
      subscriptions: { data: subscriptions, range: "1h" as const },
    };

    const requests = loadTopicTelemetry(
      {
        topicRates: async () => {
          throw new ApiRequestError(503, "503: telemetry unavailable");
        },
        topicSubscriptions: async () => {
          throw new Error("subscription refresh failed");
        },
      },
      "topic-1",
      "1h",
      lastGood,
    );
    const result = {
      rates: await requests.rates,
      subscriptions: await requests.subscriptions,
    };

    expect(result.rates).toEqual({
      status: "unavailable",
      lastGood: lastGood.rates,
    });
    expect(result.subscriptions).toEqual({
      status: "error",
      message: "subscription refresh failed",
      lastGood: lastGood.subscriptions,
    });
  });

  test("never carries last-good data into a different range", async () => {
    const requests = loadTopicTelemetry(
      {
        topicRates: async () => {
          throw new Error("rates failed");
        },
        topicSubscriptions: async () => {
          throw new ApiRequestError(404, "404: telemetry unavailable");
        },
      },
      "topic-1",
      "24h",
      {
        rates: { data: rates, range: "1h" },
        subscriptions: { data: subscriptions, range: "1h" },
      },
    );
    const result = {
      rates: await requests.rates,
      subscriptions: await requests.subscriptions,
    };

    expect(result.rates).toEqual({ status: "error", message: "rates failed" });
    expect(result.subscriptions).toEqual({ status: "unavailable" });
  });
});

describe("beginTopicTelemetryLoad", () => {
  const ready: TopicTelemetryLoads = {
    rates: { status: "ready", data: rates, range: "1h" },
    subscriptions: { status: "ready", data: subscriptions, range: "1h" },
  };

  test("marks same-range last-good values refreshing", () => {
    expect(beginTopicTelemetryLoad(ready, "1h")).toEqual({
      rates: { status: "refreshing", data: rates, range: "1h" },
      subscriptions: { status: "refreshing", data: subscriptions, range: "1h" },
    });
  });

  test("discards last-good values when the range changes", () => {
    expect(beginTopicTelemetryLoad(ready, "24h")).toEqual({
      rates: { status: "loading" },
      subscriptions: { status: "loading" },
    });
  });
});
