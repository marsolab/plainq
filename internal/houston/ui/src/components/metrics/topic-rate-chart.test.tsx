import { describe, expect, test } from "bun:test";
import { act, create } from "react-test-renderer";
import type { MultiMetricsChartResponse } from "@/lib/types";
import { loadTopicRateChartState, TopicRateChart } from "./topic-rate-chart";

declare global {
  // React uses this test-only flag to validate act() usage.
  var IS_REACT_ACT_ENVIRONMENT: boolean | undefined;
}

globalThis.IS_REACT_ACT_ENVIRONMENT = true;

const rates: MultiMetricsChartResponse = {
  metrics: [],
  timeRange: {
    from: 1_700_000_000_000,
    to: 1_700_000_360_000,
  },
};

describe("loadTopicRateChartState", () => {
  test("returns loaded topic rates data", async () => {
    const calls: string[] = [];

    const result = await loadTopicRateChartState(
      {
        topicRates: async (topicId: string, timeRange = "") => {
          calls.push(`${topicId}:${timeRange}`);
          return rates;
        },
      },
      "topic-1",
      "1h",
    );

    expect(calls).toEqual(["topic-1:1h"]);
    expect(result).toEqual({
      status: "loaded",
      data: rates,
    });
  });

  test("returns unavailable when telemetry storage is unavailable", async () => {
    const result = await loadTopicRateChartState(
      {
        topicRates: async () => {
          throw new Error("503: telemetry storage unavailable");
        },
      },
      "topic-1",
      "1h",
    );

    expect(result).toEqual({
      status: "unavailable",
    });
  });

  test("returns an error state for ordinary failures", async () => {
    const result = await loadTopicRateChartState(
      {
        topicRates: async () => {
          throw new Error("boom");
        },
      },
      "topic-1",
      "1h",
    );

    expect(result).toEqual({
      status: "error",
      message: "boom",
    });
  });
});

describe("TopicRateChart", () => {
  test("refetches topic rates when refreshKey changes", async () => {
    const calls: string[] = [];
    const metricsApi = {
      topicRates: async (topicId: string, timeRange = "") => {
        calls.push(`${topicId}:${timeRange}`);
        return rates;
      },
    };

    let chart: ReturnType<typeof create> | undefined;
    const restoreConsoleError = ignoreReactTestRendererDeprecation();

    try {
      await act(async () => {
        chart = create(
          <TopicRateChart
            topicId="topic-1"
            timeRange="1h"
            refreshKey={0}
            metricsApi={metricsApi}
          />,
        );
      });

      await act(async () => {
        chart?.update(
          <TopicRateChart
            topicId="topic-1"
            timeRange="1h"
            refreshKey={1}
            metricsApi={metricsApi}
          />,
        );
      });

      expect(calls).toEqual(["topic-1:1h", "topic-1:1h"]);
    } finally {
      restoreConsoleError();
    }
  });
});

function ignoreReactTestRendererDeprecation() {
  const originalError = console.error;

  console.error = (...args: unknown[]) => {
    const message = String(args[0] ?? "");
    if (message.includes("react-test-renderer is deprecated")) {
      return;
    }

    originalError(...args);
  };

  return () => {
    console.error = originalError;
  };
}
