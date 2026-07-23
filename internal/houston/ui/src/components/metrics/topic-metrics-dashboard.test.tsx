import { describe, expect, test } from "bun:test";
import { renderToStaticMarkup } from "react-dom/server";
import type { Topic, TopicMetricsOverview } from "@/lib/types";
import {
  buildTopicSelectorOptions,
  loadTopicMetricsOverviewState,
  TopicMetricsPanelContent,
  TopicMetricsTelemetryDisabledState,
} from "./topic-metrics-dashboard";
import { formatClock, formatCount } from "@/lib/format";

const overview: TopicMetricsOverview = {
  systemMetrics: {
    publishRate: 12.345,
    deliveryRate: 67.89,
    messagesPublished: 3210,
    deliveries: 6540,
    subscriptionsCurrent: 5,
    subscriptionsCreated: 7,
    subscriptionsDeleted: 2,
  },
  topicMetrics: [
    {
      topicId: "topic-1",
      publishRate: 8.5,
      deliveryRate: 19.25,
      messagesPublished: 1000,
      deliveries: 2500,
      subscriptionsCurrent: 3,
      subscriptionsCreated: 4,
      subscriptionsDeleted: 1,
      updatedAt: 1_700_000_360_000,
    },
  ],
  timeRange: {
    from: 1_700_000_000_000,
    to: 1_700_000_360_000,
  },
  updatedAt: 1_700_000_360_000,
};

describe("loadTopicMetricsOverviewState", () => {
  test("returns loaded topic overview data", async () => {
    const calls: string[] = [];

    const result = await loadTopicMetricsOverviewState({
      topicOverview: async () => {
        calls.push("topicOverview");
        return overview;
      },
    });

    expect(calls).toEqual(["topicOverview"]);
    expect(result).toEqual({
      status: "loaded",
      overview,
    });
  });

  test("returns unavailable when telemetry storage is unavailable", async () => {
    const result = await loadTopicMetricsOverviewState({
      topicOverview: async () => {
        throw new Error("503: telemetry storage unavailable");
      },
    });

    expect(result).toEqual({
      status: "unavailable",
    });
  });

  test("returns an error state for ordinary failures", async () => {
    const result = await loadTopicMetricsOverviewState({
      topicOverview: async () => {
        throw new Error("boom");
      },
    });

    expect(result).toEqual({
      status: "error",
      message: "boom",
    });
  });
});

describe("buildTopicSelectorOptions", () => {
  test("includes telemetry topics that are absent from the managed topic list", () => {
    const topics: Topic[] = [
      {
        topicId: "topic-1",
        topicName: "Orders",
        createdAt: "2026-07-05T00:00:00Z",
      },
    ];

    const options = buildTopicSelectorOptions(topics, [
      overview.topicMetrics[0],
      {
        topicId: "topic-2",
        publishRate: 2.5,
        deliveryRate: 5,
        messagesPublished: 100,
        deliveries: 200,
        subscriptionsCurrent: 1,
        subscriptionsCreated: 1,
        subscriptionsDeleted: 0,
        updatedAt: 1_700_000_720_000,
      },
    ]);

    expect(options).toEqual([
      { value: "topic-1", label: "Orders" },
      { value: "topic-2", label: "topic-2" },
    ]);
  });
});

describe("TopicMetricsTelemetryDisabledState", () => {
  test("renders the telemetry disabled guidance", () => {
    const markup = renderToStaticMarkup(<TopicMetricsTelemetryDisabledState />);

    expect(markup).toContain("Telemetry is not enabled");
    expect(markup).toContain("Pub/Sub management still works.");
  });
});

describe("TopicMetricsPanelContent", () => {
  test("renders deliveries summary and last updated table values", () => {
    const markup = renderToStaticMarkup(
      <TopicMetricsPanelContent
        overview={overview}
        timeRange="1h"
        selectedTopicId="topic-1"
        selectedTopicLabel="Orders"
        topicOptions={[{ value: "topic-1", label: "Orders" }]}
        topicNames={new Map([["topic-1", "Orders"]])}
        onRefresh={() => {}}
        onTimeRangeChange={() => {}}
        onTopicChange={() => {}}
        chartRefreshKey={0}
      />,
    );

    expect(markup).toContain("Deliveries");
    // Counters are exact and digit-grouped rather than rounded to "6.54K" — a
    // rounded counter reads as a claim the server never made.
    expect(markup).toContain(formatCount(overview.systemMetrics.deliveries));
    expect(markup).toContain("Last updated");
    expect(markup).toContain(formatClock(overview.topicMetrics[0].updatedAt));
  });

  test("renders unknown active subscriptions distinctly from zero", () => {
    const unknownOverview: TopicMetricsOverview = {
      ...overview,
      systemMetrics: {
        ...overview.systemMetrics,
        subscriptionsCurrent: null,
      },
      topicMetrics: [
        {
          ...overview.topicMetrics[0],
          subscriptionsCurrent: null,
        },
      ],
    };

    const markup = renderToStaticMarkup(
      <TopicMetricsPanelContent
        overview={unknownOverview}
        timeRange="1h"
        selectedTopicId="topic-1"
        selectedTopicLabel="Orders"
        topicOptions={[{ value: "topic-1", label: "Orders" }]}
        topicNames={new Map([["topic-1", "Orders"]])}
        onRefresh={() => {}}
        onTimeRangeChange={() => {}}
        onTopicChange={() => {}}
        chartRefreshKey={0}
      />,
    );

    expect(markup).toContain("Unknown");
  });
});
