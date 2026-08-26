import { describe, expect, test } from "bun:test";
import { renderToStaticMarkup } from "react-dom/server";

import type { TopicMetricsOverview } from "@/lib/types";
import { TopicDetail } from "./topic-detail";

const overview: TopicMetricsOverview = {
  systemMetrics: {
    publishRate: 1,
    deliveryRate: 1,
    messagesPublished: 1,
    publishedBytes: 12,
    deliveries: 1,
    deliveryFailures: 0,
    subscriptionsCurrent: 0,
    subscriptionsCreated: 0,
    subscriptionsDeleted: 0,
    topicsExist: 1,
    operationSummaries: null,
    storageOperationSummaries: null,
  },
  topicMetrics: [
    {
      topicId: "topic-1",
      publishRate: 1,
      deliveryRate: 1,
      messagesPublished: 1,
      deliveries: 1,
      subscriptionsCurrent: 0,
      subscriptionsCreated: 0,
      subscriptionsDeleted: 0,
      updatedAt: 1_700_000_000_000,
    },
  ],
  timeRange: { from: 1_699_999_940_000, to: 1_700_000_000_000 },
  effectiveTimeRange: { from: 1_699_999_940_000, to: 1_700_000_000_000 },
  resolution: "raw",
  updatedAt: 1_700_000_000_000,
};

describe("TopicDetail", () => {
  test("mounts active TopicTelemetry and removes the legacy inline plot", () => {
    const markup = renderToStaticMarkup(
      <TopicDetail
        topic={{
          topicId: "topic-1",
          topicName: "Orders",
          createdAt: "2026-08-26T00:00:00Z",
          subscriptions: [],
        }}
        queues={[]}
        metrics={{ status: "ready", overview }}
        metricsKey={0}
        onChanged={() => {}}
      />,
    );

    expect(markup).toContain("Publish and delivery outcomes");
    expect(markup).toContain("Active subscriptions");
    expect(markup).toContain("This node");
    expect(markup).not.toContain("Publish vs delivery");
  });
});
