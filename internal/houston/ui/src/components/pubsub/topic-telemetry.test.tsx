import { beforeEach, describe, expect, mock, test } from "bun:test";
import type { ReactNode } from "react";
import { act, create, type ReactTestInstance, type ReactTestRenderer } from "react-test-renderer";
import { renderToStaticMarkup } from "react-dom/server";

import type {
  MetricSeriesResponse,
  TopicSeriesResponse,
  TopicSubscriptionsResponse,
} from "@/lib/types";
import type { TopicTelemetryLoads } from "./telemetry";

const renderedLines: Array<Record<string, unknown>> = [];

function PassThrough({ children }: { children?: ReactNode }) {
  return <>{children}</>;
}

mock.module("recharts", () => ({
  CartesianGrid: () => null,
  Line: (props: Record<string, unknown>) => {
    renderedLines.push(props);
    return null;
  },
  LineChart: PassThrough,
  ResponsiveContainer: PassThrough,
  Tooltip: () => null,
  XAxis: () => null,
  YAxis: () => null,
}));

mock.module("../metrics/chart-tokens", () => ({
  useChartTokens: () => ({
    send: "blue",
    receive: "green",
    acknowledge: "purple",
    retry: "orange",
    grid: "gray",
    axis: "gray",
    label: "gray",
  }),
}));

const {
  DELIVERY_SERIES,
  SUBSCRIPTION_SERIES,
  TOPIC_TELEMETRY_RANGES,
  TopicTelemetry,
  TopicTelemetryView,
} = await import("./topic-telemetry");

declare global {
  var IS_REACT_ACT_ENVIRONMENT: boolean | undefined;
}

globalThis.IS_REACT_ACT_ENVIRONMENT = true;

beforeEach(() => {
  renderedLines.length = 0;
});

const timeRange = { from: 1_700_000_000_000, to: 1_700_000_060_000 };

function metric(
  metricName: string,
  value: number,
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
        value,
        source: "observed",
        count: 1,
      },
    ],
  };
}

function rates(values = { publish: 4, delivery: 3, failure: 1 }): TopicSeriesResponse {
  return {
    topicId: "topic-1",
    metrics: [
      metric("plainq_topic_publish_rate", values.publish),
      metric("plainq_topic_delivery_rate", values.delivery),
      metric("plainq_topic_delivery_failure_rate", values.failure),
    ],
    timeRange,
    effectiveTimeRange: timeRange,
    resolution: "raw",
    sampleIntervalMs: 10_000,
    generatedAt: timeRange.to,
  };
}

function subscriptions(
  summary: TopicSubscriptionsResponse["summary"] = {
    subscriptionsCurrent: 2,
    createdDuringWindow: 1,
    removedDuringWindow: 0,
    avgCreateRate: 0.1,
    avgRemoveRate: 0,
    maxCreateRate: 0.1,
    maxRemoveRate: 0,
    updatedAt: timeRange.to,
  },
): TopicSubscriptionsResponse {
  return {
    ...rates(),
    metrics: [metric("plainq_topic_subscriptions_current", 2, "stepAfter")],
    summary,
  };
}

function readyLoads(
  rateData = rates(),
  subscriptionData = subscriptions(),
): TopicTelemetryLoads {
  return {
    rates: { status: "ready", data: rateData, range: "1h" },
    subscriptions: { status: "ready", data: subscriptionData, range: "1h" },
  };
}

describe("topic telemetry series", () => {
  test("uses the stable delivery and subscription graph contract", () => {
    expect(TOPIC_TELEMETRY_RANGES.map(({ value }) => value)).toEqual([
      "5m",
      "15m",
      "1h",
      "6h",
      "24h",
    ]);
    expect(DELIVERY_SERIES).toEqual([
      { key: "publish", label: "Published", tone: "send", interpolation: "linear" },
      { key: "delivery", label: "Delivered", tone: "receive", interpolation: "linear" },
      {
        key: "failure",
        label: "Failed delivery",
        tone: "retry",
        interpolation: "linear",
        dashed: true,
      },
    ]);
    expect(SUBSCRIPTION_SERIES).toEqual([
      {
        key: "active",
        label: "Active subscriptions",
        tone: "acknowledge",
        interpolation: "stepAfter",
      },
    ]);
  });

  test("renders the active delivery and subscription line styles", () => {
    renderToStaticMarkup(
      <TopicTelemetryView
        range="1h"
        loads={readyLoads()}
        deliveryView="chart"
        subscriptionView="chart"
        onRangeChange={() => {}}
        onDeliveryViewChange={() => {}}
        onSubscriptionViewChange={() => {}}
      />,
    );

    expect(
      renderedLines.map(({ dataKey, type, stroke, strokeDasharray, connectNulls }) => ({
        dataKey,
        type,
        stroke,
        strokeDasharray,
        connectNulls,
      })),
    ).toEqual([
      {
        dataKey: "publish",
        type: "linear",
        stroke: "blue",
        strokeDasharray: undefined,
        connectNulls: false,
      },
      {
        dataKey: "delivery",
        type: "linear",
        stroke: "green",
        strokeDasharray: undefined,
        connectNulls: false,
      },
      {
        dataKey: "failure",
        type: "linear",
        stroke: "orange",
        strokeDasharray: "5 3",
        connectNulls: false,
      },
      {
        dataKey: "active",
        type: "stepAfter",
        stroke: "purple",
        strokeDasharray: undefined,
        connectNulls: false,
      },
    ]);
  });
});

describe("TopicTelemetryView", () => {
  test("renders ready tables, summaries, scope, labelled legends, and descriptions", () => {
    const markup = renderToStaticMarkup(
      <TopicTelemetryView
        range="1h"
        loads={readyLoads()}
        deliveryView="table"
        subscriptionView="table"
        onRangeChange={() => {}}
        onDeliveryViewChange={() => {}}
        onSubscriptionViewChange={() => {}}
      />,
    );

    expect(markup).toContain("Publish and delivery outcomes");
    expect(markup).toContain("Active subscriptions");
    expect(markup).toContain("This node");
    expect(markup).toContain("Published");
    expect(markup).toContain("Delivered");
    expect(markup).toContain("Failed delivery");
    expect(markup).toContain('aria-label="Publish and delivery outcomes legend"');
    expect(markup).toContain('aria-label="Active subscriptions legend"');
    expect(markup).toContain("1h window, 1 samples");
    expect(markup).toContain("Current");
    expect(markup).toContain("Created");
    expect(markup).toContain("Removed");
    expect(markup).toContain(">2<");
    expect(markup).toContain(">1<");
    expect(markup).toContain(">0<");
    expect(markup).toContain("Sample interval 10 s");
    expect(markup.match(/aria-label="[^"]+ view"/g)).toHaveLength(2);
  });

  test("renders null subscription summaries as unavailable", () => {
    const unavailableSummary = subscriptions({
      subscriptionsCurrent: null,
      createdDuringWindow: null,
      removedDuringWindow: null,
      avgCreateRate: null,
      avgRemoveRate: null,
      maxCreateRate: null,
      maxRemoveRate: null,
      updatedAt: null,
    });

    const markup = renderToStaticMarkup(
      <TopicTelemetryView
        range="1h"
        loads={readyLoads(rates(), unavailableSummary)}
        deliveryView="chart"
        subscriptionView="chart"
        onRangeChange={() => {}}
        onDeliveryViewChange={() => {}}
        onSubscriptionViewChange={() => {}}
      />,
    );

    expect(markup.match(/Unavailable/g)?.length).toBeGreaterThanOrEqual(3);
  });

  test("distinguishes a true empty range from measured zero", () => {
    const emptyRates: TopicSeriesResponse = {
      ...rates(),
      metrics: rates().metrics.map((series) => ({
        ...series,
        samples: {
          ...series.samples,
          expectedPointCount: 0,
          returnedPointCount: 0,
          firstSampleAt: null,
          lastSampleAt: null,
          complete: false,
        },
        dataPoints: [],
      })),
      effectiveTimeRange: { from: timeRange.to, to: timeRange.to },
    };

    const emptyMarkup = renderToStaticMarkup(
      <TopicTelemetryView
        range="1h"
        loads={readyLoads(emptyRates)}
        deliveryView="table"
        subscriptionView="table"
        onRangeChange={() => {}}
        onDeliveryViewChange={() => {}}
        onSubscriptionViewChange={() => {}}
      />,
    );
    const zeroMarkup = renderToStaticMarkup(
      <TopicTelemetryView
        range="1h"
        loads={readyLoads(rates({ publish: 0, delivery: 0, failure: 0 }))}
        deliveryView="table"
        subscriptionView="table"
        onRangeChange={() => {}}
        onDeliveryViewChange={() => {}}
        onSubscriptionViewChange={() => {}}
      />,
    );

    expect(emptyMarkup).toContain("No samples in this range");
    expect(zeroMarkup).not.toContain("No samples in this range");
    expect(zeroMarkup.match(/0\/s/g)?.length).toBeGreaterThanOrEqual(3);
  });

  test("shows loading skeletons and an initial error with no invented data", () => {
    const loadingMarkup = renderToStaticMarkup(
      <TopicTelemetryView
        range="1h"
        loads={{
          rates: { status: "loading" },
          subscriptions: { status: "loading" },
        }}
        deliveryView="chart"
        subscriptionView="chart"
        onRangeChange={() => {}}
        onDeliveryViewChange={() => {}}
        onSubscriptionViewChange={() => {}}
      />,
    );
    const errorMarkup = renderToStaticMarkup(
      <TopicTelemetryView
        range="1h"
        loads={{
          rates: { status: "error", message: "rates failed" },
          subscriptions: { status: "error", message: "subscriptions failed" },
        }}
        deliveryView="chart"
        subscriptionView="chart"
        onRangeChange={() => {}}
        onDeliveryViewChange={() => {}}
        onSubscriptionViewChange={() => {}}
      />,
    );

    expect(loadingMarkup.match(/data-slot="skeleton"/g)).toHaveLength(2);
    expect(errorMarkup).toContain("rates failed");
    expect(errorMarkup).toContain("subscriptions failed");
    expect(errorMarkup).not.toContain("0/s");
  });

  test("keeps same-range refresh/error/unavailable data visibly stale", () => {
    const lastGoodRates = { data: rates(), range: "1h" as const };
    const lastGoodSubscriptions = { data: subscriptions(), range: "1h" as const };
    const markup = renderToStaticMarkup(
      <TopicTelemetryView
        range="1h"
        loads={{
          rates: {
            status: "unavailable",
            lastGood: lastGoodRates,
          },
          subscriptions: {
            status: "error",
            message: "subscription refresh failed",
            lastGood: lastGoodSubscriptions,
          },
        }}
        deliveryView="table"
        subscriptionView="table"
        onRangeChange={() => {}}
        onDeliveryViewChange={() => {}}
        onSubscriptionViewChange={() => {}}
      />,
    );

    expect(markup.match(/Stale/g)).toHaveLength(2);
    expect(markup).toContain("--telemetry.enable");
    expect(markup).toContain("subscription refresh failed");
    expect(markup).toContain("4.00/s");
    expect(markup).toContain(">2<");
  });
});

describe("TopicTelemetry", () => {
  test("telemetry disabled before initial load skips both API calls", async () => {
    const calls: string[] = [];
    let renderer: ReactTestRenderer | undefined;
    const restoreConsoleError = ignoreReactTestRendererDeprecation();

    try {
      await act(async () => {
        renderer = create(
          <TopicTelemetry
            topicId="topic-1"
            metricsKey={0}
            telemetryEnabled={false}
            metricsApi={{
              topicRates: async () => {
                calls.push("rates");
                return rates();
              },
              topicSubscriptions: async () => {
                calls.push("subscriptions");
                return subscriptions();
              },
            }}
          />,
        );
      });

      expect(calls).toEqual([]);
      expect(JSON.stringify(renderer?.toJSON())).toContain("--telemetry.enable");
    } finally {
      await act(async () => {
        renderer?.unmount();
      });
      restoreConsoleError();
    }
  });

  test("one shared selector changes both requests across every stable range", async () => {
    const calls: string[] = [];
    const metricsApi = {
      topicRates: async (topicId: string, range = "1h") => {
        calls.push(`rates:${topicId}:${range}`);
        return rates();
      },
      topicSubscriptions: async (topicId: string, range = "1h") => {
        calls.push(`subscriptions:${topicId}:${range}`);
        return subscriptions();
      },
    };
    let renderer: ReactTestRenderer | undefined;
    const restoreConsoleError = ignoreReactTestRendererDeprecation();

    try {
      await act(async () => {
        renderer = create(
          <TopicTelemetry
            topicId="topic-1"
            metricsKey={0}
            telemetryEnabled
            metricsApi={metricsApi}
          />,
        );
      });

      for (const range of ["5m", "15m", "6h", "24h"] as const) {
        const button = findButton(renderer!, range);
        await act(async () => {
          button.props.onClick();
        });
      }

      expect(calls).toEqual(
        ["1h", "5m", "15m", "6h", "24h"].flatMap((range) => [
          `rates:topic-1:${range}`,
          `subscriptions:topic-1:${range}`,
        ]),
      );
    } finally {
      await act(async () => {
        renderer?.unmount();
      });
      restoreConsoleError();
    }
  });

  test("settles one panel while the other endpoint is still pending", async () => {
    const pendingRates = deferred<TopicSeriesResponse>();
    const pendingSubscriptions = deferred<TopicSubscriptionsResponse>();
    let renderer: ReactTestRenderer | undefined;
    const restoreConsoleError = ignoreReactTestRendererDeprecation();

    try {
      await act(async () => {
        renderer = create(
          <TopicTelemetry
            topicId="topic-1"
            metricsKey={0}
            telemetryEnabled
            metricsApi={{
              topicRates: async () => pendingRates.promise,
              topicSubscriptions: async () => pendingSubscriptions.promise,
            }}
          />,
        );
      });

      await act(async () => {
        pendingRates.resolve(rates());
      });

      const ratesOnly = JSON.stringify(renderer?.toJSON());
      expect(ratesOnly).toContain("Publish and delivery outcomes view");
      expect(ratesOnly).not.toContain("Active subscriptions view");
      const panels = renderer?.root.findAllByProps({ "data-slot": "panel" }) ?? [];
      expect(panels[1]?.findAllByProps({ "data-slot": "skeleton" })).toHaveLength(1);

      await act(async () => {
        pendingSubscriptions.resolve(subscriptions());
      });

      const bothReady = JSON.stringify(renderer?.toJSON());
      expect(bothReady).toContain("Publish and delivery outcomes view");
      expect(bothReady).toContain("Active subscriptions view");
    } finally {
      await act(async () => {
        renderer?.unmount();
      });
      restoreConsoleError();
    }
  });

  test("a same-range metricsKey refresh keeps old data stale until the result lands", async () => {
    const nextRates = deferred<TopicSeriesResponse>();
    const nextSubscriptions = deferred<TopicSubscriptionsResponse>();
    let rateCalls = 0;
    let subscriptionCalls = 0;
    const metricsApi = {
      topicRates: async () => {
        rateCalls += 1;
        return rateCalls === 1 ? rates() : nextRates.promise;
      },
      topicSubscriptions: async () => {
        subscriptionCalls += 1;
        return subscriptionCalls === 1 ? subscriptions() : nextSubscriptions.promise;
      },
    };
    let renderer: ReactTestRenderer | undefined;
    const restoreConsoleError = ignoreReactTestRendererDeprecation();

    try {
      await act(async () => {
        renderer = create(
          <TopicTelemetry
            topicId="topic-1"
            metricsKey={0}
            telemetryEnabled
            metricsApi={metricsApi}
          />,
        );
      });

      act(() => {
        renderer?.update(
          <TopicTelemetry
            topicId="topic-1"
            metricsKey={1}
            telemetryEnabled
            metricsApi={metricsApi}
          />,
        );
      });

      const refreshing = JSON.stringify(renderer?.toJSON());
      expect(refreshing.match(/Stale/g)).toHaveLength(2);

      await act(async () => {
        nextRates.reject(new Error("rates refresh failed"));
        nextSubscriptions.resolve(subscriptions());
      });

      const landed = JSON.stringify(renderer?.toJSON());
      expect(landed).toContain("rates refresh failed");
      expect(landed).toContain("Stale");
      expect(landed).toContain("Active subscriptions");
    } finally {
      await act(async () => {
        renderer?.unmount();
      });
      restoreConsoleError();
    }
  });

  test("a range change never labels prior-range data as the new range", async () => {
    const nextRates = deferred<TopicSeriesResponse>();
    const nextSubscriptions = deferred<TopicSubscriptionsResponse>();
    let rateCalls = 0;
    let subscriptionCalls = 0;
    const metricsApi = {
      topicRates: async () => {
        rateCalls += 1;
        return rateCalls === 1 ? rates() : nextRates.promise;
      },
      topicSubscriptions: async () => {
        subscriptionCalls += 1;
        return subscriptionCalls === 1 ? subscriptions() : nextSubscriptions.promise;
      },
    };
    let renderer: ReactTestRenderer | undefined;
    const restoreConsoleError = ignoreReactTestRendererDeprecation();

    try {
      await act(async () => {
        renderer = create(
          <TopicTelemetry
            topicId="topic-1"
            metricsKey={0}
            telemetryEnabled
            metricsApi={metricsApi}
          />,
        );
      });

      expect(JSON.stringify(renderer?.toJSON())).toContain("1h window");

      await act(async () => {
        findButton(renderer!, "24h").props.onClick();
      });

      const pending = JSON.stringify(renderer?.toJSON());
      expect(findButton(renderer!, "24h").props["aria-pressed"]).toBe(true);
      expect(pending).not.toContain("1h window");
      expect(pending).not.toContain("4.00/s");
      expect(pending).not.toContain("Publish and delivery outcomes view");
      expect(pending).not.toContain("Active subscriptions view");
    } finally {
      await act(async () => {
        renderer?.unmount();
      });
      restoreConsoleError();
    }
  });

  test("chart and table toggles expose the same readings", async () => {
    let renderer: ReactTestRenderer | undefined;
    const restoreConsoleError = ignoreReactTestRendererDeprecation();

    try {
      await act(async () => {
        renderer = create(
          <TopicTelemetry
            topicId="topic-1"
            metricsKey={0}
            telemetryEnabled
            metricsApi={{
              topicRates: async () => rates(),
              topicSubscriptions: async () => subscriptions(),
            }}
          />,
        );
      });

      const viewGroups = renderer!.root.findAll(
        (node) => node.props.role === "group" && String(node.props["aria-label"]).endsWith(" view"),
      );
      expect(viewGroups).toHaveLength(2);

      await act(async () => {
        for (const group of viewGroups) {
          const table = group.findAllByType("button").find((button) => button.children.includes("Table"));
          table?.props.onClick();
        }
      });

      const tableMarkup = JSON.stringify(renderer?.toJSON());
      expect(tableMarkup.match(/Sample/g)?.length).toBeGreaterThanOrEqual(2);
      expect(tableMarkup).toContain("4.00/s");
      expect(tableMarkup).toContain('"children":["2"]');
    } finally {
      await act(async () => {
        renderer?.unmount();
      });
      restoreConsoleError();
    }
  });
});

function findButton(renderer: ReactTestRenderer, label: string): ReactTestInstance {
  const button = renderer.root
    .findAllByType("button")
    .find((candidate) => candidate.children.includes(label));
  if (!button) throw new Error(`Button not found: ${label}`);
  return button;
}

function deferred<T>() {
  let resolve!: (value: T) => void;
  let reject!: (reason?: unknown) => void;
  const promise = new Promise<T>((resolvePromise, rejectPromise) => {
    resolve = resolvePromise;
    reject = rejectPromise;
  });
  return { promise, resolve, reject };
}

function ignoreReactTestRendererDeprecation() {
  const originalError = console.error;

  console.error = (...args: unknown[]) => {
    const message = String(args[0] ?? "");
    if (message.includes("react-test-renderer is deprecated")) return;
    originalError(...args);
  };

  return () => {
    console.error = originalError;
  };
}
