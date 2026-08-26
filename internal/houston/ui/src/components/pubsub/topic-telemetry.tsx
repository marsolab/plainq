"use client";

import * as React from "react";

import { SeriesLegend, type SeriesSpec } from "@/components/metrics/lifecycle";
import { Segmented } from "@/components/metrics/segmented";
import {
  describeSeries,
  SeriesChart,
  SeriesTable,
  type ChartRow,
} from "@/components/metrics/series-chart";
import { ScopeBadge } from "@/components/ui/badge";
import { EmptyState } from "@/components/ui/empty-state";
import { InlineAlert } from "@/components/ui/feedback";
import { Panel, PanelBody, PanelTitleBar } from "@/components/ui/panel";
import { Skeleton } from "@/components/ui/skeleton";
import { Field, Micro } from "@/components/ui/value";
import { api } from "@/lib/api-client";
import { formatCount, formatDuration, formatRate } from "@/lib/format";
import { transformTopicSeries } from "@/lib/metrics";
import type { TopicSeriesResponse, TopicSubscriptionsResponse } from "@/lib/types";
import {
  beginTopicTelemetryLoad,
  lastGoodFor,
  loadTopicTelemetry,
  type SeriesLoad,
  type TopicTelemetryApi,
  type TopicTelemetryLoads,
  type TopicTelemetryRange,
} from "./telemetry";

export const TOPIC_TELEMETRY_RANGES: ReadonlyArray<{
  value: TopicTelemetryRange;
  label: TopicTelemetryRange;
}> = [
  { value: "5m", label: "5m" },
  { value: "15m", label: "15m" },
  { value: "1h", label: "1h" },
  { value: "6h", label: "6h" },
  { value: "24h", label: "24h" },
];

export const DELIVERY_SERIES: readonly SeriesSpec[] = [
  { key: "publish", label: "Published", tone: "send", interpolation: "linear" },
  { key: "delivery", label: "Delivered", tone: "receive", interpolation: "linear" },
  {
    key: "failure",
    label: "Failed delivery",
    tone: "retry",
    interpolation: "linear",
    dashed: true,
  },
];

export const SUBSCRIPTION_SERIES: readonly SeriesSpec[] = [
  {
    key: "active",
    label: "Active subscriptions",
    tone: "acknowledge",
    interpolation: "stepAfter",
  },
];

const DELIVERY_KEYS = {
  plainq_topic_publish_rate: "publish",
  plainq_topic_delivery_rate: "delivery",
  plainq_topic_delivery_failure_rate: "failure",
} as const;

const SUBSCRIPTION_KEYS = {
  plainq_topic_subscriptions_current: "active",
} as const;

const VIEW_OPTIONS = [
  { value: "chart", label: "Chart" },
  { value: "table", label: "Table" },
] as const;

type ViewMode = (typeof VIEW_OPTIONS)[number]["value"];

interface TopicTelemetryProps {
  topicId: string;
  metricsKey: number;
  telemetryEnabled: boolean;
  metricsApi?: TopicTelemetryApi;
}

const INITIAL_LOADS: TopicTelemetryLoads = {
  rates: { status: "loading" },
  subscriptions: { status: "loading" },
};

/** Active topic telemetry, with one range and two independently retained reads. */
export function TopicTelemetry({
  topicId,
  metricsKey,
  telemetryEnabled,
  metricsApi = api.metrics,
}: TopicTelemetryProps) {
  const [range, setRange] = React.useState<TopicTelemetryRange>("1h");
  const [loads, setLoads] = React.useState<TopicTelemetryLoads>(INITIAL_LOADS);
  const [deliveryView, setDeliveryView] = React.useState<ViewMode>("chart");
  const [subscriptionView, setSubscriptionView] = React.useState<ViewMode>("chart");
  const loadsRef = React.useRef(loads);
  const identityRef = React.useRef<{ topicId: string; range: TopicTelemetryRange } | null>(
    null,
  );

  const commitLoads = React.useCallback((next: TopicTelemetryLoads) => {
    loadsRef.current = next;
    setLoads(next);
  }, []);

  React.useEffect(() => {
    let cancelled = false;
    const sameSubjectAndRange =
      identityRef.current?.topicId === topicId && identityRef.current.range === range;
    const current = sameSubjectAndRange ? loadsRef.current : INITIAL_LOADS;
    identityRef.current = { topicId, range };

    if (!telemetryEnabled) {
      const rates = lastGoodFor(current.rates, range);
      const subscriptions = lastGoodFor(current.subscriptions, range);
      commitLoads({
        rates: rates
          ? { status: "unavailable", lastGood: rates }
          : { status: "unavailable" },
        subscriptions: subscriptions
          ? { status: "unavailable", lastGood: subscriptions }
          : { status: "unavailable" },
      });
      return;
    }

    const pending = beginTopicTelemetryLoad(current, range);
    commitLoads(pending);

    const requests = loadTopicTelemetry(metricsApi, topicId, range, {
      rates: lastGoodFor(current.rates, range),
      subscriptions: lastGoodFor(current.subscriptions, range),
    });

    void requests.rates.then((rates) => {
      if (!cancelled) commitLoads({ ...loadsRef.current, rates });
    });
    void requests.subscriptions.then((subscriptions) => {
      if (!cancelled) commitLoads({ ...loadsRef.current, subscriptions });
    });

    return () => {
      cancelled = true;
    };
  }, [commitLoads, metricsApi, metricsKey, range, telemetryEnabled, topicId]);

  return (
    <TopicTelemetryView
      range={range}
      loads={loads}
      deliveryView={deliveryView}
      subscriptionView={subscriptionView}
      onRangeChange={setRange}
      onDeliveryViewChange={setDeliveryView}
      onSubscriptionViewChange={setSubscriptionView}
    />
  );
}

export function TopicTelemetryView({
  range,
  loads,
  deliveryView,
  subscriptionView,
  onRangeChange,
  onDeliveryViewChange,
  onSubscriptionViewChange,
}: {
  range: TopicTelemetryRange;
  loads: TopicTelemetryLoads;
  deliveryView: ViewMode;
  subscriptionView: ViewMode;
  onRangeChange: (range: TopicTelemetryRange) => void;
  onDeliveryViewChange: (view: ViewMode) => void;
  onSubscriptionViewChange: (view: ViewMode) => void;
}) {
  return (
    <section aria-label="Topic telemetry" className="flex flex-col gap-3">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="flex items-center gap-2">
          <span className="caption">Telemetry scope</span>
          <ScopeBadge tone="neutral">This node</ScopeBadge>
        </div>
        <Segmented
          label="Topic telemetry range"
          value={range}
          options={TOPIC_TELEMETRY_RANGES}
          onChange={onRangeChange}
        />
      </div>

      <DeliveryPanel
        range={range}
        load={loads.rates}
        view={deliveryView}
        onViewChange={onDeliveryViewChange}
      />
      <SubscriptionPanel
        range={range}
        load={loads.subscriptions}
        view={subscriptionView}
        onViewChange={onSubscriptionViewChange}
      />
    </section>
  );
}

function DeliveryPanel({
  range,
  load,
  view,
  onViewChange,
}: {
  range: TopicTelemetryRange;
  load: SeriesLoad<TopicSeriesResponse>;
  view: ViewMode;
  onViewChange: (view: ViewMode) => void;
}) {
  const retained = lastGoodFor(load, range);
  const rows = retained ? transformTopicSeries(retained.data, DELIVERY_KEYS) : [];
  const summary = describeSeries(rows, DELIVERY_SERIES, range, formatRate);

  return (
    <Panel>
      <PanelTitleBar
        title="Publish and delivery outcomes"
        description="Published messages, successful deliveries, and failed delivery attempts."
        action={
          retained && rows.length > 0 ? (
            <Segmented
              label="Publish and delivery outcomes view"
              value={view}
              options={VIEW_OPTIONS}
              onChange={onViewChange}
              variant="text"
            />
          ) : undefined
        }
      />
      <PanelBody className="flex flex-col gap-3 px-4 py-3.5">
        <LoadNotice load={load} hasData={Boolean(retained)} />
        {retained ? (
          rows.length > 0 ? (
            <SeriesContent
              title="Publish and delivery outcomes"
              data={rows}
              series={DELIVERY_SERIES}
              response={retained.data}
              view={view}
              summary={summary}
              formatValue={formatRate}
            />
          ) : (
            <NoSamples />
          )
        ) : (
          <NoRetainedData load={load} />
        )}
      </PanelBody>
    </Panel>
  );
}

function SubscriptionPanel({
  range,
  load,
  view,
  onViewChange,
}: {
  range: TopicTelemetryRange;
  load: SeriesLoad<TopicSubscriptionsResponse>;
  view: ViewMode;
  onViewChange: (view: ViewMode) => void;
}) {
  const retained = lastGoodFor(load, range);
  const rows = retained ? transformTopicSeries(retained.data, SUBSCRIPTION_KEYS) : [];
  const summary = describeSeries(rows, SUBSCRIPTION_SERIES, range, formatCount);

  return (
    <Panel>
      <PanelTitleBar
        title="Active subscriptions"
        description="The subscription count after each recorded change."
        action={
          retained && rows.length > 0 ? (
            <Segmented
              label="Active subscriptions view"
              value={view}
              options={VIEW_OPTIONS}
              onChange={onViewChange}
              variant="text"
            />
          ) : undefined
        }
      />

      {retained ? <SubscriptionSummary data={retained.data} /> : null}

      <PanelBody className="flex flex-col gap-3 px-4 py-3.5">
        <LoadNotice load={load} hasData={Boolean(retained)} />
        {retained ? (
          rows.length > 0 ? (
            <SeriesContent
              title="Active subscriptions"
              data={rows}
              series={SUBSCRIPTION_SERIES}
              response={retained.data}
              view={view}
              summary={summary}
              formatValue={formatCount}
            />
          ) : (
            <NoSamples />
          )
        ) : (
          <NoRetainedData load={load} />
        )}
      </PanelBody>
    </Panel>
  );
}

function SubscriptionSummary({ data }: { data: TopicSubscriptionsResponse }) {
  const values = [
    { label: "Current", value: data.summary.subscriptionsCurrent },
    { label: "Created", value: data.summary.createdDuringWindow },
    { label: "Removed", value: data.summary.removedDuringWindow },
  ];

  return (
    <div className="grid grid-cols-3 border-b border-border">
      {values.map(({ label, value }, index) => (
        <Field
          key={label}
          label={label}
          className={index > 0 ? "border-l border-border px-4 py-2.5" : "px-4 py-2.5"}
        >
          {value === null ? (
            <span className="text-subtle">Unavailable</span>
          ) : (
            formatCount(value)
          )}
        </Field>
      ))}
    </div>
  );
}

function SeriesContent({
  title,
  data,
  series,
  response,
  view,
  summary,
  formatValue,
}: {
  title: string;
  data: ReadonlyArray<ChartRow>;
  series: readonly SeriesSpec[];
  response: TopicSeriesResponse;
  view: ViewMode;
  summary: string;
  formatValue: (value: number) => string;
}) {
  return (
    <>
      <div role="group" aria-label={`${title} legend`}>
        <SeriesLegend series={series} />
      </div>
      <p className="sr-only">{summary}</p>
      {view === "chart" ? (
        <SeriesChart
          data={data}
          series={series}
          height={220}
          formatValue={formatValue}
          summary={summary}
        />
      ) : (
        <SeriesTable data={data} series={series} formatValue={formatValue} />
      )}
      <Micro className="text-[10px]">
        {data.length} {data.length === 1 ? "sample" : "samples"} · Sample interval{" "}
        {formatDuration(response.sampleIntervalMs / 1000)}
      </Micro>
    </>
  );
}

function LoadNotice<T>({ load, hasData }: { load: SeriesLoad<T>; hasData: boolean }) {
  if (!hasData) return null;

  switch (load.status) {
    case "refreshing":
      return (
        <div role="status" className="flex items-center gap-2 text-xs text-muted-foreground">
          <ScopeBadge>Stale</ScopeBadge>
          Refreshing this range…
        </div>
      );
    case "unavailable":
      return (
        <InlineAlert tone="warning">
          <span className="inline-flex flex-wrap items-center gap-2">
            <ScopeBadge>Stale</ScopeBadge>
            {telemetryUnavailableGuidance()}
          </span>
        </InlineAlert>
      );
    case "error":
      return (
        <InlineAlert>
          <span className="inline-flex flex-wrap items-center gap-2">
            <ScopeBadge>Stale</ScopeBadge>
            {load.message}. Showing the last good data for this range.
          </span>
        </InlineAlert>
      );
    default:
      return null;
  }
}

function NoRetainedData<T>({ load }: { load: SeriesLoad<T> }) {
  switch (load.status) {
    case "loading":
      return <Skeleton className="h-[220px] w-full" />;
    case "unavailable":
      return (
        <EmptyState
          title="Telemetry is unavailable"
          description={telemetryUnavailableGuidance()}
          className="py-10"
        />
      );
    case "error":
      return (
        <EmptyState
          title="Telemetry could not be loaded"
          description={load.message}
          className="py-10"
        />
      );
    default:
      return <Skeleton className="h-[220px] w-full" />;
  }
}

function NoSamples() {
  return (
    <EmptyState
      title="No samples in this range"
      description="The server returned no measured values. This is not the same as a measured zero."
      className="py-10"
    />
  );
}

function telemetryUnavailableGuidance() {
  return "Telemetry is disabled or unavailable on this server. Start PlainQ with --telemetry.enable and retry.";
}

export type { ViewMode };
