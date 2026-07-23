"use client";

import * as React from "react";
import { Plus, Send } from "lucide-react";

import { Panel, PanelTitleBar } from "@/components/ui/panel";
import { Button } from "@/components/ui/button";
import { InlineAlert } from "@/components/ui/feedback";
import { Skeleton } from "@/components/ui/skeleton";
import { CopyableId, Micro, MonoValue, Timestamp } from "@/components/ui/value";
import { SeriesChart, describeSeries } from "@/components/metrics/series-chart";
import { SeriesLegend, type SeriesSpec } from "@/components/metrics/lifecycle";
import { Segmented } from "@/components/metrics/segmented";
import { formatRateFigure } from "@/components/metrics/format-metrics";
import { formatCount, formatRate } from "@/lib/format";
import { cn } from "@/lib/utils";
import type { Queue, Subscription, Topic } from "@/lib/types";
import { PublishDialog } from "./publish-dialog";
import { PublishDeliveryPlot } from "./publish-delivery-plot";
import { DeleteTopicDialog } from "./delete-topic-dialog";
import { ConnectQueueDialog, DisconnectQueueDialog } from "./subscription-dialogs";
import {
  loadTopicRates,
  plotReason,
  topicMetricsFor,
  type TopicMetricsState,
  type TopicRatesState,
} from "./telemetry";

/** The windows the metrics API accepts as `?range=`. */
const RANGES = [
  { value: "5m", label: "5m" },
  { value: "15m", label: "15m" },
  { value: "1h", label: "1h" },
  { value: "6h", label: "6h" },
  { value: "24h", label: "24h" },
] as const;

type Range = (typeof RANGES)[number]["value"];

const SERIES: readonly SeriesSpec[] = [
  { key: "publish", label: "Publish", tone: "send" },
  { key: "delivery", label: "Delivery", tone: "receive" },
];

interface TopicDetailProps {
  topic: Topic;
  queues: Queue[];
  metrics: TopicMetricsState;
  /** Bumped after a publish or a connection change, to re-read the series. */
  metricsKey: number;
  /** False when the operator may read Pub/Sub but not change it. */
  canManage?: boolean;
  onChanged: () => void;
}

export function TopicDetail({
  topic,
  queues,
  metrics,
  metricsKey,
  canManage = true,
  onChanged,
}: TopicDetailProps) {
  const [publishOpen, setPublishOpen] = React.useState(false);
  const [connectOpen, setConnectOpen] = React.useState(false);
  const [deleteOpen, setDeleteOpen] = React.useState(false);
  const [disconnecting, setDisconnecting] = React.useState<Subscription | null>(null);
  const [range, setRange] = React.useState<Range>("1h");
  const [rates, setRates] = React.useState<TopicRatesState>({ status: "loading" });

  const queueNames = React.useMemo(
    () => new Map(queues.map((queue) => [queue.queueId, queue.queueName])),
    [queues],
  );

  const telemetryOff = metrics.status === "unavailable";

  React.useEffect(() => {
    // Nothing to ask for when the metrics API is not mounted: the page already
    // says why, and a request per topic would only produce more 404s.
    if (telemetryOff) {
      setRates({ status: "unavailable" });
      return;
    }

    let cancelled = false;
    setRates({ status: "loading" });
    void loadTopicRates(topic.topicId, range).then((result) => {
      if (!cancelled) setRates(result);
    });

    return () => {
      cancelled = true;
    };
  }, [topic.topicId, range, metricsKey, telemetryOff]);

  const subscriptions = topic.subscriptions ?? [];
  const row = topicMetricsFor(metrics, topic.topicId);
  const blockedReason = canManage ? undefined : "Your role cannot change Pub/Sub topics.";
  const nameOf = (sub: Subscription) =>
    sub.queueName || queueNames.get(sub.queueId) || sub.queueId;

  const rangeLabel = RANGES.find((entry) => entry.value === range)?.label ?? range;
  const samples = rates.status === "ready" ? rates.rows : [];

  return (
    <>
      <Panel>
        <PanelTitleBar
          className="py-2.5"
          title={
            <span className="flex min-w-0 flex-wrap items-center gap-2">
              <span className="truncate">{topic.topicName}</span>
              <CopyableId
                value={topic.topicId}
                label="Topic ID"
                className="text-[10px] font-normal"
              />
            </span>
          }
          action={
            <div className="flex shrink-0 items-center gap-1.5">
              <Button size="sm" blockedReason={blockedReason} onClick={() => setPublishOpen(true)}>
                <Send aria-hidden />
                Publish
              </Button>
              <Button
                variant="destructive-outline"
                size="sm"
                blockedReason={blockedReason}
                onClick={() => setDeleteOpen(true)}
              >
                Delete topic
              </Button>
            </div>
          }
        />

        <TopicFigures metrics={metrics} row={row} listedSubscriptions={subscriptions.length} />

        <section className="border-b border-border px-4 py-3.5">
          <div className="mb-2 flex items-center justify-between gap-3">
            <h3 className="text-xs font-semibold">
              Connected queues{" "}
              <span className="font-mono font-normal text-muted-foreground tabular">
                {formatCount(subscriptions.length)}
              </span>
            </h3>
            <Button
              variant="outline"
              size="sm"
              blockedReason={blockedReason}
              onClick={() => setConnectOpen(true)}
            >
              <Plus aria-hidden />
              Connect queue
            </Button>
          </div>

          {subscriptions.length === 0 ? (
            <InlineAlert tone="warning">
              No queues are connected. Publishing succeeds with 0 deliveries — messages are not
              stored on the topic.
            </InlineAlert>
          ) : (
            <div className="border border-border">
              {subscriptions.map((sub) => (
                <div
                  key={sub.subscriptionId}
                  className="flex items-center justify-between gap-3 border-t border-border px-2.5 py-2 first:border-t-0"
                >
                  <div className="min-w-0">
                    <span className="block truncate text-[13px] leading-[17px] font-medium">
                      {nameOf(sub)}
                    </span>
                    <span className="block truncate font-mono text-[10px] text-muted-foreground">
                      {sub.queueId}
                    </span>
                  </div>
                  <Button
                    variant="ghost"
                    size="sm"
                    blockedReason={blockedReason}
                    onClick={() => setDisconnecting(sub)}
                  >
                    Disconnect
                  </Button>
                </div>
              ))}
            </div>
          )}
        </section>

        <section className="px-4 py-3.5">
          <div className="mb-2.5 flex flex-wrap items-center justify-between gap-2">
            <h3 className="text-xs font-semibold">Publish vs delivery</h3>
            {/* Nothing to window when the collector is off. */}
            {rates.status === "unavailable" ? null : (
              <Segmented
                options={RANGES}
                value={range}
                onChange={setRange}
                label="Metrics window"
                className="h-7"
              />
            )}
          </div>

          {rates.status === "loading" ? (
            <Skeleton className="h-[200px] w-full" />
          ) : samples.length > 0 ? (
            <>
              <SeriesChart
                data={samples}
                series={SERIES}
                height={200}
                formatValue={formatRate}
                formatTick={formatRateFigure}
                summary={describeSeries(samples, SERIES, rangeLabel, formatRate)}
              />
              <div className="mt-2 flex flex-wrap items-center justify-between gap-2">
                <SeriesLegend series={SERIES} />
                <Micro className="text-[10px]">
                  {formatCount(samples.length)} {samples.length === 1 ? "sample" : "samples"} ·{" "}
                  {rangeLabel} window
                </Micro>
              </div>
            </>
          ) : (
            <PublishDeliveryPlot
              title={
                rates.status === "unavailable"
                  ? "Telemetry is off"
                  : rates.status === "error"
                    ? "Series could not be read"
                    : "No samples in this range"
              }
              reason={plotReason(rates)}
            />
          )}
        </section>
      </Panel>

      <PublishDialog
        open={publishOpen}
        onOpenChange={setPublishOpen}
        topic={topic}
        queueNames={queueNames}
        onPublished={onChanged}
      />

      <DeleteTopicDialog
        open={deleteOpen}
        onOpenChange={setDeleteOpen}
        topic={topic}
        onDeleted={onChanged}
      />

      <ConnectQueueDialog
        open={connectOpen}
        onOpenChange={setConnectOpen}
        topic={topic}
        queues={queues}
        onConnected={onChanged}
      />

      <DisconnectQueueDialog
        open={disconnecting !== null}
        onOpenChange={(open) => {
          if (!open) setDisconnecting(null);
        }}
        topic={topic}
        subscription={disconnecting}
        queueName={disconnecting ? nameOf(disconnecting) : ""}
        onDisconnected={onChanged}
      />
    </>
  );
}

/** Hairlines between cells only: the panel already draws the outer box. */
const FIGURE_CELL =
  "border-border px-3 py-2 [&:nth-child(3n+2)]:border-l [&:nth-child(3n)]:border-l [&:nth-child(n+4)]:border-t";

function Figure({
  label,
  children,
  mono = true,
  unknown,
}: {
  label: string;
  children: React.ReactNode;
  mono?: boolean;
  unknown?: boolean;
}) {
  return (
    <div className={FIGURE_CELL}>
      <div className="text-[10px] text-muted-foreground">{label}</div>
      {mono ? (
        <MonoValue className={cn("mt-0.5 block", unknown && "text-subtle")}>{children}</MonoValue>
      ) : (
        <div className={cn("mt-0.5", unknown && "text-subtle")}>{children}</div>
      )}
    </div>
  );
}

/**
 * What the collector holds for this one topic. Counters are process-current,
 * so they are labelled as such rather than presented as an all-time total the
 * server never claimed.
 */
function TopicFigures({
  metrics,
  row,
  listedSubscriptions,
}: {
  metrics: TopicMetricsState;
  row: ReturnType<typeof topicMetricsFor>;
  listedSubscriptions: number;
}) {
  if (metrics.status === "loading") {
    return (
      <div className="grid grid-cols-3 border-b border-border">
        {Array.from({ length: 6 }, (_, index) => (
          <div key={index} className={FIGURE_CELL}>
            <Skeleton className="h-[10px] w-16" />
            <Skeleton className="mt-1.5 h-[15px] w-12" />
          </div>
        ))}
      </div>
    );
  }

  // The topic list is the other real source of a subscription count, and it is
  // the one that answers before the collector has seen a change.
  const subscriptions = row?.subscriptionsCurrent ?? listedSubscriptions;
  // 0 is the collector's "never updated", not an epoch reading.
  const sampledAt = row !== null && row.updatedAt > 0 ? row.updatedAt : null;

  return (
    <div className="grid grid-cols-3 border-b border-border">
      <Figure label="Publish rate" unknown={row === null}>
        {row === null ? "Unknown" : formatRate(row.publishRate)}
      </Figure>
      <Figure label="Delivery rate" unknown={row === null}>
        {row === null ? "Unknown" : formatRate(row.deliveryRate)}
      </Figure>
      <Figure label="Subscriptions">{formatCount(subscriptions)}</Figure>
      <Figure label="Published since start" unknown={row === null}>
        {row === null ? "Unknown" : formatCount(row.messagesPublished)}
      </Figure>
      <Figure label="Deliveries since start" unknown={row === null}>
        {row === null ? "Unknown" : formatCount(row.deliveries)}
      </Figure>
      {/* `Timestamp` brings its own mono absolute-over-relative pair, so the
          cell does not wrap it in a second one. */}
      <Figure label="Last sample" mono={!sampledAt} unknown={!sampledAt}>
        {sampledAt ? <Timestamp value={sampledAt} /> : "Unknown"}
      </Figure>
    </div>
  );
}

export function TopicDetailSkeleton() {
  return (
    <Panel>
      <div className="flex items-center justify-between gap-3 border-b border-border px-4 py-2.5">
        <Skeleton className="h-[18px] w-64" />
        <div className="flex shrink-0 items-center gap-1.5">
          <Skeleton className="h-7 w-20" />
          <Skeleton className="h-7 w-24" />
        </div>
      </div>
      <div className="border-b border-border px-4 py-3.5">
        <Skeleton className="h-4 w-40" />
        <Skeleton className="mt-2 h-[52px] w-full" />
      </div>
      <div className="px-4 py-3.5">
        <Skeleton className="h-4 w-32" />
        <Skeleton className="mt-2.5 h-[200px] w-full" />
      </div>
    </Panel>
  );
}
