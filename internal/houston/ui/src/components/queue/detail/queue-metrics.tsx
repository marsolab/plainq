"use client";

import { useState } from "react";
import { RefreshCw } from "lucide-react";

import { Panel, PanelFooter, PanelTitleBar } from "@/components/ui/panel";
import { Button } from "@/components/ui/button";
import { ScopeBadge } from "@/components/ui/badge";
import { Banner } from "@/components/ui/feedback";
import { Field, Micro } from "@/components/ui/value";
import { Skeleton } from "@/components/ui/skeleton";
import { formatClock, formatCount, formatRate } from "@/lib/format";
import type { Queue, QueueMetricsSummary } from "@/lib/types";

import { Segmented } from "./segmented";
import { QueueSeriesChart, type QueueSeries } from "./queue-series-chart";
import { useQueueTelemetry } from "./use-queue-telemetry";

/** The ranges the metrics API accepts as its `range` parameter. */
type Range = "5m" | "15m" | "1h" | "6h" | "24h" | "7d";

const RANGES: { value: Range; label: string }[] = [
  { value: "5m", label: "5m" },
  { value: "15m", label: "15m" },
  { value: "1h", label: "1h" },
  { value: "6h", label: "6h" },
  { value: "24h", label: "24h" },
  { value: "7d", label: "7d" },
];

const THROUGHPUT: QueueSeries[] = [
  { key: "send", label: "Send", tone: "send" },
  { key: "receive", label: "Receive", tone: "receive", dashed: true },
  { key: "delete", label: "Acknowledge / delete", tone: "acknowledge" },
];

const IN_FLIGHT: QueueSeries[] = [{ key: "value", label: "In flight", tone: "send" }];

/**
 * S11, scoped to one queue and read from the real per-queue telemetry routes:
 * `/metrics/queue/{id}`, `…/rates` and `…/inflight`.
 *
 * Only what the collector records is drawn. Queue depth and oldest-message age
 * are not among the recorded series, so they are absent rather than shown as
 * zero, and a server started without telemetry storage says exactly that
 * instead of implying the queue is idle.
 */
export function QueueMetrics({ queue }: { queue: Queue }) {
  const [range, setRange] = useState<Range>("1h");
  const telemetry = useQueueTelemetry(queue.queueId, range, true);
  const { summary, status, error, readAt, refreshing } = telemetry;

  const inFlightPoints = telemetry.inFlight.map((point) => ({
    t: point.timestamp,
    value: point.value,
  }));
  const ratePoints = telemetry.rates.map((row) => ({
    t: row.timestamp,
    send: row.send,
    receive: row.receive,
    delete: row.delete,
  }));

  return (
    <div className="flex flex-col gap-4">
      {status === "unavailable" ? (
        <Banner>
          Telemetry storage is not configured on this server, so no samples are
          collected for any queue. Sending, receiving and acknowledging are
          unaffected — see the read-only System configuration for how telemetry is
          enabled.
        </Banner>
      ) : null}

      {status === "failed" && error ? (
        <Banner
          tone="error"
          action={
            <Button variant="link" size="sm" onClick={telemetry.reload} loading={refreshing}>
              Retry
            </Button>
          }
        >
          <span className="inline-flex items-center gap-2">
            {summary ? <ScopeBadge tone="warning">Stale</ScopeBadge> : null}
            {error}
            {summary && readAt ? ` — showing the read at ${formatClock(readAt)}.` : ""}
          </span>
        </Banner>
      ) : null}

      <Panel>
        <PanelTitleBar
          title={
            <span className="inline-flex items-center gap-2.5">
              {queue.queueName} — Metrics
              <Segmented
                label="Time range"
                mono
                value={range}
                options={RANGES}
                onValueChange={setRange}
              />
            </span>
          }
          action={
            <div className="flex items-center gap-2">
              <Micro>{readAt ? formatClock(readAt) : "not read yet"}</Micro>
              <Button
                variant="outline"
                size="sm"
                onClick={telemetry.reload}
                loading={refreshing}
              >
                <RefreshCw aria-hidden />
                Refresh
              </Button>
            </div>
          }
        />

        {status === "loading" && !summary ? (
          <div className="grid grid-cols-2 border-b border-border sm:grid-cols-3 lg:grid-cols-6">
            {Array.from({ length: 6 }, (_, index) => (
              <div key={index} className="border-r border-border px-3.5 py-2.5 last:border-r-0">
                <Skeleton className="h-3 w-20" />
                <Skeleton className="mt-2 h-4 w-14" />
              </div>
            ))}
          </div>
        ) : (
          <SummaryTiles summary={summary} />
        )}

        <div className="grid lg:grid-cols-2">
          <div className="border-b border-border p-3.5 lg:border-r lg:border-b-0">
            <div className="mb-2 text-xs font-semibold">Throughput</div>
            {ratePoints.length === 0 ? (
              <NoSamples range={range} unavailable={status === "unavailable"} />
            ) : (
              <QueueSeriesChart
                points={ratePoints}
                series={THROUGHPUT}
                formatValue={formatRate}
              />
            )}
          </div>

          <div className="p-3.5">
            <div className="mb-2 text-xs font-semibold">In-flight messages</div>
            {inFlightPoints.length === 0 ? (
              <NoSamples range={range} unavailable={status === "unavailable"} />
            ) : (
              <QueueSeriesChart
                points={inFlightPoints}
                series={IN_FLIGHT}
                formatValue={formatCount}
              />
            )}
          </div>
        </div>

        <PanelFooter>
          <span className="text-[11px] text-subtle">
            Series differ by dash pattern as well as colour, and segments run straight
            between samples. Metrics the collector does not record — queue depth,
            oldest-message age — are omitted rather than drawn as zero.
          </span>
        </PanelFooter>
      </Panel>
    </div>
  );
}

/**
 * Six values the summary endpoint actually returns. The current rate is the
 * headline; the window's average and maximum sit under it as the hint, because
 * a single instantaneous reading is easy to over-read.
 */
function SummaryTiles({ summary }: { summary: QueueMetricsSummary | null }) {
  // Rates print their own denominator, so no label repeats "/s".
  const tiles = [
    {
      label: "Send rate",
      value: summary ? formatRate(summary.currentSendRate) : null,
      hint: summary
        ? `avg ${formatRate(summary.avgSendRate)} · max ${formatRate(summary.maxSendRate)}`
        : undefined,
    },
    {
      label: "Receive rate",
      value: summary ? formatRate(summary.currentReceiveRate) : null,
      hint: summary
        ? `avg ${formatRate(summary.avgReceiveRate)} · max ${formatRate(summary.maxReceiveRate)}`
        : undefined,
    },
    {
      label: "Ack / delete rate",
      value: summary ? formatRate(summary.currentDeleteRate) : null,
      hint: summary
        ? `avg ${formatRate(summary.avgDeleteRate)} · max ${formatRate(summary.maxDeleteRate)}`
        : undefined,
    },
    {
      label: "In flight",
      value: summary ? formatCount(summary.currentInFlight) : null,
      hint: "currently held by consumers",
    },
    {
      label: "Sent",
      value: summary ? formatCount(summary.totalSent) : null,
      hint: "in this range",
    },
    {
      label: "Acknowledged",
      value: summary ? formatCount(summary.totalDeleted) : null,
      hint: "in this range",
    },
  ];

  return (
    <div className="grid grid-cols-2 border-b border-border sm:grid-cols-3 lg:grid-cols-6">
      {tiles.map((tile) => (
        <Field
          key={tile.label}
          label={tile.label}
          hint={tile.value === null ? undefined : tile.hint}
          className="border-r border-border px-3.5 py-2.5 last:border-r-0"
        >
          {tile.value ?? <span className="text-subtle">—</span>}
        </Field>
      ))}
    </div>
  );
}

/**
 * The hatched fill reads as "deliberately nothing", which a blank box does not:
 * an empty chart frame is otherwise indistinguishable from a flat line at zero.
 */
function NoSamples({ range, unavailable }: { range: Range; unavailable: boolean }) {
  return (
    <div
      className="flex h-[150px] items-center justify-center border border-border"
      style={{
        backgroundImage:
          "repeating-linear-gradient(45deg,var(--color-surface),var(--color-surface) 10px,var(--color-background) 10px,var(--color-background) 20px)",
      }}
    >
      <span className="bg-surface px-2 py-1 text-center text-xs font-medium text-strong">
        {unavailable
          ? "Telemetry storage is not configured"
          : `No samples in the last ${range}`}
      </span>
    </div>
  );
}
