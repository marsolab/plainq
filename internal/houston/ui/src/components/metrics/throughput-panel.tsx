"use client";

import * as React from "react";
import { ChartLine } from "lucide-react";

import { ScopeBadge } from "@/components/ui/badge";
import { EmptyState } from "@/components/ui/empty-state";
import { Panel, PanelBody, PanelTitleBar } from "@/components/ui/panel";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Skeleton } from "@/components/ui/skeleton";
import { Micro } from "@/components/ui/value";
import { formatRate } from "@/lib/format";
import { api } from "@/lib/api-client";
import { SeriesLegend, type SeriesSpec } from "./lifecycle";
import { Segmented } from "./segmented";
import { describeSeries, SeriesChart, SeriesTable, type ChartRow } from "./series-chart";
import { loadQueueRateSeries, loadTopicRateSeries, type RangeKey } from "./telemetry-data";
import { useSeries } from "./use-series";

export type ThroughputScope = "queues" | "topics";

/**
 * Queue traffic and topic fan-out come from separate routes against separate
 * collectors, so they are separate plots. Merging them would suggest one
 * pipeline where there are two.
 *
 * Keys match what `transformRateMetrics` emits for the server's metric names.
 */
export const THROUGHPUT_SERIES: Record<ThroughputScope, SeriesSpec[]> = {
  queues: [
    { key: "send", label: "sent", tone: "send" },
    { key: "receive", label: "received", tone: "receive" },
    { key: "delete", label: "deleted", tone: "acknowledge", dashed: true },
  ],
  topics: [
    { key: "publish", label: "published", tone: "send" },
    { key: "delivery", label: "delivered", tone: "receive" },
  ],
};

export interface ThroughputSubject {
  id: string;
  label: string;
}

export interface ThroughputSelection {
  scope: ThroughputScope;
  queueId: string | null;
  topicId: string | null;
}

export function selectedSubjectId(selection: ThroughputSelection): string | null {
  return selection.scope === "queues" ? selection.queueId : selection.topicId;
}

/**
 * Rate history for one queue or one topic. There is no system-wide series to
 * plot: the client exposes history per entity only, and summing the per-queue
 * rows into a single line would be a reading the server never took.
 */
export function ThroughputPanel({
  selection,
  onSelectionChange,
  subjects,
  range,
  refreshToken,
  onRowsChange,
}: {
  selection: ThroughputSelection;
  onSelectionChange: (selection: ThroughputSelection) => void;
  /** Queues and topics the overview reported, named where the directory knew them. */
  subjects: Record<ThroughputScope, ThroughputSubject[]>;
  range: RangeKey;
  refreshToken: number;
  /** Lifts the samples on screen so the toolbar's export offers exactly them. */
  onRowsChange?: (rows: ChartRow[]) => void;
}) {
  const [view, setView] = React.useState<"chart" | "table">("chart");

  const { scope } = selection;
  const series = THROUGHPUT_SERIES[scope];
  const options = subjects[scope];
  const subjectId = selectedSubjectId(selection);

  const state = useSeries(
    subjectId === null ? null : `${scope}:${subjectId}:${range}`,
    refreshToken,
    () =>
      subjectId === null
        ? Promise.resolve({ status: "loaded" as const, rows: [] })
        : scope === "queues"
          ? loadQueueRateSeries(api.metrics, subjectId, range)
          : loadTopicRateSeries(api.metrics, subjectId, range),
  );

  const { rows, loading, unavailable, error, stale } = state;
  const summary = describeSeries(rows, series, range, formatRate);
  const subjectLabel = options.find((option) => option.id === subjectId)?.label ?? null;

  React.useEffect(() => {
    onRowsChange?.(rows);
  }, [rows, onRowsChange]);

  return (
    <Panel className="flex flex-col">
      <PanelTitleBar
        className="items-center py-2.5"
        title={
          <div className="flex items-center gap-2.5">
            Throughput
            <Segmented
              variant="text"
              label="Throughput scope"
              value={scope}
              onChange={(next) => onSelectionChange({ ...selection, scope: next })}
              options={[
                { value: "queues", label: "Queues" },
                { value: "topics", label: "Pub/Sub" },
              ]}
            />
            {stale ? <ScopeBadge>Stale</ScopeBadge> : null}
          </div>
        }
        action={
          <>
            <SeriesLegend series={series} />
            <Segmented
              variant="text"
              label="Throughput view"
              value={view}
              onChange={setView}
              options={[
                { value: "chart", label: "Chart" },
                { value: "table", label: "Table" },
              ]}
            />
          </>
        }
      />

      <PanelBody className="flex flex-1 flex-col gap-3 px-4 py-3.5">
        <label className="flex items-center gap-2.5">
          <span className="text-xs font-medium text-strong">
            {scope === "queues" ? "Queue" : "Topic"}
          </span>
          <Select
            value={subjectId ?? ""}
            onValueChange={(value) => {
              if (!value) return;
              onSelectionChange(
                scope === "queues"
                  ? { ...selection, queueId: value }
                  : { ...selection, topicId: value },
              );
            }}
            disabled={options.length === 0}
          >
            <SelectTrigger
              className="w-64"
              aria-label={scope === "queues" ? "Queue series" : "Topic series"}
            >
              <SelectValue placeholder="Nothing reporting" />
            </SelectTrigger>
            <SelectContent>
              {options.map((option) => (
                <SelectItem key={option.id} value={option.id}>
                  {option.label}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </label>

        <ThroughputBody
          loading={loading}
          unavailable={unavailable}
          error={error}
          hasSubject={subjectId !== null}
          scope={scope}
          rows={rows}
          series={series}
          view={view}
          summary={summary}
        />

        {rows.length > 0 && !loading ? (
          <Micro className="leading-[16px]">
            {subjectLabel ? `${subjectLabel} · ` : ""}
            {summary}
          </Micro>
        ) : null}
      </PanelBody>
    </Panel>
  );
}

function ThroughputBody({
  loading,
  unavailable,
  error,
  hasSubject,
  scope,
  rows,
  series,
  view,
  summary,
}: {
  loading: boolean;
  unavailable: boolean;
  error: string | null;
  hasSubject: boolean;
  scope: ThroughputScope;
  rows: ChartRow[];
  series: SeriesSpec[];
  view: "chart" | "table";
  summary: string;
}) {
  if (loading) return <Skeleton className="h-[240px] w-full" />;

  if (unavailable) {
    return (
      <EmptyState
        icon={ChartLine}
        title="Telemetry is not enabled"
        description="Rate history needs telemetry storage configured. Queue and Pub/Sub management are unaffected."
      />
    );
  }

  if (error !== null && rows.length === 0) {
    return <EmptyState icon={ChartLine} title="Samples could not be loaded" description={error} />;
  }

  if (!hasSubject) {
    return (
      <EmptyState
        icon={ChartLine}
        title={scope === "queues" ? "No queues reporting" : "No topics reporting"}
        description={
          scope === "queues"
            ? "No queue has produced a sample since this process started."
            : "No topic has published since this process started."
        }
      />
    );
  }

  if (rows.length === 0) {
    return (
      <EmptyState
        icon={ChartLine}
        title="No samples in this range"
        description="Nothing was sampled for this subject in the selected range. Pick a shorter range or wait for the next bucket."
      />
    );
  }

  return view === "chart" ? (
    <SeriesChart data={rows} series={series} height={240} formatValue={formatRate} summary={summary} />
  ) : (
    <SeriesTable data={rows} series={series} formatValue={formatRate} />
  );
}
