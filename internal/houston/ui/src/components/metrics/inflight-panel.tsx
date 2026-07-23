"use client";

import { toast } from "sonner";

import { Button } from "@/components/ui/button";
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
import { ScopeBadge } from "@/components/ui/badge";
import { api } from "@/lib/api-client";
import { formatCount } from "@/lib/format";
import { downloadCsv, downloadJson } from "./export";
import type { SeriesSpec } from "./lifecycle";
import { describeSeries, SeriesChart } from "./series-chart";
import { loadInFlightSeries, type RangeKey } from "./telemetry-data";
import type { ThroughputSubject } from "./throughput-panel";
import { useSeries } from "./use-series";

/**
 * In-flight is a count of messages held under a visibility timeout, not a
 * rate — it carries no denominator, so it gets its own plot rather than a
 * second axis on the throughput chart.
 */
const IN_FLIGHT_SERIES: SeriesSpec[] = [{ key: "inflight", label: "in-flight", tone: "send" }];

export function InFlightPanel({
  queues,
  queueId,
  onQueueChange,
  range,
  refreshToken,
  canExport,
  blockedExportReason,
}: {
  queues: ThroughputSubject[];
  queueId: string | null;
  onQueueChange: (queueId: string) => void;
  range: RangeKey;
  refreshToken: number;
  canExport: boolean;
  blockedExportReason?: string;
}) {
  const state = useSeries(
    queueId === null ? null : `${queueId}:${range}`,
    refreshToken,
    () =>
      queueId === null
        ? Promise.resolve({ status: "loaded" as const, rows: [] })
        : loadInFlightSeries(api.metrics, queueId, range),
  );

  const { rows, loading, unavailable, error, stale } = state;
  const queueLabel = queues.find((queue) => queue.id === queueId)?.label ?? null;
  const summary = describeSeries(rows, IN_FLIGHT_SERIES, range, formatCount);

  const exportSubject =
    rows.length > 0 && queueId !== null
      ? {
          name: `inflight-${queueLabel ?? queueId}`,
          data: rows,
          series: IN_FLIGHT_SERIES,
          fromMs: rows[0]!.t,
          toMs: rows[rows.length - 1]!.t,
        }
      : null;

  return (
    <Panel className="flex flex-col">
      <PanelTitleBar
        className="items-center py-2.5"
        title={
          <div className="flex items-center gap-2.5">
            In-flight
            {stale ? <ScopeBadge>Stale</ScopeBadge> : null}
          </div>
        }
      />

      <PanelBody className="flex flex-1 flex-col gap-3 px-4 py-3.5">
        <label className="flex flex-col gap-1.5">
          <span className="text-xs font-medium text-strong">Queue</span>
          <Select
            value={queueId ?? ""}
            onValueChange={(value) => {
              if (value) onQueueChange(value);
            }}
            disabled={queues.length === 0}
          >
            <SelectTrigger className="w-full" aria-label="In-flight queue">
              <SelectValue placeholder="Nothing reporting" />
            </SelectTrigger>
            <SelectContent>
              {queues.map((queue) => (
                <SelectItem key={queue.id} value={queue.id}>
                  {queue.label}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </label>

        {loading ? (
          <Skeleton className="h-[150px] w-full" />
        ) : unavailable ? (
          <EmptyState
            title="Telemetry is not enabled"
            description="In-flight history needs telemetry storage configured."
            className="px-4 py-8"
          />
        ) : error !== null && rows.length === 0 ? (
          <EmptyState title="Samples could not be loaded" description={error} className="px-4 py-8" />
        ) : queueId === null ? (
          <EmptyState
            title="No queues reporting"
            description="No queue has produced a sample since this process started."
            className="px-4 py-8"
          />
        ) : rows.length === 0 ? (
          <EmptyState
            title="No samples in this range"
            description="Nothing was sampled for this queue in the selected range."
            className="px-4 py-8"
          />
        ) : (
          <SeriesChart
            data={rows}
            series={IN_FLIGHT_SERIES}
            height={150}
            formatValue={formatCount}
            summary={summary}
          />
        )}

        {rows.length > 0 && !loading ? <Micro className="leading-[16px]">{summary}</Micro> : null}

        <div className="mt-auto flex gap-2 pt-1">
          <Button
            variant="outline"
            size="sm"
            disabled={!exportSubject}
            blockedReason={canExport ? undefined : blockedExportReason}
            onClick={() => {
              if (!exportSubject) return;
              toast.success(`Exported ${downloadCsv(exportSubject)}`);
            }}
          >
            Export CSV
          </Button>
          <Button
            variant="outline"
            size="sm"
            disabled={!exportSubject}
            blockedReason={canExport ? undefined : blockedExportReason}
            onClick={() => {
              if (!exportSubject) return;
              toast.success(`Exported ${downloadJson(exportSubject)}`);
            }}
          >
            Export JSON
          </Button>
        </div>
      </PanelBody>
    </Panel>
  );
}
