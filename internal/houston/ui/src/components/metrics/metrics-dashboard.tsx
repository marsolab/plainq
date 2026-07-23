"use client";

import * as React from "react";
import { ChartLine } from "lucide-react";

import { Button } from "@/components/ui/button";
import { EmptyState } from "@/components/ui/empty-state";
import { PageHeader } from "@/components/ui/page-header";
import { Panel } from "@/components/ui/panel";
import { api } from "@/lib/api-client";
import type { ExportSubject } from "./export";
import { HealthPanel, type HealthScope } from "./health-panel";
import { InFlightPanel } from "./inflight-panel";
import { RangeToolbar } from "./range-toolbar";
import type { ChartRow } from "./series-chart";
import { SummaryTiles } from "./summary-tiles";
import {
  loadTelemetryDirectory,
  loadTelemetrySnapshot,
  type RangeKey,
  type TelemetryDirectory,
  type TelemetrySnapshot,
} from "./telemetry-data";
import {
  selectedSubjectId,
  THROUGHPUT_SERIES,
  ThroughputPanel,
  type ThroughputSelection,
  type ThroughputSubject,
} from "./throughput-panel";

const AUTO_REFRESH_MS = 30_000;

export interface MetricsState {
  snapshot: TelemetrySnapshot | null;
  loading: boolean;
  refreshing: boolean;
  /** Telemetry storage is off. Management surfaces are unaffected. */
  unavailable: boolean;
  error: string | null;
  /** What is on screen is the last good read, and a newer one failed. */
  stale: boolean;
  /** Bumped on every completed read so the charts re-fetch with the tiles. */
  refreshToken: number;
  refresh: () => void;
}

const EMPTY_DIRECTORY: TelemetryDirectory = { queues: new Map(), topics: new Map() };

/**
 * Owns the overview conversation for the whole screen. A failed read never
 * clears what is already there — the last good snapshot stays, labelled, until
 * a newer one lands.
 */
export function useMetrics(): MetricsState {
  const [snapshot, setSnapshot] = React.useState<TelemetrySnapshot | null>(null);
  const [loading, setLoading] = React.useState(true);
  const [refreshing, setRefreshing] = React.useState(false);
  const [unavailable, setUnavailable] = React.useState(false);
  const [error, setError] = React.useState<string | null>(null);
  const [refreshToken, setRefreshToken] = React.useState(0);

  const requestRef = React.useRef(0);
  // Held in refs rather than read from state so `load` keeps a stable identity;
  // otherwise the interval below would be torn down on every landed snapshot.
  const snapshotRef = React.useRef<TelemetrySnapshot | null>(null);
  const directoryRef = React.useRef<TelemetryDirectory>(EMPTY_DIRECTORY);

  const load = React.useCallback(async () => {
    const request = requestRef.current + 1;
    requestRef.current = request;

    if (snapshotRef.current) setRefreshing(true);
    else setLoading(true);

    // Names are best effort and cheap to re-read; the numbers do not depend on
    // them, so a failed directory read costs labels and nothing else.
    const directory = await loadTelemetryDirectory().catch(() => directoryRef.current);
    if (requestRef.current !== request) return;
    directoryRef.current = directory;

    const result = await loadTelemetrySnapshot(api.metrics, directory);
    if (requestRef.current !== request) return;

    switch (result.status) {
      case "loaded":
        snapshotRef.current = result.snapshot;
        setSnapshot(result.snapshot);
        setUnavailable(false);
        setError(null);
        break;
      case "unavailable":
        setUnavailable(true);
        setError(null);
        break;
      case "error":
        setUnavailable(false);
        setError(result.message);
        break;
    }

    setLoading(false);
    setRefreshing(false);
    setRefreshToken((token) => token + 1);
  }, []);

  React.useEffect(() => {
    void load();
  }, [load]);

  React.useEffect(() => {
    const timer = window.setInterval(() => {
      if (document.visibilityState === "visible") void load();
    }, AUTO_REFRESH_MS);

    return () => window.clearInterval(timer);
  }, [load]);

  return {
    snapshot,
    loading,
    refreshing,
    unavailable,
    error,
    stale: snapshot !== null && error !== null,
    refreshToken,
    refresh: () => void load(),
  };
}

function subjectsOf(snapshot: TelemetrySnapshot | null): Record<"queues" | "topics", ThroughputSubject[]> {
  return {
    queues: (snapshot?.queues ?? []).map((row) => ({
      id: row.queueId,
      label: row.queueName ?? row.queueId,
    })),
    topics: (snapshot?.topics ?? []).map((row) => ({
      id: row.topicId,
      label: row.topicName ?? row.topicId,
    })),
  };
}

export function MetricsDashboard({
  state,
  range,
  onRangeChange,
  canExport,
  blockedExportReason,
}: {
  state: MetricsState;
  range: RangeKey;
  onRangeChange: (range: RangeKey) => void;
  canExport: boolean;
  blockedExportReason?: string;
}) {
  const { snapshot, loading, unavailable, error, stale, refreshToken, refresh } = state;

  const [healthScope, setHealthScope] = React.useState<HealthScope>("queues");
  const [selection, setSelection] = React.useState<ThroughputSelection>({
    scope: "queues",
    queueId: null,
    topicId: null,
  });
  const [inFlightQueueId, setInFlightQueueId] = React.useState<string | null>(null);
  const [throughputRows, setThroughputRows] = React.useState<ChartRow[]>([]);

  const subjects = React.useMemo(() => subjectsOf(snapshot), [snapshot]);

  // Selections follow what is actually reporting: default to the first subject
  // and drop one that has stopped appearing rather than querying a dead ID.
  React.useEffect(() => {
    setSelection((current) => {
      const queueId = resolveSubject(current.queueId, subjects.queues);
      const topicId = resolveSubject(current.topicId, subjects.topics);

      return queueId === current.queueId && topicId === current.topicId
        ? current
        : { ...current, queueId, topicId };
    });
    setInFlightQueueId((current) => resolveSubject(current, subjects.queues));
  }, [subjects]);

  const throughputSubjectId = selectedSubjectId(selection);
  const exportSubject: ExportSubject | null =
    throughputRows.length > 0 && throughputSubjectId !== null
      ? {
          name: `throughput-${selection.scope}-${throughputSubjectId}`,
          data: throughputRows,
          series: THROUGHPUT_SERIES[selection.scope],
          fromMs: throughputRows[0]!.t,
          toMs: throughputRows[throughputRows.length - 1]!.t,
        }
      : null;

  return (
    <>
      <PageHeader
        title="Metrics"
        description="System-wide traffic: queues and Pub/Sub topics."
        actions={
          <RangeToolbar
            range={range}
            onRangeChange={onRangeChange}
            exportSubject={exportSubject}
            canExport={canExport}
            blockedExportReason={blockedExportReason}
          />
        }
      />

      {unavailable ? (
        <Panel>
          <EmptyState
            icon={ChartLine}
            title="Telemetry is not enabled"
            description="Queue and Pub/Sub management still work. Start PlainQ with telemetry storage configured to collect dashboard data."
          />
        </Panel>
      ) : snapshot === null && error !== null ? (
        <Panel>
          <EmptyState
            icon={ChartLine}
            title="Metrics could not be loaded"
            description={error}
            action={
              <Button variant="outline" onClick={refresh}>
                Retry
              </Button>
            }
          />
        </Panel>
      ) : (
        <div className="flex flex-col gap-4">
          <SummaryTiles counters={snapshot?.counters ?? null} loading={loading} stale={stale} />

          <div className="grid gap-4 xl:grid-cols-[1.35fr_1fr]">
            <ThroughputPanel
              selection={selection}
              onSelectionChange={setSelection}
              subjects={subjects}
              range={range}
              refreshToken={refreshToken}
              onRowsChange={setThroughputRows}
            />
            <InFlightPanel
              queues={subjects.queues}
              queueId={inFlightQueueId}
              onQueueChange={setInFlightQueueId}
              range={range}
              refreshToken={refreshToken}
              canExport={canExport}
              blockedExportReason={blockedExportReason}
            />
          </div>

          <HealthPanel
            snapshot={snapshot}
            scope={healthScope}
            onScopeChange={setHealthScope}
            loading={loading}
            stale={stale}
          />
        </div>
      )}
    </>
  );
}

function resolveSubject(current: string | null, options: ThroughputSubject[]): string | null {
  if (current !== null && options.some((option) => option.id === current)) return current;
  return options[0]?.id ?? null;
}
