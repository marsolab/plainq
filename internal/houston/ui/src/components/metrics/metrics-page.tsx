"use client";

import * as React from "react";

import { AppShell } from "@/components/layout/app-shell";
import { Banner } from "@/components/ui/feedback";
import { Button } from "@/components/ui/button";
import { formatClock } from "@/lib/format";
import { MetricsDashboard, useMetrics } from "./metrics-dashboard";
import type { RangeKey } from "./telemetry-data";

/**
 * Shown when an operator lacks the export capability. Exports are built from
 * the samples already on screen, so nothing here is gated today — the reason is
 * kept next to the control it would block, ready for a capability endpoint.
 */
export const EXPORT_BLOCKED_REASON =
  "Exporting samples requires the metrics export permission, which this account does not have.";

/**
 * The metrics surface owns the shell because the shell's freshness stamp,
 * refresh control and page banner all describe this page's telemetry
 * conversation — none of it is knowable from the Astro page.
 *
 * The page lives at /telemetry: the server reserves /metrics for its Prometheus
 * scrape endpoint, so a Houston route there would never be reached.
 */
export function MetricsPage({ canExport = true }: { canExport?: boolean }) {
  const [range, setRange] = React.useState<RangeKey>("1h");

  const state = useMetrics();
  const { snapshot, error, refreshing, refresh } = state;

  const showStaleBanner = error !== null && snapshot !== null;

  const banner = showStaleBanner ? (
    <Banner
      tone="error"
      action={
        <Button variant="link" size="sm" onClick={refresh}>
          Retry
        </Button>
      }
    >
      {error} Showing the last read, captured {formatClock(snapshot.capturedAt)}.
    </Banner>
  ) : undefined;

  return (
    <AppShell
      currentPath="/telemetry"
      title="Metrics"
      updatedAt={snapshot ? new Date(snapshot.capturedAt) : null}
      onRefresh={refresh}
      refreshing={refreshing}
      banner={banner}
    >
      <MetricsDashboard
        state={state}
        range={range}
        onRangeChange={setRange}
        canExport={canExport}
        blockedExportReason={EXPORT_BLOCKED_REASON}
      />
    </AppShell>
  );
}
