import * as React from "react";

import { ScopeBadge } from "@/components/ui/badge";
import { Panel } from "@/components/ui/panel";
import { Skeleton } from "@/components/ui/skeleton";
import { formatCount } from "@/lib/format";
import { cn } from "@/lib/utils";
import { formatRateFigure } from "./format-metrics";
import { SeriesSwatch, type LifecycleTone } from "./lifecycle";
import type { SystemCounters } from "./telemetry-data";

/**
 * The four counters `/metrics/overview` actually populates. The response also
 * carries `queuesExist` and three lifetime totals, but the handler never sets
 * them — they arrive as a hard 0 that means "not reported", so they are not
 * rendered at all rather than shown as readings.
 *
 * These are process-current: the overview route takes no range, so the toolbar
 * above does not scope them.
 */
export function SummaryTiles({
  counters,
  loading = false,
  stale = false,
}: {
  counters: SystemCounters | null;
  loading?: boolean;
  stale?: boolean;
}) {
  if (loading || !counters) {
    return (
      <TileGrid>
        {Array.from({ length: 4 }).map((_, index) => (
          <Panel key={index} className="px-3.5 py-3">
            <Skeleton className="h-[15px] w-20" />
            <Skeleton className="mt-2 h-[18px] w-14" />
          </Panel>
        ))}
      </TileGrid>
    );
  }

  return (
    <TileGrid>
      <Tile
        label="Send rate"
        tone="send"
        value={formatRateFigure(counters.sendRate)}
        unit="/s"
        stale={stale}
      />
      <Tile
        label="Receive rate"
        tone="receive"
        value={formatRateFigure(counters.receiveRate)}
        unit="/s"
        stale={stale}
      />
      <Tile
        label="Delete rate"
        tone="acknowledge"
        value={formatRateFigure(counters.deleteRate)}
        unit="/s"
        stale={stale}
      />
      <Tile label="In-flight" value={formatCount(counters.inFlight)} stale={stale} />
    </TileGrid>
  );
}

function TileGrid({ children }: { children: React.ReactNode }) {
  return <div className="grid grid-cols-2 gap-3 xl:grid-cols-4">{children}</div>;
}

function Tile({
  label,
  value,
  unit,
  tone,
  stale,
}: {
  label: string;
  value: string;
  unit?: string;
  tone?: LifecycleTone;
  stale?: boolean;
}) {
  return (
    <Panel className="px-3.5 py-3">
      <div className="flex items-center gap-1.5 text-[11px] text-muted-foreground">
        {tone ? <SeriesSwatch tone={tone} /> : null}
        {label}
        {/* The muted value alone would read as a live counter to anyone who
            cannot tell the greys apart — the word has to be there too. */}
        {stale ? <ScopeBadge className="ml-auto">Stale</ScopeBadge> : null}
      </div>
      <div
        className={cn(
          "font-mono text-[18px] leading-[26px] font-medium tabular",
          stale && "text-muted-foreground",
        )}
      >
        {value}
        {unit ? <span className="text-[11px] text-subtle">{unit}</span> : null}
      </div>
    </Panel>
  );
}
