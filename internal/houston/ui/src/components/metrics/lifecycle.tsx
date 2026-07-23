import * as React from "react";

import { cn } from "@/lib/utils";
import type { ChartTokens } from "./chart-tokens";

/**
 * The lifecycle palette, as used by charts and their legends. `Status` covers
 * queue *states*; these are message *operations*, which is why send/receive/
 * acknowledge/retry appear here rather than as status tones.
 *
 * A swatch is never the only carrier of meaning — every one of them is rendered
 * beside the name of the series it stands for.
 */
export type LifecycleTone = "send" | "receive" | "acknowledge" | "retry";

const SWATCH: Record<LifecycleTone, string> = {
  send: "bg-send",
  receive: "bg-receive",
  acknowledge: "bg-acknowledge",
  retry: "bg-retry",
};

export const TONE_TEXT: Record<LifecycleTone, string> = {
  send: "text-send-text",
  receive: "text-receive-text",
  acknowledge: "text-acknowledge-text",
  retry: "text-retry-text",
};

export function toneColor(tokens: ChartTokens, tone: LifecycleTone): string {
  return tokens[tone];
}

export function SeriesSwatch({
  tone,
  className,
  ...props
}: React.ComponentProps<"span"> & { tone: LifecycleTone }) {
  return (
    <span
      aria-hidden
      className={cn("inline-block size-[7px] shrink-0", SWATCH[tone], className)}
      {...props}
    />
  );
}

export interface SeriesSpec {
  key: string;
  label: string;
  tone: LifecycleTone;
  /** Dashed so the series survives grayscale and colour-blind rendering. */
  dashed?: boolean;
}

export function SeriesLegend({
  series,
  className,
}: {
  series: readonly SeriesSpec[];
  className?: string;
}) {
  return (
    <div className={cn("flex flex-wrap items-center gap-3", className)}>
      {series.map((entry) => (
        <span key={entry.key} className="inline-flex items-center gap-1.5 text-[10px] text-strong">
          <SeriesSwatch tone={entry.tone} className={cn(entry.dashed && "opacity-70")} />
          {entry.label}
        </span>
      ))}
    </div>
  );
}
