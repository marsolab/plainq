import * as React from "react";

import { cn } from "@/lib/utils";

/**
 * Every status in Houston is a square marker plus a word. Color is the
 * secondary channel, never the only one — an operator who cannot distinguish
 * amber from green still reads the label.
 */
export type StatusTone =
  | "neutral" // no claim / not started
  | "visible" // in the queue, available to receive
  | "in-flight" // received, hidden by the visibility timeout
  | "acknowledged"
  | "dead-lettered"
  | "healthy"
  | "degraded"
  | "warning";

const MARKER: Record<StatusTone, string> = {
  neutral: "border border-muted-foreground bg-surface",
  visible: "border border-muted-foreground bg-surface",
  "in-flight": "bg-send",
  acknowledged: "bg-acknowledge",
  "dead-lettered": "bg-retry",
  healthy: "bg-success",
  degraded: "bg-destructive",
  warning: "bg-warning",
};

const TEXT: Record<StatusTone, string> = {
  neutral: "text-foreground",
  visible: "text-foreground",
  "in-flight": "text-send-text",
  acknowledged: "text-acknowledge-text",
  "dead-lettered": "text-retry-text",
  healthy: "text-foreground",
  degraded: "text-destructive-text",
  warning: "text-warning-text",
};

/** The bare square. Use when the label is supplied by an adjacent column. */
function StatusMarker({
  tone = "neutral",
  className,
  ...props
}: React.ComponentProps<"span"> & { tone?: StatusTone }) {
  return (
    <span
      data-slot="status-marker"
      aria-hidden
      className={cn("inline-block size-2 shrink-0", MARKER[tone], className)}
      {...props}
    />
  );
}

/** Marker + label, the default way to render any status. */
function Status({
  tone = "neutral",
  children,
  className,
  markerClassName,
  ...props
}: React.ComponentProps<"span"> & {
  tone?: StatusTone;
  markerClassName?: string;
}) {
  return (
    <span
      data-slot="status"
      className={cn("inline-flex items-center gap-1.5 text-xs", TEXT[tone], className)}
      {...props}
    >
      <StatusMarker tone={tone} className={markerClassName} />
      {children}
    </span>
  );
}

export { Status, StatusMarker };
