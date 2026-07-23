import * as React from "react";
import { TriangleAlert, Info, X } from "lucide-react";

import { cn } from "@/lib/utils";

/**
 * Four feedback channels, each with one job:
 *   inline  — local validation, next to the field that failed
 *   banner  — page-level impact the operator should know about but can work around
 *   toast   — a background action that finished
 *   dialog  — an explicit confirmation
 * Never native confirm().
 */

type FeedbackTone = "error" | "warning";

/**
 * Sits next to the thing that failed and offers the way out. `action` is the
 * recovery, not a dismissal.
 */
function InlineAlert({
  tone = "error",
  action,
  className,
  children,
  ...props
}: React.ComponentProps<"div"> & { tone?: FeedbackTone; action?: React.ReactNode }) {
  const Icon = tone === "error" ? TriangleAlert : Info;

  return (
    <div
      data-slot="inline-alert"
      role="alert"
      className={cn(
        "flex items-center gap-2.5 border px-3 py-2 text-xs",
        tone === "error"
          ? "border-destructive-border bg-destructive-surface text-destructive-text"
          : "border-warning bg-warning-surface text-warning-text",
        className,
      )}
      {...props}
    >
      <Icon className="size-3.5 shrink-0" aria-hidden />
      <span className="min-w-0">{children}</span>
      {action ? <span className="ml-auto shrink-0 font-semibold">{action}</span> : null}
    </div>
  );
}

/**
 * Page-level. Degraded telemetry must never look like degraded queue
 * management, so a banner states the blast radius and stays out of the way.
 */
function Banner({
  tone = "warning",
  action,
  onDismiss,
  className,
  children,
  ...props
}: React.ComponentProps<"div"> & {
  tone?: FeedbackTone;
  action?: React.ReactNode;
  onDismiss?: () => void;
}) {
  return (
    <div
      data-slot="banner"
      role="status"
      className={cn(
        "flex items-center gap-2.5 border px-3 py-2.5 text-xs",
        tone === "error"
          ? "border-destructive-border bg-destructive-surface text-destructive-text"
          : "border-warning bg-warning-surface text-warning-text",
        className,
      )}
      {...props}
    >
      <TriangleAlert className="size-3.5 shrink-0" aria-hidden />
      <span className="min-w-0">{children}</span>
      {action ? <span className="ml-auto shrink-0 font-semibold">{action}</span> : null}
      {onDismiss ? (
        <button
          type="button"
          onClick={onDismiss}
          aria-label="Dismiss"
          className={cn("shrink-0 cursor-pointer", action ? "" : "ml-auto")}
        >
          <X className="size-3.5" aria-hidden />
        </button>
      ) : null}
    </div>
  );
}

export { InlineAlert, Banner };
