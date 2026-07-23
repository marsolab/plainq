import * as React from "react";

import { cn } from "@/lib/utils";
import { Status, type StatusTone } from "@/components/ui/status";

/**
 * System panels sit two to a row, so their values are set flush right and read
 * as a single column against the panel edge. `DefinitionRow` in the foundation
 * is the other shape — a wide left-hand term column for resource detail pages
 * — and would leave a gutter of dead space at this width.
 */
function Row({
  label,
  labelClassName,
  className,
  children,
  ...props
}: React.ComponentProps<"div"> & {
  label: React.ReactNode;
  labelClassName?: string;
}) {
  return (
    <div
      className={cn(
        "flex items-center justify-between gap-4 border-t border-muted px-4 py-2 first:border-t-0",
        className,
      )}
      {...props}
    >
      <span className={cn("shrink-0", labelClassName)}>{label}</span>
      <span className="min-w-0 truncate text-right">{children}</span>
    </div>
  );
}

/**
 * One startup fact, always a plain mono value. Deliberately unable to render a
 * marker-plus-word status: nothing in this panel is probed, and a fact that
 * looked like the Health panel's live rows would be claiming a measurement.
 */
function FactRow({
  label,
  subdued = false,
  children,
  ...props
}: React.ComponentProps<"div"> & {
  label: React.ReactNode;
  /** Redacted or unexposed: kept visible, but visibly not a value. */
  subdued?: boolean;
}) {
  return (
    <Row label={label} labelClassName="text-xs text-muted-foreground" {...props}>
      <span className={cn("font-mono text-xs tabular", subdued && "text-subtle")}>
        {children}
      </span>
    </Row>
  );
}

/** A subsystem and what PlainQ currently knows about it. */
function HealthRow({
  label,
  tone,
  children,
  ...props
}: React.ComponentProps<"div"> & { label: React.ReactNode; tone: StatusTone }) {
  return (
    <Row label={label} labelClassName="text-[13px]" {...props}>
      <Status tone={tone}>{children}</Status>
    </Row>
  );
}

export { FactRow, HealthRow };
