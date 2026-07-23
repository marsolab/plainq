"use client";

import * as React from "react";
import { Copy, Check } from "lucide-react";
import { toast } from "sonner";

import { cn } from "@/lib/utils";
import { formatDateFull, formatDateShort, formatRelative } from "@/lib/format";

/** Any server-supplied value: ID, count, duration, rate. Mono, tabular. */
function MonoValue({ className, ...props }: React.ComponentProps<"span">) {
  return (
    <span
      data-slot="mono-value"
      className={cn("font-mono text-[13px] tabular", className)}
      {...props}
    />
  );
}

/** Small mono note — "cursor pagination · no total count", freshness stamps. */
function Micro({ className, ...props }: React.ComponentProps<"span">) {
  return (
    <span
      data-slot="micro"
      className={cn("font-mono text-[11px] text-muted-foreground", className)}
      {...props}
    />
  );
}

/**
 * Absolute time first, relative underneath. The absolute value is what an
 * operator correlates against logs; "3 days ago" is only orientation.
 */
function Timestamp({
  value,
  variant = "short",
  className,
  ...props
}: Omit<React.ComponentProps<"span">, "children"> & {
  value: string | number | Date;
  variant?: "short" | "full" | "inline";
}) {
  const absolute = variant === "full" ? formatDateFull(value) : formatDateShort(value);
  const relative = formatRelative(value);

  if (variant === "inline") {
    return (
      <span
        data-slot="timestamp"
        className={cn("inline-flex items-baseline gap-2", className)}
        {...props}
      >
        <span className="font-mono text-xs tabular">{formatDateFull(value)}</span>
        <span className="text-[11px] text-muted-foreground">{relative}</span>
      </span>
    );
  }

  return (
    <span
      data-slot="timestamp"
      title={formatDateFull(value)}
      className={cn("block", className)}
      {...props}
    >
      <span className="block font-mono text-xs leading-[18px] tabular">{absolute}</span>
      <span className="block text-[11px] leading-[15px] text-muted-foreground">{relative}</span>
    </span>
  );
}

/**
 * A ULID the operator will paste into a log query. Click copies; the toast is
 * the confirmation, so the button never silently succeeds.
 */
function CopyableId({
  value,
  label = "ID",
  className,
  ...props
}: Omit<React.ComponentProps<"button">, "value"> & {
  value: string;
  label?: string;
}) {
  const [copied, setCopied] = React.useState(false);

  const copy = async () => {
    try {
      await navigator.clipboard.writeText(value);
      setCopied(true);
      toast.success(`${label} copied`);
      window.setTimeout(() => setCopied(false), 1500);
    } catch {
      toast.error(`Could not copy ${label.toLowerCase()}`);
    }
  };

  return (
    <button
      type="button"
      data-slot="copyable-id"
      onClick={copy}
      aria-label={`Copy ${label.toLowerCase()} ${value}`}
      className={cn(
        "inline-flex cursor-pointer items-center gap-1.5 border border-border bg-surface px-2 py-[3px] font-mono text-[11px] text-strong transition-colors hover:bg-muted",
        className,
      )}
      {...props}
    >
      {value}
      {copied ? (
        <Check className="size-3 text-success" aria-hidden />
      ) : (
        <Copy className="size-3 text-muted-foreground" aria-hidden />
      )}
    </button>
  );
}

/**
 * Label-over-value pair used across overview and configuration surfaces.
 * Values default to mono so columns of them line up.
 */
function Field({
  label,
  hint,
  mono = true,
  children,
  className,
  ...props
}: React.ComponentProps<"div"> & {
  label: React.ReactNode;
  hint?: React.ReactNode;
  mono?: boolean;
}) {
  return (
    <div data-slot="field-value" className={cn("min-w-0", className)} {...props}>
      <div className="text-xs font-medium text-muted-foreground">{label}</div>
      <div className={cn("mt-1 text-[13px]", mono && "font-mono tabular")}>{children}</div>
      {hint ? <div className="mt-0.5 text-[11px] text-subtle">{hint}</div> : null}
    </div>
  );
}

/** Key/value rows inside a panel, separated by hairlines. */
function DefinitionRow({
  label,
  hint,
  children,
  className,
  ...props
}: React.ComponentProps<"div"> & { label: React.ReactNode; hint?: React.ReactNode }) {
  return (
    <div
      data-slot="definition-row"
      className={cn(
        "flex items-baseline gap-4 border-b border-border px-4 py-2.5 last:border-b-0",
        className,
      )}
      {...props}
    >
      <div className="w-52 shrink-0">
        <div className="text-xs font-medium">{label}</div>
        {hint ? <div className="mt-0.5 text-[11px] text-subtle">{hint}</div> : null}
      </div>
      <div className="min-w-0 flex-1 font-mono text-[13px] tabular">{children}</div>
    </div>
  );
}

export { MonoValue, Micro, Timestamp, CopyableId, Field, DefinitionRow };
