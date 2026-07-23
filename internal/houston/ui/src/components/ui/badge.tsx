import * as React from "react";
import { cva, type VariantProps } from "class-variance-authority";
import { Slot } from "radix-ui";

import { cn } from "@/lib/utils";

const badgeVariants = cva(
  "group/badge inline-flex w-fit shrink-0 items-center justify-center gap-1.5 border whitespace-nowrap [&>svg]:pointer-events-none [&>svg]:size-3",
  {
    variants: {
      variant: {
        default: "border-transparent bg-primary px-2 py-0.5 text-xs font-medium text-primary-foreground",
        /** The workhorse: a quiet outlined fact, e.g. "Dead-letter → orders-dlq". */
        outline: "border-border bg-muted px-2 py-[3px] text-[11px] font-medium text-strong",
        surface: "border-border bg-surface px-2 py-[3px] text-[11px] font-medium text-strong",
        warning:
          "border-warning bg-warning-surface px-2 py-[3px] text-[11px] font-medium text-warning-text",
        destructive:
          "border-destructive-border bg-destructive-surface px-2 py-[3px] text-[11px] font-medium text-destructive-text",
      },
    },
    defaultVariants: {
      variant: "outline",
    },
  },
);

function Badge({
  className,
  variant = "outline",
  asChild = false,
  ...props
}: React.ComponentProps<"span"> &
  VariantProps<typeof badgeVariants> & { asChild?: boolean }) {
  const Comp = asChild ? Slot.Root : "span";

  return (
    <Comp
      data-slot="badge"
      data-variant={variant}
      className={cn(badgeVariants({ variant }), className)}
      {...props}
    />
  );
}

/**
 * Uppercase mono tag for scope and staleness — EXP, STALE, BETA. Deliberately
 * unfilled so it reads as an annotation on the thing, not a status of it.
 */
function ScopeBadge({
  className,
  tone = "warning",
  ...props
}: React.ComponentProps<"span"> & { tone?: "warning" | "neutral" }) {
  return (
    <span
      data-slot="scope-badge"
      className={cn(
        "inline-flex shrink-0 items-center border px-1.5 font-mono text-[9px] leading-[15px] tracking-[0.08em] uppercase",
        tone === "warning"
          ? "border-warning text-warning-text"
          : "border-foreground text-foreground",
        className,
      )}
      {...props}
    />
  );
}

/**
 * Delivery attempts, e.g. 4 / 5. Turns amber once the message is one failure
 * away from eviction, because that is the moment an operator must act.
 */
function AttemptsBadge({
  attempts,
  max,
  className,
  ...props
}: React.ComponentProps<"span"> & { attempts: number; max: number }) {
  const atRisk = max > 0 && attempts >= max - 1;

  return (
    <span
      data-slot="attempts-badge"
      className={cn(
        "inline-flex w-fit shrink-0 items-center border px-2 py-[3px] font-mono text-[11px] tabular",
        atRisk
          ? "border-warning bg-warning-surface text-warning-text"
          : "border-border bg-surface text-strong",
        className,
      )}
      {...props}
    >
      {attempts} / {max} attempts
    </span>
  );
}

export { Badge, badgeVariants, ScopeBadge, AttemptsBadge };
