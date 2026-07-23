import * as React from "react";
import type { LucideIcon } from "lucide-react";

import { cn } from "@/lib/utils";

/**
 * First use is the only place the product gets to explain itself, so an empty
 * state teaches the lifecycle in one sentence and offers the single action
 * that ends the emptiness.
 */
function EmptyState({
  icon: Icon,
  title,
  description,
  action,
  children,
  className,
  ...props
}: Omit<React.ComponentProps<"div">, "title"> & {
  icon?: LucideIcon;
  title: React.ReactNode;
  description?: React.ReactNode;
  action?: React.ReactNode;
}) {
  return (
    <div
      data-slot="empty-state"
      className={cn(
        "flex flex-col items-center gap-3 px-10 py-12 text-center",
        className,
      )}
      {...props}
    >
      {Icon ? <Icon className="size-[22px] text-muted-foreground" aria-hidden /> : null}
      <div className="text-sm font-semibold">{title}</div>
      {description ? (
        <p className="max-w-[330px] text-xs leading-relaxed text-muted-foreground">
          {description}
        </p>
      ) : null}
      {children}
      {action ? <div className="mt-2">{action}</div> : null}
    </div>
  );
}

/**
 * VISIBLE → IN-FLIGHT → ACKNOWLEDGED. The one diagram in the product, shown
 * where an operator has nothing else to look at yet.
 */
function LifecycleLegend({ className, ...props }: React.ComponentProps<"div">) {
  return (
    <div
      data-slot="lifecycle-legend"
      className={cn(
        "mt-1 flex items-center gap-1.5 font-mono text-[10px] text-muted-foreground",
        className,
      )}
      {...props}
    >
      <span className="border border-border px-2 py-[3px]">VISIBLE</span>
      <span aria-hidden>→</span>
      <span className="border border-[#bfdbfe] bg-[#eff6ff] px-2 py-[3px] text-send-text">
        IN-FLIGHT
      </span>
      <span aria-hidden>→</span>
      <span className="border border-[#e9d5ff] bg-[#faf5ff] px-2 py-[3px] text-acknowledge-text">
        ACKNOWLEDGED
      </span>
    </div>
  );
}

export { EmptyState, LifecycleLegend };
