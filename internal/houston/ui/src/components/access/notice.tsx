import * as React from "react";
import { Info } from "lucide-react";

import { cn } from "@/lib/utils";

/**
 * States a capability the server does not expose yet. Access surfaces lean on
 * this instead of a skeleton, because a skeleton promises data that is coming
 * and here nothing is coming until an endpoint is written.
 */
function DependencyNotice({
  title,
  children,
  className,
  ...props
}: Omit<React.ComponentProps<"div">, "title"> & { title: React.ReactNode }) {
  return (
    <div className={cn("flex gap-3 p-5", className)} {...props}>
      <Info className="mt-px size-4 shrink-0 text-strong" aria-hidden />
      <div className="min-w-0">
        <div className="text-[13px] leading-[18px] font-semibold">{title}</div>
        {children ? (
          <div className="mt-1 text-xs leading-relaxed text-muted-foreground">{children}</div>
        ) : null}
      </div>
    </div>
  );
}

/**
 * The answer to a request that changed nothing — a duplicate role assignment
 * or a duplicate team membership. Nothing failed, so it is not an alert; the
 * operator only needs to know the state they wanted is already the state.
 */
function QuietNotice({ className, ...props }: React.ComponentProps<"div">) {
  return (
    <div
      role="status"
      className={cn("border border-border bg-muted px-2.5 py-2 text-xs text-strong", className)}
      {...props}
    />
  );
}

export { DependencyNotice, QuietNotice };
