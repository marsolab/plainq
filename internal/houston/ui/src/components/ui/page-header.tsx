import * as React from "react";

import { cn } from "@/lib/utils";

/**
 * Page title, one line of what this surface is for, and the actions that
 * belong to it. The primary action is the only filled control on the page.
 */
function PageHeader({
  title,
  description,
  actions,
  className,
  children,
  ...props
}: Omit<React.ComponentProps<"div">, "title"> & {
  title: React.ReactNode;
  description?: React.ReactNode;
  actions?: React.ReactNode;
}) {
  return (
    <div
      data-slot="page-header"
      className={cn("mb-5 flex items-end justify-between gap-6", className)}
      {...props}
    >
      <div className="min-w-0">
        <h1 className="text-2xl leading-[30px] font-semibold tracking-[-0.02em]">{title}</h1>
        {description ? (
          <p className="mt-1 text-[13px] leading-[18px] text-muted-foreground">{description}</p>
        ) : null}
        {children}
      </div>
      {actions ? <div className="flex shrink-0 items-center gap-2">{actions}</div> : null}
    </div>
  );
}

/** Section heading inside a page — one step down from the page title. */
function SectionHeader({
  title,
  description,
  actions,
  className,
  ...props
}: Omit<React.ComponentProps<"div">, "title"> & {
  title: React.ReactNode;
  description?: React.ReactNode;
  actions?: React.ReactNode;
}) {
  return (
    <div
      data-slot="section-header"
      className={cn("flex items-end justify-between gap-6", className)}
      {...props}
    >
      <div className="min-w-0">
        <h2 className="text-[13px] font-semibold">{title}</h2>
        {description ? (
          <p className="mt-0.5 text-xs text-muted-foreground">{description}</p>
        ) : null}
      </div>
      {actions ? <div className="flex shrink-0 items-center gap-2">{actions}</div> : null}
    </div>
  );
}

export { PageHeader, SectionHeader };
