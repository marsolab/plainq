import * as React from "react";

import { cn } from "@/lib/utils";

/**
 * The one container in the system: a white surface inside a single hairline
 * border, square. There is no elevated card and no nested panel — depth is
 * carried by borders, never by shadow.
 */
function Panel({ className, ...props }: React.ComponentProps<"section">) {
  return (
    <section
      data-slot="panel"
      className={cn("border border-border bg-surface", className)}
      {...props}
    />
  );
}

/**
 * Mono uppercase caption bar. Names the panel's contents in the same voice as
 * the values inside it.
 */
function PanelHeader({
  className,
  children,
  action,
  ...props
}: React.ComponentProps<"div"> & { action?: React.ReactNode }) {
  return (
    <div
      data-slot="panel-header"
      className={cn(
        "flex min-h-9 items-center gap-3 border-b border-border px-3 py-2",
        className,
      )}
      {...props}
    >
      <span className="caption truncate">{children}</span>
      {action ? <div className="ml-auto flex items-center gap-2">{action}</div> : null}
    </div>
  );
}

/**
 * Sentence-case header for panels that read as content rather than as
 * instrumentation — dialogs, forms, summaries.
 */
function PanelTitleBar({
  className,
  title,
  description,
  action,
  ...props
}: Omit<React.ComponentProps<"div">, "title"> & {
  title: React.ReactNode;
  description?: React.ReactNode;
  action?: React.ReactNode;
}) {
  return (
    <div
      data-slot="panel-title-bar"
      className={cn(
        "flex items-start gap-3 border-b border-border px-4 py-3",
        className,
      )}
      {...props}
    >
      <div className="min-w-0">
        <div className="text-[13px] font-semibold">{title}</div>
        {description ? (
          <div className="mt-0.5 text-xs text-muted-foreground">{description}</div>
        ) : null}
      </div>
      {action ? <div className="ml-auto flex shrink-0 items-center gap-2">{action}</div> : null}
    </div>
  );
}

function PanelBody({ className, ...props }: React.ComponentProps<"div">) {
  return <div data-slot="panel-body" className={cn("p-4", className)} {...props} />;
}

function PanelFooter({ className, ...props }: React.ComponentProps<"div">) {
  return (
    <div
      data-slot="panel-footer"
      className={cn(
        "flex items-center justify-between gap-3 border-t border-border px-4 py-2.5",
        className,
      )}
      {...props}
    />
  );
}

/**
 * Destructive actions live at the bottom of a configuration surface, fenced
 * off and labelled, never inline with ordinary settings.
 */
function DangerZone({
  className,
  title = "Danger zone",
  description,
  children,
  ...props
}: Omit<React.ComponentProps<"div">, "title"> & {
  title?: React.ReactNode;
  description?: React.ReactNode;
}) {
  return (
    <div
      data-slot="danger-zone"
      className={cn("border border-destructive-border bg-surface", className)}
      {...props}
    >
      <div className="border-b border-destructive-border bg-destructive-surface px-4 py-2">
        <span className="font-mono text-[10px] tracking-[0.1em] text-destructive-text uppercase">
          {title}
        </span>
      </div>
      <div className="flex items-center gap-4 p-4">
        {description ? (
          <p className="text-xs leading-relaxed text-muted-foreground">{description}</p>
        ) : null}
        <div className="ml-auto flex shrink-0 items-center gap-2">{children}</div>
      </div>
    </div>
  );
}

export { Panel, PanelHeader, PanelTitleBar, PanelBody, PanelFooter, DangerZone };
