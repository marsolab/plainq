"use client";

import * as React from "react";
import { Dialog as DialogPrimitive } from "radix-ui";
import { X } from "lucide-react";

import { cn } from "@/lib/utils";

/**
 * A right-anchored sheet. The foundation has a centred dialog for explicit
 * confirmation; Access needs an editing surface that keeps the row it came
 * from in view, which is a different job, so it lives here rather than in the
 * shared component set.
 */
function Sheet({ ...props }: React.ComponentProps<typeof DialogPrimitive.Root>) {
  return <DialogPrimitive.Root data-slot="sheet" {...props} />;
}

function SheetContent({
  className,
  title,
  description,
  header,
  children,
  ...props
}: Omit<React.ComponentProps<typeof DialogPrimitive.Content>, "title"> & {
  title: React.ReactNode;
  description?: React.ReactNode;
  /** Replaces the default title block when the header carries status. */
  header?: React.ReactNode;
}) {
  return (
    <DialogPrimitive.Portal>
      <DialogPrimitive.Overlay
        className={cn(
          "fixed inset-0 z-50 bg-foreground/10 duration-100",
          // Radix emits data-state="open"|"closed"; a bare `data-open:` variant
          // compiles to [data-open], which nothing ever sets.
          "data-[state=open]:animate-in data-[state=open]:fade-in-0",
          "data-[state=closed]:animate-out data-[state=closed]:fade-out-0",
        )}
      />
      <DialogPrimitive.Content
        data-slot="sheet-content"
        className={cn(
          "fixed inset-y-0 right-0 z-50 flex w-full max-w-[480px] flex-col overflow-y-auto",
          "border-l border-border-strong bg-surface text-[13px] text-foreground duration-150 outline-none",
          "data-[state=open]:animate-in data-[state=open]:slide-in-from-right",
          "data-[state=closed]:animate-out data-[state=closed]:slide-out-to-right",
          className,
        )}
        {...props}
      >
        <div className="flex shrink-0 items-start justify-between gap-4 border-b border-border px-5 py-4">
          <div className="min-w-0">
            <DialogPrimitive.Title className="text-[15px] leading-5 font-semibold">
              {title}
            </DialogPrimitive.Title>
            {header ?? null}
            {description ? (
              <DialogPrimitive.Description className="mt-1 text-xs text-muted-foreground">
                {description}
              </DialogPrimitive.Description>
            ) : (
              <DialogPrimitive.Description className="sr-only">
                {typeof title === "string" ? title : "Details"}
              </DialogPrimitive.Description>
            )}
          </div>
          <DialogPrimitive.Close
            aria-label="Close"
            className="-mr-1 inline-flex size-6 shrink-0 cursor-pointer items-center justify-center text-muted-foreground hover:text-foreground"
          >
            <X className="size-[15px]" aria-hidden />
          </DialogPrimitive.Close>
        </div>
        {children}
      </DialogPrimitive.Content>
    </DialogPrimitive.Portal>
  );
}

/** Bordered stack of editable rows — roles, teams, members. */
function SheetSection({
  title,
  action,
  note,
  className,
  children,
  ...props
}: Omit<React.ComponentProps<"div">, "title"> & {
  title: React.ReactNode;
  action?: React.ReactNode;
  note?: React.ReactNode;
}) {
  return (
    <div
      className={cn("border-b border-border px-5 py-4", className)}
      {...props}
    >
      <div className="mb-2.5 flex items-center justify-between gap-3">
        <span className="text-xs font-semibold">{title}</span>
        {action ? <div className="flex items-center gap-2">{action}</div> : null}
      </div>
      {children}
      {note ? <div className="mt-2 text-[11px] text-subtle">{note}</div> : null}
    </div>
  );
}

/** One row inside a `SheetSection`: label over hint, trailing control. */
function SheetRow({
  label,
  hint,
  action,
  className,
  ...props
}: React.ComponentProps<"div"> & {
  label: React.ReactNode;
  hint?: React.ReactNode;
  action?: React.ReactNode;
}) {
  return (
    <div
      className={cn(
        "flex items-center justify-between gap-3 border border-border px-2.5 py-2 not-first:border-t-0",
        className,
      )}
      {...props}
    >
      <div className="min-w-0">
        <span className="block text-[13px] leading-[17px] font-medium">{label}</span>
        {hint ? (
          <span className="block text-[11px] text-muted-foreground">{hint}</span>
        ) : null}
      </div>
      {action ? <div className="flex shrink-0 items-center gap-2">{action}</div> : null}
    </div>
  );
}

export { Sheet, SheetContent, SheetSection, SheetRow };
