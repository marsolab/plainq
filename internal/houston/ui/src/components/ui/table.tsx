"use client";

import * as React from "react";

import { cn } from "@/lib/utils";

function Table({ className, ...props }: React.ComponentProps<"table">) {
  return (
    <div data-slot="table-container" className="relative w-full overflow-x-auto">
      <table
        data-slot="table"
        className={cn("w-full border-collapse text-[13px]", className)}
        {...props}
      />
    </div>
  );
}

function TableHeader({ className, ...props }: React.ComponentProps<"thead">) {
  return <thead data-slot="table-header" className={cn(className)} {...props} />;
}

function TableBody({ className, ...props }: React.ComponentProps<"tbody">) {
  return (
    <tbody
      data-slot="table-body"
      className={cn("[&_tr:last-child>td]:border-b-0", className)}
      {...props}
    />
  );
}

function TableFooter({ className, ...props }: React.ComponentProps<"tfoot">) {
  return (
    <tfoot
      data-slot="table-footer"
      className={cn("border-t bg-muted font-medium", className)}
      {...props}
    />
  );
}

function TableRow({ className, ...props }: React.ComponentProps<"tr">) {
  return (
    <tr
      data-slot="table-row"
      className={cn(
        "transition-colors hover:bg-muted/60 data-[state=selected]:bg-muted",
        className,
      )}
      {...props}
    />
  );
}

function TableHead({
  className,
  numeric,
  ...props
}: React.ComponentProps<"th"> & { numeric?: boolean }) {
  return (
    <th
      data-slot="table-head"
      className={cn(
        "h-9 border-b border-border px-4 align-middle text-xs font-medium whitespace-nowrap text-muted-foreground",
        numeric ? "text-right" : "text-left",
        className,
      )}
      {...props}
    />
  );
}

function TableCell({
  className,
  numeric,
  ...props
}: React.ComponentProps<"td"> & { numeric?: boolean }) {
  return (
    <td
      data-slot="table-cell"
      className={cn(
        "border-b border-border px-4 py-3 align-middle whitespace-nowrap",
        numeric && "text-right font-mono text-xs tabular",
        className,
      )}
      {...props}
    />
  );
}

/**
 * Primary cell: a name on top, its immutable ID in mono underneath. Used
 * wherever a row stands for an addressable resource.
 */
function TableIdentityCell({
  name,
  id,
  href,
  className,
  ...props
}: Omit<React.ComponentProps<"td">, "id"> & {
  name: React.ReactNode;
  id?: React.ReactNode;
  href?: string;
}) {
  return (
    <TableCell className={cn("py-3", className)} {...props}>
      {href ? (
        <a href={href} className="block text-[13px] leading-[18px] font-semibold hover:underline">
          {name}
        </a>
      ) : (
        <span className="block text-[13px] leading-[18px] font-semibold">{name}</span>
      )}
      {id ? (
        <span className="block font-mono text-[11px] leading-[15px] text-muted-foreground">
          {id}
        </span>
      ) : null}
    </TableCell>
  );
}

function TableCaption({ className, ...props }: React.ComponentProps<"caption">) {
  return (
    <caption
      data-slot="table-caption"
      className={cn("mt-4 text-xs text-muted-foreground", className)}
      {...props}
    />
  );
}

export {
  Table,
  TableHeader,
  TableBody,
  TableFooter,
  TableHead,
  TableRow,
  TableCell,
  TableIdentityCell,
  TableCaption,
};
