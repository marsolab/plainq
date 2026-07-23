"use client";

import * as React from "react";

import { cn } from "@/lib/utils";

/**
 * A hairline box of mutually exclusive choices. `Tabs` is the underlined
 * navigation control; this is a filter that sits inside a header, so it needs
 * a filled selected state instead of a rule.
 */
export interface SegmentedOption<T extends string> {
  value: T;
  label: React.ReactNode;
}

export function Segmented<T extends string>({
  options,
  value,
  onChange,
  label,
  variant = "mono",
  className,
}: {
  options: ReadonlyArray<SegmentedOption<T>>;
  value: T;
  onChange: (value: T) => void;
  label: string;
  variant?: "mono" | "text";
  className?: string;
}) {
  return (
    <div
      role="group"
      aria-label={label}
      className={cn("flex w-fit border border-border bg-surface", className)}
    >
      {options.map((option, index) => {
        const selected = option.value === value;

        return (
          <button
            key={option.value}
            type="button"
            aria-pressed={selected}
            onClick={() => onChange(option.value)}
            className={cn(
              "cursor-pointer whitespace-nowrap transition-colors",
              variant === "mono"
                ? "px-2.5 py-1.5 font-mono text-[11px]"
                : "px-2.5 py-[3px] text-[11px] font-medium",
              index > 0 && "border-l border-border",
              selected
                ? "bg-primary text-primary-foreground"
                : cn(
                    variant === "mono" ? "text-muted-foreground" : "text-strong",
                    "hover:bg-muted hover:text-foreground",
                  ),
            )}
          >
            {option.label}
          </button>
        );
      })}
    </div>
  );
}
