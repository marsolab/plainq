"use client";

import { cn } from "@/lib/utils";

export interface SegmentedOption<T extends string> {
  value: T;
  label: string;
  /** Rendered as the control's tooltip — always says *why* it is unavailable. */
  disabled?: string;
}

interface SegmentedProps<T extends string> {
  value: T;
  options: SegmentedOption<T>[];
  onValueChange: (value: T) => void;
  label: string;
  /** Mono 10px for range presets; Inter 11px for encoding switches. */
  mono?: boolean;
  className?: string;
}

/**
 * A one-of-N switch between views of the same thing — payload encodings, time
 * ranges. Not a tab (it never changes what is on the page, only how it is
 * shown) and not a button group (exactly one segment is always active).
 */
export function Segmented<T extends string>({
  value,
  options,
  onValueChange,
  label,
  mono = false,
  className,
}: SegmentedProps<T>) {
  return (
    <div
      role="radiogroup"
      aria-label={label}
      className={cn("inline-flex w-fit border border-border bg-surface", className)}
    >
      {options.map((option, index) => {
        const active = option.value === value;
        return (
          <button
            key={option.value}
            type="button"
            role="radio"
            aria-checked={active}
            disabled={Boolean(option.disabled)}
            title={option.disabled}
            onClick={() => onValueChange(option.value)}
            className={cn(
              "px-2.5 py-[3px] font-medium transition-colors",
              mono ? "font-mono text-[10px]" : "text-[11px]",
              index > 0 && "border-l border-border",
              active
                ? "bg-primary text-primary-foreground"
                : "text-strong hover:bg-muted",
              option.disabled && "cursor-not-allowed text-subtle hover:bg-transparent",
            )}
          >
            {option.label}
          </button>
        );
      })}
    </div>
  );
}
