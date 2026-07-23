"use client";

import * as React from "react";
import { Checkbox as CheckboxPrimitive } from "radix-ui";
import { Check } from "lucide-react";

import { cn } from "@/lib/utils";

/** 15px square. Checked fills solid; unchecked is a hairline on white. */
function Checkbox({
  className,
  ...props
}: React.ComponentProps<typeof CheckboxPrimitive.Root>) {
  return (
    <CheckboxPrimitive.Root
      data-slot="checkbox"
      className={cn(
        "peer relative flex size-[15px] shrink-0 items-center justify-center border border-muted-foreground bg-surface transition-colors outline-none",
        // Widens the hit target without changing the drawn box.
        "after:absolute after:-inset-x-2 after:-inset-y-1.5",
        "data-checked:border-primary data-checked:bg-primary data-checked:text-primary-foreground",
        "aria-invalid:border-destructive",
        "disabled:cursor-not-allowed disabled:border-border disabled:bg-muted disabled:text-subtle",
        "group-has-disabled/field:opacity-50",
        className,
      )}
      {...props}
    >
      <CheckboxPrimitive.Indicator
        data-slot="checkbox-indicator"
        className="grid place-content-center text-current"
      >
        <Check className="size-[11px]" strokeWidth={3} aria-hidden />
      </CheckboxPrimitive.Indicator>
    </CheckboxPrimitive.Root>
  );
}

export { Checkbox };
