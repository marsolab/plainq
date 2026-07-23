import * as React from "react";
import { Switch as SwitchPrimitive } from "radix-ui";

import { cn } from "@/lib/utils";

/**
 * 32×18 square track, 14px square thumb — no radius, switches included.
 * Reserved for settings that persist on toggle; anything needing a save step
 * is a checkbox in a form.
 */
function Switch({
  className,
  size = "default",
  ...props
}: React.ComponentProps<typeof SwitchPrimitive.Root> & {
  size?: "sm" | "default";
}) {
  return (
    <SwitchPrimitive.Root
      data-slot="switch"
      data-size={size}
      className={cn(
        "peer group/switch relative inline-flex shrink-0 items-center p-[2px] transition-colors outline-none",
        "after:absolute after:-inset-x-2 after:-inset-y-1.5",
        "data-[size=default]:h-[18px] data-[size=default]:w-[32px]",
        "data-[size=sm]:h-[14px] data-[size=sm]:w-[24px]",
        "data-checked:bg-primary data-unchecked:bg-border",
        "data-disabled:cursor-not-allowed data-disabled:opacity-45",
        className,
      )}
      {...props}
    >
      <SwitchPrimitive.Thumb
        data-slot="switch-thumb"
        className={cn(
          "pointer-events-none block bg-surface transition-transform",
          "group-data-[size=default]/switch:size-[14px] group-data-[size=sm]/switch:size-[10px]",
          "data-unchecked:translate-x-0",
          "group-data-[size=default]/switch:data-checked:translate-x-[14px]",
          "group-data-[size=sm]/switch:data-checked:translate-x-[10px]",
        )}
      />
    </SwitchPrimitive.Root>
  );
}

export { Switch };
