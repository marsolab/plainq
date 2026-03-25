import { Tooltip as BaseTooltip } from "@base-ui/react/tooltip";
import { cn } from "@/lib/utils";
import type { ComponentPropsWithoutRef } from "react";

const Tooltip = BaseTooltip.Root;
const TooltipTrigger = BaseTooltip.Trigger;

function TooltipPopup({
  className,
  ...props
}: ComponentPropsWithoutRef<typeof BaseTooltip.Popup>) {
  return (
    <BaseTooltip.Portal>
      <BaseTooltip.Positioner>
        <BaseTooltip.Popup
          className={cn(
            "z-50 overflow-hidden rounded-md bg-primary px-3 py-1.5 text-xs text-primary-foreground shadow-md data-[ending-style]:opacity-0 data-[starting-style]:opacity-0",
            className,
          )}
          {...props}
        />
      </BaseTooltip.Positioner>
    </BaseTooltip.Portal>
  );
}

export { Tooltip, TooltipTrigger, TooltipPopup };
