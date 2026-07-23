import * as React from "react";
import { Label as LabelPrimitive } from "radix-ui";

import { cn } from "@/lib/utils";

function Label({
  className,
  ...props
}: React.ComponentProps<typeof LabelPrimitive.Root>) {
  return (
    <LabelPrimitive.Root
      data-slot="label"
      className={cn(
        "flex items-center gap-2 text-xs leading-none font-medium text-strong select-none",
        "group-data-[disabled=true]:pointer-events-none group-data-[disabled=true]:text-subtle",
        "peer-disabled:cursor-not-allowed peer-disabled:text-subtle",
        className,
      )}
      {...props}
    />
  );
}

export { Label };
