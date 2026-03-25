import { Separator as BaseSeparator } from "@base-ui/react/separator";
import { cn } from "@/lib/utils";
import type { ComponentPropsWithoutRef } from "react";

function Separator({
  className,
  ...props
}: ComponentPropsWithoutRef<typeof BaseSeparator>) {
  return (
    <BaseSeparator
      className={cn("shrink-0 bg-border h-px w-full", className)}
      {...props}
    />
  );
}

export { Separator };
