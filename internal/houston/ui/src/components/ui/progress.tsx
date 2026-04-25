import { Progress as BaseProgress } from "@base-ui/react/progress";
import { cn } from "@/lib/utils";
import type { ComponentPropsWithoutRef } from "react";

function Progress({
  className,
  ...props
}: ComponentPropsWithoutRef<typeof BaseProgress.Root>) {
  return (
    <BaseProgress.Root className={cn("relative", className)} {...props}>
      <BaseProgress.Track className="relative h-2 w-full overflow-hidden rounded-full bg-primary/20">
        <BaseProgress.Indicator className="h-full bg-primary transition-all" />
      </BaseProgress.Track>
    </BaseProgress.Root>
  );
}

export { Progress };
