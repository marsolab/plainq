import { cn } from "@/lib/utils";

/**
 * A skeleton occupies exactly the space the real content will, so nothing
 * reflows when data lands. Deliberately static: a pulse that fades to
 * transparent reads as flicker on a dense instrument panel.
 */
function Skeleton({ className, ...props }: React.ComponentProps<"div">) {
  return (
    <div
      data-slot="skeleton"
      aria-hidden
      className={cn("bg-[#ececec]", className)}
      {...props}
    />
  );
}

export { Skeleton };
