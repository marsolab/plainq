import { cn } from "@/lib/utils";

/**
 * The dequeue notch: a solid square with a bite taken out of its right edge —
 * a message leaving the queue. Monospaced wordmark so the brand sits in the
 * same voice as the IDs and values it sits above.
 */
function Mark({ size = 24, className }: { size?: number; className?: string }) {
  const notch = Math.round(size * 0.29);

  return (
    <div
      className={cn("relative shrink-0 bg-primary", className)}
      style={{ width: size, height: size }}
      aria-hidden
    >
      <div
        className="absolute right-0 bg-background"
        style={{ width: notch, height: notch, top: (size - notch) / 2 }}
      />
    </div>
  );
}

function Wordmark({
  size = 24,
  showProduct = true,
  className,
}: {
  size?: number;
  showProduct?: boolean;
  className?: string;
}) {
  return (
    <div className={cn("flex items-center gap-2.5", className)}>
      <Mark size={size} />
      <div className="flex flex-col">
        <span className="font-mono text-sm leading-4 font-semibold tracking-[-0.02em]">
          PlainQ
        </span>
        {showProduct ? (
          <span className="font-mono text-[9px] leading-3 tracking-[0.2em] text-muted-foreground">
            HOUSTON
          </span>
        ) : null}
      </div>
    </div>
  );
}

export { Wordmark, Mark };
