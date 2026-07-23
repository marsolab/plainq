/**
 * The publish-vs-delivery plot standing in for a series that has no samples —
 * either because the window is genuinely empty or because the collector is
 * off.
 *
 * Axes stay; the plot area is hatched and explicitly empty. A flat line at
 * zero would claim the topic is idle, which is a different fact from "nothing
 * was measured" — so the plot never draws one.
 */
export function PublishDeliveryPlot({
  title = "No samples in this range",
  reason,
}: {
  title?: string;
  reason: string;
}) {
  return (
    <div className="relative">
      <svg
        viewBox="0 0 580 200"
        role="img"
        aria-label={`Publish and delivery rate over time: ${title.toLowerCase()}. ${reason}`}
        className="block w-full"
      >
        <defs>
          <pattern
            id="pubsub-plot-hatch"
            width="20"
            height="20"
            patternUnits="userSpaceOnUse"
            patternTransform="rotate(45)"
          >
            <rect width="20" height="20" className="fill-surface" />
            <rect width="10" height="20" className="fill-background" />
          </pattern>
        </defs>

        <rect x="36" y="16" width="534" height="144" fill="url(#pubsub-plot-hatch)" />

        <g className="stroke-border">
          <line x1="36" y1="40" x2="570" y2="40" />
          <line x1="36" y1="80" x2="570" y2="80" />
          <line x1="36" y1="120" x2="570" y2="120" />
        </g>

        <g className="stroke-subtle">
          <line x1="36" y1="16" x2="36" y2="160" />
          <line x1="36" y1="160" x2="570" y2="160" />
        </g>
      </svg>

      <div className="absolute inset-0 flex flex-col items-center justify-center gap-1.5 px-6 text-center">
        <span className="text-xs font-medium text-strong">{title}</span>
        <span className="text-[11px] text-muted-foreground">{reason}</span>
      </div>
    </div>
  );
}
