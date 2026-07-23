import { formatClock } from "@/lib/format";
import { cn } from "@/lib/utils";

export type SeriesTone = "send" | "receive" | "acknowledge" | "retry";

const STROKE: Record<SeriesTone, string> = {
  send: "stroke-send",
  receive: "stroke-receive",
  acknowledge: "stroke-acknowledge",
  retry: "stroke-retry",
};

const SWATCH: Record<SeriesTone, string> = {
  send: "bg-send",
  receive: "bg-receive",
  acknowledge: "bg-acknowledge",
  retry: "bg-retry",
};

export interface QueueSeries {
  key: string;
  label: string;
  tone: SeriesTone;
  /** Dashed so the series survives greyscale and colour-blind rendering. */
  dashed?: boolean;
}

export interface QueueSeriesPoint {
  t: number;
  [key: string]: number | undefined;
}

interface QueueSeriesChartProps {
  points: readonly QueueSeriesPoint[];
  series: readonly QueueSeries[];
  /** Renders a value with its unit, for the axis and the spoken summary. */
  formatValue: (value: number) => string;
  height?: number;
}

const WIDTH = 640;
const PAD_LEFT = 44;
const PAD_RIGHT = 8;
const PAD_TOP = 8;
const PAD_BOTTOM = 18;

/**
 * Square by construction: hairline horizontal grid, one baseline, mono ticks,
 * straight segments between samples. A smoothed curve would invent readings
 * the collector never took, and an area fill would imply a total.
 *
 * Colour is never the only channel — every series is named in the legend and
 * a second series is dashed.
 */
export function QueueSeriesChart({
  points,
  series,
  formatValue,
  height = 150,
}: QueueSeriesChartProps) {
  const values = points.flatMap((point) =>
    series
      .map((entry) => point[entry.key])
      .filter((value): value is number => typeof value === "number" && Number.isFinite(value)),
  );

  // A flat run of zeros still needs a scale, and an empty one must not divide
  // by zero — 1 keeps the baseline where a reading of 0 belongs.
  const peak = values.length > 0 ? Math.max(...values) : 0;
  const top = peak > 0 ? peak : 1;

  const first = points[0]?.t;
  const last = points[points.length - 1]?.t;
  const span = first !== undefined && last !== undefined && last > first ? last - first : 1;

  const x = (t: number) =>
    PAD_LEFT + ((t - (first ?? 0)) / span) * (WIDTH - PAD_LEFT - PAD_RIGHT);
  const y = (value: number) =>
    PAD_TOP + (1 - value / top) * (height - PAD_TOP - PAD_BOTTOM);

  const gridlines = [0, 0.5, 1];

  const summary = series
    .map((entry) => {
      const readings = points
        .map((point) => point[entry.key])
        .filter((value): value is number => typeof value === "number");
      if (readings.length === 0) return `${entry.label}: no samples`;
      const highest = Math.max(...readings);
      const latest = readings[readings.length - 1]!;
      return `${entry.label}: latest ${formatValue(latest)}, peak ${formatValue(highest)}`;
    })
    .join(". ");

  return (
    <div className="flex flex-col gap-2">
      <svg
        viewBox={`0 0 ${WIDTH} ${height}`}
        role="img"
        aria-label={summary}
        preserveAspectRatio="none"
        className="block h-auto w-full"
        style={{ height }}
      >
        {gridlines.map((fraction) => {
          const line = PAD_TOP + fraction * (height - PAD_TOP - PAD_BOTTOM);
          return (
            <g key={fraction}>
              <line
                x1={PAD_LEFT}
                x2={WIDTH - PAD_RIGHT}
                y1={line}
                y2={line}
                className="stroke-border"
                strokeWidth={1}
                vectorEffect="non-scaling-stroke"
              />
              <text
                x={PAD_LEFT - 6}
                y={line + 3}
                textAnchor="end"
                className="fill-muted-foreground font-mono text-[9px]"
              >
                {formatValue(top * (1 - fraction))}
              </text>
            </g>
          );
        })}

        {series.map((entry) => {
          // A gap in one series breaks the line and starts a new subpath: a
          // segment drawn across missing samples would claim readings the
          // collector never took.
          let drawing = false;
          const path = points
            .map((point) => {
              const value = point[entry.key];
              if (typeof value !== "number" || !Number.isFinite(value)) {
                drawing = false;
                return null;
              }
              const command = drawing ? "L" : "M";
              drawing = true;
              return `${command}${x(point.t).toFixed(2)},${y(value).toFixed(2)}`;
            })
            .filter((segment): segment is string => segment !== null)
            .join(" ");

          if (path === "") return null;

          return (
            <path
              key={entry.key}
              d={path}
              fill="none"
              strokeWidth={1.5}
              vectorEffect="non-scaling-stroke"
              strokeDasharray={entry.dashed ? "4 3" : undefined}
              className={STROKE[entry.tone]}
            />
          );
        })}

        {first !== undefined ? (
          <text
            x={PAD_LEFT}
            y={height - 4}
            className="fill-muted-foreground font-mono text-[9px]"
          >
            {formatClock(first)}
          </text>
        ) : null}
        {last !== undefined ? (
          <text
            x={WIDTH - PAD_RIGHT}
            y={height - 4}
            textAnchor="end"
            className="fill-muted-foreground font-mono text-[9px]"
          >
            {formatClock(last)}
          </text>
        ) : null}
      </svg>

      <div className="flex flex-wrap items-center gap-3">
        {series.map((entry) => (
          <span
            key={entry.key}
            className="inline-flex items-center gap-1.5 text-[10px] text-strong"
          >
            <span
              aria-hidden
              className={cn("inline-block size-[7px] shrink-0", SWATCH[entry.tone], entry.dashed && "opacity-70")}
            />
            {entry.label}
          </span>
        ))}
      </div>
    </div>
  );
}
