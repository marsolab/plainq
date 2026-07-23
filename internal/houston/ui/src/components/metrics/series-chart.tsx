"use client";

import {
  CartesianGrid,
  Line,
  LineChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";

import { Skeleton } from "@/components/ui/skeleton";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { formatClock } from "@/lib/format";
import { cn } from "@/lib/utils";
import { useChartTokens, type ChartTokens } from "./chart-tokens";
import { formatAxisTime } from "./format-metrics";
import { SeriesSwatch, toneColor, type SeriesSpec } from "./lifecycle";

export type ChartRow = { t: number } & Record<string, number>;

interface SeriesChartProps {
  data: ReadonlyArray<ChartRow>;
  series: readonly SeriesSpec[];
  height: number;
  /** Renders a value with its unit — tooltip, table and summary all share it. */
  formatValue: (value: number) => string;
  /** Y axis ticks, where the unit is implied by the chart's own label. */
  formatTick?: (value: number) => string;
  /** Read by screen readers in place of the plot. */
  summary: string;
}

/**
 * Square by construction: hairline horizontal grid, a single baseline, mono
 * ticks, and a bordered tooltip with no shadow. Curves are straight segments —
 * a smoothed line invents readings between samples.
 */
export function SeriesChart({
  data,
  series,
  height,
  formatValue,
  formatTick,
  summary,
}: SeriesChartProps) {
  const tokens = useChartTokens();

  if (!tokens) return <Skeleton style={{ height }} className="w-full" />;

  return (
    <div role="img" aria-label={summary} style={{ height }} className="w-full">
      <ResponsiveContainer width="100%" height="100%">
        <LineChart data={data as ChartRow[]} margin={{ top: 6, right: 8, bottom: 0, left: 0 }}>
          <CartesianGrid vertical={false} stroke={tokens.grid} />
          <XAxis
            dataKey="t"
            type="number"
            scale="time"
            domain={["dataMin", "dataMax"]}
            tickFormatter={formatAxisTime}
            tick={axisTick(tokens)}
            tickLine={false}
            axisLine={{ stroke: tokens.axis }}
            minTickGap={48}
          />
          <YAxis
            width={40}
            tickFormatter={formatTick}
            tick={axisTick(tokens)}
            tickLine={false}
            axisLine={false}
          />
          <Tooltip
            cursor={{ stroke: tokens.axis, strokeWidth: 1 }}
            isAnimationActive={false}
            content={<SeriesTooltip series={series} formatValue={formatValue} />}
          />
          {series.map((entry) => (
            <Line
              key={entry.key}
              type="linear"
              dataKey={entry.key}
              name={entry.label}
              stroke={toneColor(tokens, entry.tone)}
              strokeWidth={2}
              strokeDasharray={entry.dashed ? "5 3" : undefined}
              dot={false}
              activeDot={{ r: 3, strokeWidth: 0 }}
              isAnimationActive={false}
            />
          ))}
        </LineChart>
      </ResponsiveContainer>
    </div>
  );
}

function axisTick(tokens: ChartTokens) {
  return {
    fill: tokens.label,
    fontSize: 11,
    fontFamily: "var(--font-mono)",
  };
}

interface SeriesTooltipProps {
  active?: boolean;
  label?: string | number;
  payload?: ReadonlyArray<{ dataKey?: string | number; value?: number | string }>;
  series: readonly SeriesSpec[];
  formatValue: (value: number) => string;
}

function SeriesTooltip({ active, label, payload, series, formatValue }: SeriesTooltipProps) {
  if (!active || !payload || payload.length === 0) return null;

  return (
    <div className="border border-border bg-surface px-2.5 py-2">
      <div className="font-mono text-[11px] text-muted-foreground">
        {typeof label === "number" ? formatClock(label) : label}
      </div>
      <div className="mt-1.5 flex flex-col gap-1">
        {series.map((entry) => {
          const point = payload.find((item) => item.dataKey === entry.key);
          if (!point || typeof point.value !== "number") return null;

          return (
            <div key={entry.key} className="flex items-center gap-2 text-xs">
              <SeriesSwatch tone={entry.tone} />
              <span>{entry.label}</span>
              <span className="ml-auto pl-4 font-mono text-xs tabular">
                {formatValue(point.value)}
              </span>
            </div>
          );
        })}
      </div>
    </div>
  );
}

/**
 * The same samples as a table. Offered beside every chart: a plot is a summary,
 * and an operator correlating against logs needs the readings themselves.
 */
export function SeriesTable({
  data,
  series,
  formatValue,
  className,
}: {
  data: ReadonlyArray<ChartRow>;
  series: readonly SeriesSpec[];
  formatValue: (value: number) => string;
  className?: string;
}) {
  return (
    <div className={cn("max-h-[248px] overflow-y-auto border border-border", className)}>
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead className="sticky top-0 bg-surface">Sample</TableHead>
            {series.map((entry) => (
              <TableHead key={entry.key} numeric className="sticky top-0 bg-surface">
                {entry.label}
              </TableHead>
            ))}
          </TableRow>
        </TableHeader>
        <TableBody>
          {data.map((row) => (
            <TableRow key={row.t}>
              <TableCell className="font-mono text-xs tabular">{formatClock(row.t)}</TableCell>
              {series.map((entry) => (
                <TableCell key={entry.key} numeric>
                  {formatValue(row[entry.key] ?? 0)}
                </TableCell>
              ))}
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </div>
  );
}

/**
 * One sentence of what the plot shows, rendered as text and handed to screen
 * readers as the chart's label. Averages and peaks only — nothing the samples
 * do not contain.
 */
export function describeSeries(
  data: ReadonlyArray<ChartRow>,
  series: readonly SeriesSpec[],
  windowLabel: string,
  formatValue: (value: number) => string,
): string {
  if (data.length === 0) return `${windowLabel} window · no samples`;

  const parts = series.map((entry) => {
    const values = data.map((row) => row[entry.key] ?? 0);
    const average = values.reduce((sum, value) => sum + value, 0) / values.length;
    const peak = values.reduce((max, value) => Math.max(max, value), 0);
    return `${entry.label.toLowerCase()} avg ${formatValue(average)}, peak ${formatValue(peak)}`;
  });

  return `${windowLabel} window, ${data.length} samples · ${parts.join(" · ")}`;
}
