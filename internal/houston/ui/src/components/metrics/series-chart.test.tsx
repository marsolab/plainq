import { beforeEach, describe, expect, mock, test } from "bun:test";
import { cloneElement, type ReactElement, type ReactNode } from "react";
import { renderToStaticMarkup } from "react-dom/server";

import type { ChartRow } from "@/lib/types";
import type { SeriesSpec } from "./lifecycle";

const renderedLines: Array<Record<string, unknown>> = [];
let tooltipContent: ReactElement<Record<string, unknown>> | null = null;

function PassThrough({ children }: { children?: ReactNode }) {
  return <>{children}</>;
}

mock.module("recharts", () => ({
  CartesianGrid: () => null,
  Line: (props: Record<string, unknown>) => {
    renderedLines.push(props);
    return null;
  },
  LineChart: PassThrough,
  ResponsiveContainer: PassThrough,
  Tooltip: ({ content }: { content?: ReactElement<Record<string, unknown>> }) => {
    tooltipContent = content ?? null;
    return null;
  },
  XAxis: () => null,
  YAxis: () => null,
}));

mock.module("./chart-tokens", () => ({
  useChartTokens: () => ({
    send: "blue",
    receive: "green",
    acknowledge: "purple",
    retry: "orange",
    grid: "gray",
    axis: "gray",
    label: "gray",
  }),
}));

const { SeriesChart, SeriesTable, countSeriesSamples, describeSeries } = await import(
  "./series-chart"
);

const series: readonly SeriesSpec[] = [
  {
    key: "rate",
    label: "Rate",
    tone: "send",
    interpolation: "linear",
  },
  {
    key: "active",
    label: "Active",
    tone: "receive",
    interpolation: "stepAfter",
  },
];

beforeEach(() => {
  renderedLines.length = 0;
  tooltipContent = null;
});

describe("SeriesChart", () => {
  test("preserves gaps and uses each series interpolation", () => {
    renderToStaticMarkup(
      <SeriesChart
        data={[{ t: 1000, rate: 2, active: 3 }]}
        series={series}
        height={200}
        formatValue={(value) => String(value)}
        summary="Telemetry series"
      />,
    );

    expect(
      renderedLines.map(({ dataKey, type, connectNulls }) => ({
        dataKey,
        type,
        connectNulls,
      })),
    ).toEqual([
      { dataKey: "rate", type: "linear", connectNulls: false },
      { dataKey: "active", type: "stepAfter", connectNulls: false },
    ]);
  });

  test("renders unavailable tooltip values for null and absent series", () => {
    renderToStaticMarkup(
      <SeriesChart
        data={[{ t: 1000, rate: null }]}
        series={series}
        height={200}
        formatValue={(value) => `value:${value}`}
        summary="Telemetry series"
      />,
    );

    expect(tooltipContent).not.toBeNull();
    const markup = renderToStaticMarkup(
      cloneElement(tooltipContent!, {
        active: true,
        label: 1000,
        payload: [{ dataKey: "rate", value: null }],
      }),
    );

    expect(markup.match(/Unavailable/g)).toHaveLength(2);
    expect(markup).not.toContain("value:0");
  });
});

describe("SeriesTable", () => {
  test("renders unavailable for null and absent values without changing zero", () => {
    const data: ChartRow[] = [
      { t: 1000, rate: null },
      { t: 2000 },
      { t: 3000, rate: 0 },
    ];

    const markup = renderToStaticMarkup(
      <SeriesTable
        data={data}
        series={[series[0]]}
        formatValue={(value) => `value:${value}`}
      />,
    );

    expect(markup.match(/Unavailable/g)).toHaveLength(2);
    expect(markup.match(/value:0/g)).toHaveLength(1);
  });
});

describe("describeSeries", () => {
  test("excludes null from averages and peaks while keeping measured zero", () => {
    const summary = describeSeries(
      [
        { t: 1000, rate: null },
        { t: 2000, rate: 0 },
        { t: 3000, rate: 10 },
      ],
      [series[0]],
      "1h",
      (value) => String(value),
    );

    expect(summary).toBe("1h window, 2 samples · rate avg 5, peak 10");
  });

  test("describes rows with no measured values as no samples", () => {
    const summary = describeSeries(
      [{ t: 1000, rate: null }, { t: 2000 }],
      [series[0]],
      "1h",
      (value) => String(value),
    );

    expect(summary).toBe("1h window · no samples");
  });

  test("counts only timestamps carrying a finite measured value", () => {
    expect(
      countSeriesSamples(
        [
          { t: 1000, rate: null },
          { t: 2000 },
          { t: 3000, rate: 0 },
          { t: 4000, active: 2 },
          { t: 5000, rate: Number.NaN },
        ],
        series,
      ),
    ).toBe(2);
  });
});
