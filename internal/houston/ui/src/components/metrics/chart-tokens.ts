"use client";

import * as React from "react";

/**
 * Recharts paints SVG with colour values, not class names, so the palette is
 * read back out of the design tokens at runtime instead of being duplicated as
 * hex here. Reading them also gates chart rendering on mount, which is what the
 * responsive container needs anyway.
 */
export interface ChartTokens {
  send: string;
  receive: string;
  acknowledge: string;
  retry: string;
  /** Grid hairlines and the baseline axis. */
  grid: string;
  axis: string;
  /** Axis tick labels. */
  label: string;
}

const VARIABLES: Record<keyof ChartTokens, string> = {
  send: "--color-send",
  receive: "--color-receive",
  acknowledge: "--color-acknowledge",
  retry: "--color-retry",
  grid: "--color-border",
  axis: "--color-subtle",
  label: "--color-muted-foreground",
};

function readChartTokens(): ChartTokens | null {
  // Server-rendered and test renders have no document to read tokens off; the
  // caller keeps showing the chart's skeleton until a real one exists.
  if (typeof document === "undefined") return null;

  const styles = getComputedStyle(document.documentElement);
  const entries = Object.entries(VARIABLES).map(([key, variable]) => [
    key,
    styles.getPropertyValue(variable).trim(),
  ]);
  return Object.fromEntries(entries) as ChartTokens;
}

/** `null` until mounted — render the chart's skeleton in the meantime. */
export function useChartTokens(): ChartTokens | null {
  const [tokens, setTokens] = React.useState<ChartTokens | null>(null);

  React.useEffect(() => {
    setTokens(readChartTokens());
  }, []);

  return tokens;
}
