"use client";

import * as React from "react";

import type { SeriesLoadState } from "./telemetry-data";
import type { ChartRow } from "./series-chart";

export interface SeriesState {
  rows: ChartRow[];
  loading: boolean;
  /** Telemetry storage is off — distinct from "the window held no samples". */
  unavailable: boolean;
  error: string | null;
  /** Rows on screen are the last good read of *this* subject, and a refresh failed. */
  stale: boolean;
}

const EMPTY: ChartRow[] = [];

/**
 * One series, reloaded whenever its subject or the refresh token changes.
 *
 * The two are deliberately separate. A failed *refresh* keeps the rows already
 * on screen and labels them stale — blanking a chart because a re-read failed
 * loses the operator the only reading they had. Changing the *subject* clears
 * them first, because leaving one queue's samples under another queue's
 * heading is worse than showing nothing.
 *
 * `subject` is the key that identifies what is being plotted, and is null when
 * there is nothing to plot yet. `load` closes over that subject; its identity
 * is not part of the reload condition.
 */
export function useSeries(
  subject: string | null,
  refreshToken: number,
  load: () => Promise<SeriesLoadState>,
): SeriesState {
  const [rows, setRows] = React.useState<ChartRow[]>(EMPTY);
  const [loading, setLoading] = React.useState(subject !== null);
  const [unavailable, setUnavailable] = React.useState(false);
  const [error, setError] = React.useState<string | null>(null);

  // Adjusting state during render rather than in an effect: React re-renders
  // with the cleared values before committing, so the previous subject's rows
  // are never painted under the new subject's heading.
  const [plotted, setPlotted] = React.useState(subject);
  if (plotted !== subject) {
    setPlotted(subject);
    setRows(EMPTY);
    setUnavailable(false);
    setError(null);
    setLoading(subject !== null);
  }

  // `load` is a fresh closure on every render; the effect keys off the subject
  // and the refresh token, and reads the latest closure when it fires.
  const loadRef = React.useRef(load);
  loadRef.current = load;

  React.useEffect(() => {
    if (subject === null) return;

    let cancelled = false;
    setLoading(true);

    void loadRef.current().then((result) => {
      if (cancelled) return;

      switch (result.status) {
        case "loaded":
          setRows(result.rows);
          setUnavailable(false);
          setError(null);
          break;
        case "unavailable":
          setRows(EMPTY);
          setUnavailable(true);
          setError(null);
          break;
        case "error":
          setUnavailable(false);
          setError(result.message);
          break;
      }

      setLoading(false);
    });

    return () => {
      cancelled = true;
    };
  }, [subject, refreshToken]);

  return {
    rows,
    loading,
    unavailable,
    error,
    stale: error !== null && rows.length > 0,
  };
}
