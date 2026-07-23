"use client";

import { formatDateFull } from "@/lib/format";
import type { ChartRow } from "./series-chart";
import type { SeriesSpec } from "./lifecycle";

/**
 * Exports are built from the samples already on screen — the client has the
 * whole series, so there is nothing to ask the server for and nothing that can
 * silently differ from what the operator is looking at.
 */

export interface ExportSubject {
  /** Becomes the file name stem, e.g. `plainq-throughput-queues`. */
  name: string;
  data: ReadonlyArray<ChartRow>;
  series: readonly SeriesSpec[];
  /** Absolute bounds of the exported window, recorded in the JSON envelope. */
  fromMs: number;
  toMs: number;
}

/**
 * CSV fields are comma-separated and the readable stamp carries a comma of its
 * own (`Jul 23, 2026 …`), which would shift every column by one. ISO-8601 says
 * the same instant without a separator in it, and sorts lexically besides.
 */
function isoStamp(ms: number): string {
  return new Date(ms).toISOString();
}

export function toCsv({ data, series }: ExportSubject): string {
  const header = ["sample_utc", ...series.map((entry) => entry.key)].join(",");
  const rows = data.map((row) =>
    [isoStamp(row.t), ...series.map((entry) => String(row[entry.key] ?? ""))].join(","),
  );
  return [header, ...rows].join("\n");
}

export function toJson(subject: ExportSubject): string {
  return JSON.stringify(
    {
      metric: subject.name,
      window: { from: formatDateFull(subject.fromMs), to: formatDateFull(subject.toMs) },
      series: subject.series.map((entry) => entry.key),
      samples: subject.data.map((row) => ({
        at: formatDateFull(row.t),
        ...Object.fromEntries(subject.series.map((entry) => [entry.key, row[entry.key]])),
      })),
    },
    null,
    2,
  );
}

function download(filename: string, mime: string, contents: string): void {
  const url = URL.createObjectURL(new Blob([contents], { type: mime }));
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = filename;
  // The anchor has to be in the document for the click to count, and the URL
  // has to outlive this task: revoking it in the same tick can beat the
  // browser to reading the blob, and the download silently never happens.
  document.body.append(anchor);
  anchor.click();
  anchor.remove();
  window.setTimeout(() => URL.revokeObjectURL(url), 0);
}

/**
 * File-name stamp. Derived from the timestamp rather than by stripping punctuation
 * out of the readable form, which dropped the month entirely and left the day
 * standing before the year.
 */
function stamp(): string {
  return new Date().toISOString().slice(0, 19).replace(/:/g, "-");
}

export function downloadCsv(subject: ExportSubject): string {
  const filename = `plainq-${subject.name}-${stamp()}.csv`;
  download(filename, "text/csv;charset=utf-8", toCsv(subject));
  return filename;
}

export function downloadJson(subject: ExportSubject): string {
  const filename = `plainq-${subject.name}-${stamp()}.json`;
  download(filename, "application/json;charset=utf-8", toJson(subject));
  return filename;
}
