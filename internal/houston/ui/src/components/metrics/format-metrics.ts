import { formatClock, groupDigits } from "@/lib/format";

/**
 * Two shapes this screen needs that the shared formatters do not cover, both
 * built on top of them rather than beside them.
 */

/**
 * The numeric half of a rate. Columns here name the denominator in the header
 * ("Send /s", "Redeliveries /m"), so repeating it in every cell would state the
 * unit twice. Precision is pinned at one decimal rather than borrowed from
 * `formatRate`, whose sliding 2-then-1-then-0 scale leaves a mono `tabular`
 * column with ragged decimal points and renders a genuine zero as a bare "0"
 * beside neighbours carrying two decimals.
 */
export function formatRateFigure(perSecond: number): string {
  if (!Number.isFinite(perSecond)) return "—";
  // A rate that rounds down to 0.0 without being zero would read as idle in a
  // column where the zeros are meant to be genuine, so it says so instead.
  if (perSecond > 0 && perSecond < 0.05) return "<0.1";

  const [whole = "0", fraction = "0"] = perSecond.toFixed(1).split(".");
  return `${groupDigits(Number(whole))}.${fraction}`;
}

/**
 * Axis ticks have no room for the full stamp; the tooltip and the table view
 * both carry `HH:MM:SS UTC`, so nothing is lost by trimming here.
 */
export function formatAxisTime(value: number): string {
  return formatClock(value).slice(0, 5);
}
