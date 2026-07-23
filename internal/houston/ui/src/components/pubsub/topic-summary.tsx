import { Info } from "lucide-react";

import { Panel } from "@/components/ui/panel";
import { Skeleton } from "@/components/ui/skeleton";
import { MonoValue } from "@/components/ui/value";
import { formatCount, formatRate } from "@/lib/format";
import { cn } from "@/lib/utils";
import type { TopicMetricsState } from "./telemetry";

/**
 * Informational, page-level, and deliberately neutral. Telemetry being off is
 * not a failure of topic management, so it must not borrow the amber or red
 * chrome that a real transport problem gets. A metrics request that *failed*
 * is a different fact and says so, with the way back.
 */
function TelemetryNotice({
  state,
  onRetry,
}: {
  state: TopicMetricsState;
  onRetry: () => void;
}) {
  if (state.status === "loading" || state.status === "ready") return null;

  return (
    <div className="mb-3 flex gap-2 border border-border bg-muted px-3 py-2.5">
      <Info className="mt-px size-3.5 shrink-0 text-strong" aria-hidden />
      <p className="text-xs leading-relaxed text-strong">
        {state.status === "unavailable" ? (
          <>
            Telemetry is disabled on this server, so publish and delivery readings stay
            unknown. Topic management works normally. Enable it with{" "}
            <span className="font-mono text-[11px]">--telemetry</span> and restart.
          </>
        ) : (
          <>
            Topic metrics could not be loaded: {state.message}. Topic management works
            normally.{" "}
            <button
              type="button"
              onClick={onRetry}
              className="cursor-pointer underline underline-offset-2"
            >
              Retry
            </button>
          </>
        )}
      </p>
    </div>
  );
}

function SummaryTile({
  label,
  qualifier,
  swatch,
  children,
  unknown,
}: {
  label: string;
  qualifier?: string;
  swatch?: string;
  children: React.ReactNode;
  unknown?: boolean;
}) {
  return (
    <Panel className="px-3.5 py-3">
      <div className="flex items-center gap-1.5 text-[11px] text-muted-foreground">
        {swatch ? <span className={cn("size-[7px] shrink-0", swatch)} aria-hidden /> : null}
        {label}
        {qualifier ? <span className="text-subtle">{qualifier}</span> : null}
      </div>
      <MonoValue
        className={cn(
          "mt-0.5 block text-[18px] leading-[26px] font-medium",
          unknown && "text-subtle",
        )}
      >
        {children}
      </MonoValue>
    </Panel>
  );
}

interface TopicSummaryProps {
  metrics: TopicMetricsState;
  /**
   * Subscriptions counted from the topic list. Null while it has never loaded
   * — unknown, which is not zero. Used only when the collector has no count of
   * its own, which it does not until it has seen a subscription change.
   */
  listedSubscriptions: number | null;
  loading?: boolean;
  onRetryMetrics: () => void;
}

/**
 * Process-current and unscoped, the same readings `/metrics/topics/overview`
 * serves. Rates and counters come from the collector; when it is off or
 * unreachable every one of them reads "Unknown" rather than zero, because an
 * unmeasured topic is not an idle one.
 */
export function TopicSummary({
  metrics,
  listedSubscriptions,
  loading,
  onRetryMetrics,
}: TopicSummaryProps) {
  if (loading) {
    return (
      <div className="mb-4 grid grid-cols-5 gap-3">
        {Array.from({ length: 5 }, (_, index) => (
          <Panel key={index} className="px-3.5 py-3">
            <Skeleton className="h-[11px] w-20" />
            <Skeleton className="mt-2 h-[18px] w-14" />
          </Panel>
        ))}
      </div>
    );
  }

  const system = metrics.status === "ready" ? metrics.overview.systemMetrics : null;
  // The collector reports a live subscription count only once it has observed
  // the subscriptions; until then the topic list is the one that knows, and it
  // is just as real a reading.
  const subscriptions = system?.subscriptionsCurrent ?? listedSubscriptions;
  const subscriptionsFromList =
    system !== null && system.subscriptionsCurrent === null && listedSubscriptions !== null;

  return (
    <div className="mb-4">
      <TelemetryNotice state={metrics} onRetry={onRetryMetrics} />

      <div className="grid grid-cols-5 gap-3">
        <SummaryTile label="Publish rate" swatch="bg-send" unknown={system === null}>
          {system === null ? "Unknown" : formatRate(system.publishRate)}
        </SummaryTile>
        <SummaryTile label="Delivery rate" swatch="bg-receive" unknown={system === null}>
          {system === null ? "Unknown" : formatRate(system.deliveryRate)}
        </SummaryTile>
        <SummaryTile label="Published" qualifier="since start" unknown={system === null}>
          {system === null ? "Unknown" : formatCount(system.messagesPublished)}
        </SummaryTile>
        <SummaryTile label="Deliveries" qualifier="since start" unknown={system === null}>
          {system === null ? "Unknown" : formatCount(system.deliveries)}
        </SummaryTile>
        <SummaryTile
          label="Active subscriptions"
          qualifier={subscriptionsFromList ? "from topic list" : undefined}
          unknown={subscriptions === null}
        >
          {subscriptions === null ? "Unknown" : formatCount(subscriptions)}
        </SummaryTile>
      </div>
    </div>
  );
}
