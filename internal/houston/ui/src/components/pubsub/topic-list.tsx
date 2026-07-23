import { Panel, PanelTitleBar } from "@/components/ui/panel";
import { ScopeBadge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import { Status } from "@/components/ui/status";
import { Micro } from "@/components/ui/value";
import { formatCount, formatRate } from "@/lib/format";
import { cn } from "@/lib/utils";
import type { Topic } from "@/lib/types";
import { topicMetricsFor, type TopicMetricsState } from "./telemetry";

interface TopicListProps {
  topics: Topic[];
  selectedTopicId: string | null;
  onSelect: (topicId: string) => void;
  /** Per-topic publish rates, when the collector is running. */
  metrics: TopicMetricsState;
  /** Last good data, kept on screen after a refresh failed. */
  stale?: boolean;
}

export function TopicList({
  topics,
  selectedTopicId,
  onSelect,
  metrics,
  stale,
}: TopicListProps) {
  return (
    <Panel>
      <PanelTitleBar
        className="py-2.5"
        title="Topics"
        action={
          <>
            {stale ? <ScopeBadge tone="neutral">Stale</ScopeBadge> : null}
            <Micro className="text-[10px]">
              {formatCount(topics.length)} {topics.length === 1 ? "topic" : "topics"}
            </Micro>
          </>
        }
      />

      {topics.map((topic) => {
        const selected = topic.topicId === selectedTopicId;
        const connected = (topic.subscriptions ?? []).length;
        const row = topicMetricsFor(metrics, topic.topicId);
        // A topic the collector is running for but has never seen a publish on
        // reads em-dash, not 0/s: it has recorded nothing, which is a different
        // fact from having recorded no traffic.
        const rate =
          metrics.status !== "ready" ? null : row === null ? "—" : formatRate(row.publishRate);

        return (
          <button
            key={topic.topicId}
            type="button"
            aria-current={selected ? "true" : undefined}
            onClick={() => onSelect(topic.topicId)}
            className={cn(
              "block w-full border-t border-border px-4 py-3 text-left transition-colors first:border-t-0",
              selected
                ? "bg-muted shadow-[inset_2px_0_0_var(--color-foreground)]"
                : "hover:bg-muted/60",
            )}
          >
            <span className="flex items-baseline justify-between gap-3">
              <span className="truncate text-[13px] leading-[17px] font-semibold">
                {topic.topicName}
              </span>
              {rate === null ? null : (
                <span
                  title={row === null ? "No publish samples recorded for this topic" : undefined}
                  className={cn(
                    "shrink-0 font-mono text-[11px] tabular",
                    row === null ? "text-subtle" : "text-muted-foreground",
                  )}
                >
                  {rate}
                </span>
              )}
            </span>
            <span className="mt-[3px] flex items-center justify-between gap-3">
              <span className="truncate font-mono text-[10px] text-muted-foreground">
                {topic.topicId}
              </span>
              {connected === 0 ? (
                <Status tone="warning" className="shrink-0 text-[11px]">
                  0 connected queues
                </Status>
              ) : (
                <span className="shrink-0 text-[11px] text-muted-foreground">
                  {formatCount(connected)} connected {connected === 1 ? "queue" : "queues"}
                </span>
              )}
            </span>
          </button>
        );
      })}

      <p className="border-t border-border px-4 py-2.5 text-[11px] leading-[15px] text-subtle">
        {metrics.status === "ready" ? "Publish rate is process-current. " : ""}
        Selecting a topic puts it in the URL (?topic=…) so the view can be shared.
      </p>
    </Panel>
  );
}

export function TopicListSkeleton() {
  return (
    <Panel>
      <PanelTitleBar className="py-2.5" title="Topics" />
      {Array.from({ length: 3 }, (_, index) => (
        <div key={index} className="border-t border-border px-4 py-3 first:border-t-0">
          <Skeleton className="h-[17px] w-36" />
          <Skeleton className="mt-[5px] h-[13px] w-56" />
        </div>
      ))}
    </Panel>
  );
}
