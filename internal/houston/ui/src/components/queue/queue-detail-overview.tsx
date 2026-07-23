"use client";

import { ArrowRight, ExternalLink } from "lucide-react";

import { Panel, PanelBody, PanelTitleBar } from "@/components/ui/panel";
import { Field, Micro, Timestamp } from "@/components/ui/value";
import { ScopeBadge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { EVICTION_POLICY_LABELS } from "@/lib/constants";
import {
  formatClock,
  formatCount,
  formatDuration,
  formatRate,
  formatSecondsExact,
  truncateId,
} from "@/lib/format";
import type { Queue } from "@/lib/types";

import { LifecycleDiagram } from "./detail/lifecycle-diagram";
import { useQueueTelemetry } from "./detail/use-queue-telemetry";

interface QueueDetailOverviewProps {
  queue: Queue;
  /** Resolved dead-letter queue name; null when it could not be read. */
  deadLetterLabel: string | null;
  onOpenTab: (tab: string) => void;
}

const OPERATIONAL_NOTES = [
  {
    title: "At-least-once delivery",
    body: "A message may be delivered more than once. Consumers must tolerate duplicates.",
  },
  {
    title: "Best-effort ordering",
    body: "Order is not guaranteed, especially across retries.",
  },
  {
    title: "Opaque payloads",
    body: "The server never interprets message bytes.",
  },
  {
    title: "No deduplication",
    body: "Sending the same bytes twice stores two messages.",
  },
];

/**
 * S09. The three things an operator needs before touching anything: what this
 * queue is configured to do, whether there is traffic to look at, and what the
 * lifecycle means *with these settings substituted in*.
 */
export function QueueDetailOverview({
  queue,
  deadLetterLabel,
  onOpenTab,
}: QueueDetailOverviewProps) {
  const policy = EVICTION_POLICY_LABELS[queue.evictionPolicy] ?? queue.evictionPolicy;

  return (
    <div className="flex flex-col gap-4">
      <div className="grid gap-4 xl:grid-cols-[1.4fr_1fr]">
        <Panel>
          <PanelTitleBar
            title="Configuration"
            action={
              <span className="flex items-center gap-2 text-xs text-muted-foreground">
                Fixed at creation
                <Button variant="link" size="sm" onClick={() => onOpenTab("configuration")}>
                  Configuration tab
                  <ArrowRight aria-hidden />
                </Button>
              </span>
            }
          />
          <div className="grid gap-y-1 p-1.5 sm:grid-cols-2 lg:grid-cols-3">
            <Field
              label="Retention"
              hint={formatSecondsExact(queue.retentionPeriodSeconds)}
              className="px-3.5 py-2.5"
            >
              {formatDuration(queue.retentionPeriodSeconds)}
            </Field>
            <Field label="Visibility timeout" className="px-3.5 py-2.5">
              {formatDuration(queue.visibilityTimeoutSeconds)}
            </Field>
            <Field label="Max receive attempts" className="px-3.5 py-2.5">
              {formatCount(queue.maxReceiveAttempts)}
            </Field>
            <Field label="Eviction policy" mono={false} className="px-3.5 py-2.5">
              <span className="font-medium">{policy}</span>
            </Field>
            {/*
             * The queue record carries the dead-letter target's ID; the page
             * resolves its name. Both are shown — the name is what an operator
             * recognises, the ID is what they paste into a query.
             */}
            <Field
              label="Dead-letter queue"
              mono={false}
              hint={
                queue.deadLetterQueueId ? (
                  <span className="font-mono" title={queue.deadLetterQueueId}>
                    {truncateId(queue.deadLetterQueueId)}
                  </span>
                ) : undefined
              }
              className="px-3.5 py-2.5"
            >
              {queue.deadLetterQueueId ? (
                <a
                  href={`/queue/${queue.deadLetterQueueId}`}
                  className="inline-flex items-center gap-1.5 font-medium hover:underline"
                >
                  {deadLetterLabel ?? queue.deadLetterQueueId}
                  <ExternalLink className="size-3 text-muted-foreground" aria-hidden />
                </a>
              ) : (
                <span className="text-muted-foreground">None</span>
              )}
            </Field>
            <Field label="Created" mono={false} className="px-3.5 py-2.5">
              <Timestamp value={queue.createdAt} />
            </Field>
          </div>
        </Panel>

        <TrafficPanel queue={queue} onOpenTab={onOpenTab} />
      </div>

      <Panel>
        <PanelTitleBar
          title="Message lifecycle"
          action={
            <Micro>
              visibility {formatDuration(queue.visibilityTimeoutSeconds)} · attempts{" "}
              {formatCount(queue.maxReceiveAttempts)} · retention{" "}
              {formatDuration(queue.retentionPeriodSeconds)}
            </Micro>
          }
        />
        <PanelBody className="overflow-x-auto pt-5 pb-3">
          <LifecycleDiagram
            visibilitySeconds={queue.visibilityTimeoutSeconds}
            maxReceiveAttempts={queue.maxReceiveAttempts}
            retentionSeconds={queue.retentionPeriodSeconds}
            deadLetterLabel={
              queue.deadLetterQueueId ? (deadLetterLabel ?? queue.deadLetterQueueId) : null
            }
            evictionPolicyLabel={policy}
          />
        </PanelBody>
      </Panel>

      <Panel>
        <PanelTitleBar title="Operational notes" />
        <div className="grid sm:grid-cols-2 lg:grid-cols-4">
          {OPERATIONAL_NOTES.map((note) => (
            <div
              key={note.title}
              className="border-b border-border px-4 py-3 last:border-b-0 lg:border-r lg:border-b-0 lg:last:border-r-0"
            >
              <div className="text-xs leading-[17px] font-semibold">{note.title}</div>
              <p className="mt-0.5 text-[11px] leading-[15px] text-muted-foreground">
                {note.body}
              </p>
            </div>
          ))}
        </div>
      </Panel>
    </div>
  );
}

/**
 * The snapshot from `/metrics/queue/{id}` over the last hour — the same source
 * the Metrics tab reads, kept to four figures here.
 *
 * A server without telemetry storage answers 404/503, which is a configuration
 * fact rather than a fault, so the panel says so and points at System instead
 * of drawing zeros.
 */
function TrafficPanel({
  queue,
  onOpenTab,
}: {
  queue: Queue;
  onOpenTab: (tab: string) => void;
}) {
  const { summary, status, error, readAt } = useQueueTelemetry(queue.queueId, "1h", false);

  return (
    <Panel>
      <PanelTitleBar
        title="Traffic"
        action={
          status === "unavailable" ? (
            <ScopeBadge>Not recorded</ScopeBadge>
          ) : status === "failed" ? (
            <ScopeBadge tone="warning">{summary ? "Stale" : "Unread"}</ScopeBadge>
          ) : (
            <Micro>last 1 h{readAt ? ` · ${formatClock(readAt)}` : ""}</Micro>
          )
        }
      />
      <PanelBody className="flex flex-col items-start gap-3">
        {status === "unavailable" ? (
          <p className="text-xs leading-relaxed text-muted-foreground">
            Telemetry storage is not configured on this server, so no samples are
            collected for any queue — no rates and no in-flight count. Sending,
            receiving and acknowledging are unaffected.
          </p>
        ) : status === "failed" && !summary ? (
          <p className="text-xs leading-relaxed text-destructive-text">
            {error ?? "The traffic snapshot could not be read."}
          </p>
        ) : (
          // Rates carry their own denominator, so the labels do not repeat it.
          <div className="grid w-full grid-cols-2 gap-x-4 gap-y-3">
            <Field label="Send">
              {summary ? formatRate(summary.currentSendRate) : <span className="text-subtle">—</span>}
            </Field>
            <Field label="Receive">
              {summary ? (
                formatRate(summary.currentReceiveRate)
              ) : (
                <span className="text-subtle">—</span>
              )}
            </Field>
            <Field label="Acknowledge / delete">
              {summary ? (
                formatRate(summary.currentDeleteRate)
              ) : (
                <span className="text-subtle">—</span>
              )}
            </Field>
            <Field label="In flight">
              {summary ? (
                formatCount(summary.currentInFlight)
              ) : (
                <span className="text-subtle">—</span>
              )}
            </Field>
          </div>
        )}

        {status === "failed" && summary && readAt ? (
          <Micro>Last good read {formatClock(readAt)} — {error}</Micro>
        ) : null}

        <Button variant="outline" size="sm" onClick={() => onOpenTab("metrics")}>
          Metrics tab
          <ArrowRight aria-hidden />
        </Button>
      </PanelBody>
    </Panel>
  );
}
