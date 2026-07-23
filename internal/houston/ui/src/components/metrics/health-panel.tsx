"use client";

import * as React from "react";

import { ScopeBadge } from "@/components/ui/badge";
import { EmptyState } from "@/components/ui/empty-state";
import { Panel, PanelTitleBar } from "@/components/ui/panel";
import { Skeleton } from "@/components/ui/skeleton";
import { Status } from "@/components/ui/status";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableIdentityCell,
  TableRow,
} from "@/components/ui/table";
import { formatClock, formatCount, truncateId } from "@/lib/format";
import { cn } from "@/lib/utils";
import { formatRateFigure } from "./format-metrics";
import { Segmented } from "./segmented";
import type {
  QueueActivity,
  QueueHealthRow,
  TelemetrySnapshot,
  TopicHealthRow,
} from "./telemetry-data";

export type HealthScope = "queues" | "topics";

const QUEUE_ACTIVITY: Record<
  QueueActivity,
  { tone: React.ComponentProps<typeof Status>["tone"]; label: string }
> = {
  active: { tone: "healthy", label: "Active" },
  // Rates are all zero but messages are held under a visibility timeout.
  "in-flight": { tone: "in-flight", label: "In flight" },
  idle: { tone: "neutral", label: "Idle" },
};

export function HealthPanel({
  snapshot,
  scope,
  onScopeChange,
  loading,
  stale,
}: {
  snapshot: TelemetrySnapshot | null;
  scope: HealthScope;
  onScopeChange: (scope: HealthScope) => void;
  loading: boolean;
  stale: boolean;
}) {
  const queues = snapshot?.queues ?? [];
  const topics = snapshot?.topics ?? [];

  return (
    <Panel>
      <PanelTitleBar
        className="items-center py-2.5"
        title={
          <div className="flex items-center gap-2.5">
            Health
            <Segmented
              variant="text"
              label="Health scope"
              value={scope}
              onChange={onScopeChange}
              options={[
                { value: "queues", label: "Queues" },
                { value: "topics", label: "Pub/Sub" },
              ]}
            />
            {stale ? <ScopeBadge>Stale</ScopeBadge> : null}
          </div>
        }
        action={
          <span className="font-mono text-[10px] text-muted-foreground">
            counters since process start · process-current, unscoped by range
          </span>
        }
      />

      {loading ? (
        <TableSkeleton columns={scope === "queues" ? 9 : 7} />
      ) : scope === "queues" ? (
        <QueueHealthTable rows={queues} />
      ) : (
        <TopicHealthTable rows={topics} reporting={snapshot?.topicsReporting ?? false} />
      )}
    </Panel>
  );
}

/**
 * The overview names no queues, so a row falls back to its ID rather than
 * inventing a label. Truncated only because the column is narrow; the queue
 * page behind the link carries the full value.
 */
function subjectName(name: string | null, id: string): string {
  return name ?? truncateId(id);
}

function QueueHealthTable({ rows }: { rows: QueueHealthRow[] }) {
  if (rows.length === 0) {
    return (
      <EmptyState
        title="No queues reporting"
        description="No queue has produced a sample yet. Queue management is unaffected — this panel only reads counters."
      />
    );
  }

  return (
    <>
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead>Queue</TableHead>
            <TableHead numeric>In-flight</TableHead>
            <TableHead numeric>Send /s</TableHead>
            <TableHead numeric>Receive /s</TableHead>
            <TableHead numeric>Delete /s</TableHead>
            <TableHead numeric>Sent</TableHead>
            <TableHead numeric>Received</TableHead>
            <TableHead numeric>Deleted</TableHead>
            <TableHead>Activity</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {rows.map((row) => {
            const activity = QUEUE_ACTIVITY[row.activity];

            return (
              <TableRow key={row.queueId}>
                <TableIdentityCell
                  name={subjectName(row.queueName, row.queueId)}
                  href={`/queue/${row.queueId}`}
                />
                <TableCell numeric>{formatCount(row.inFlight)}</TableCell>
                <TableCell numeric>{formatRateFigure(row.sendRate)}</TableCell>
                <TableCell numeric>{formatRateFigure(row.receiveRate)}</TableCell>
                <TableCell numeric>{formatRateFigure(row.deleteRate)}</TableCell>
                <TableCell numeric>{formatCount(row.messagesSent)}</TableCell>
                <TableCell numeric>{formatCount(row.messagesReceived)}</TableCell>
                <TableCell numeric>{formatCount(row.messagesDeleted)}</TableCell>
                <TableCell>
                  <Status tone={activity.tone}>{activity.label}</Status>
                </TableCell>
              </TableRow>
            );
          })}
        </TableBody>
      </Table>
      <TableNote>
        Counters run since process start and reset on restart — never lifetime totals. Activity is
        read off the rates in this row, not reported by the server.
      </TableNote>
    </>
  );
}

function TopicHealthTable({ rows, reporting }: { rows: TopicHealthRow[]; reporting: boolean }) {
  if (!reporting) {
    return (
      <EmptyState
        title="Topic telemetry did not answer"
        description="The topic overview could not be read, so nothing is shown here rather than an empty table that would read as “no topics”. Pub/Sub management is unaffected."
      />
    );
  }

  if (rows.length === 0) {
    return (
      <EmptyState
        title="No topics reporting"
        description="Topic telemetry is instrumented, but no topic has published since this process started."
      />
    );
  }

  return (
    <>
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead>Topic</TableHead>
            <TableHead numeric>Publish /s</TableHead>
            <TableHead numeric>Delivery /s</TableHead>
            <TableHead numeric>Published</TableHead>
            <TableHead numeric>Deliveries</TableHead>
            <TableHead numeric>Subscriptions</TableHead>
            <TableHead>Last updated</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {rows.map((row) => {
            // Publishing into a topic with no subscribers delivers nothing —
            // worth flagging, but it is a fact about the topic, not an error.
            const orphaned = row.subscriptions === 0;

            return (
              <TableRow key={row.topicId}>
                <TableIdentityCell name={subjectName(row.topicName, row.topicId)} href="/pubsub" />
                <TableCell numeric>{formatRateFigure(row.publishRate)}</TableCell>
                <TableCell numeric>{formatRateFigure(row.deliveryRate)}</TableCell>
                <TableCell numeric>{formatCount(row.published)}</TableCell>
                <TableCell numeric>{formatCount(row.deliveries)}</TableCell>
                <TableCell numeric>
                  {row.subscriptions === null ? (
                    <span className="text-subtle">Unknown</span>
                  ) : orphaned ? (
                    <Status tone="warning" className="justify-end font-mono tabular">
                      0
                    </Status>
                  ) : (
                    formatCount(row.subscriptions)
                  )}
                </TableCell>
                <TableCell className="font-mono text-xs tabular">
                  {formatClock(row.updatedAt)}
                </TableCell>
              </TableRow>
            );
          })}
        </TableBody>
      </Table>
      <TableNote>
        Counters run since process start and reset on restart — never lifetime totals. A
        subscription count the transport does not report reads “Unknown”, never 0.
      </TableNote>
    </>
  );
}

function TableNote({ children }: { children: React.ReactNode }) {
  return (
    <div className="border-t border-border px-4 py-2 text-[11px] text-subtle">{children}</div>
  );
}

function TableSkeleton({ columns }: { columns: number }) {
  return (
    <div className="flex flex-col">
      {Array.from({ length: 4 }).map((_, row) => (
        <div key={row} className="flex items-center gap-4 border-b border-border px-4 py-3">
          {Array.from({ length: columns }).map((_, column) => (
            <Skeleton
              key={column}
              className={cn("h-[15px] flex-1", column === 0 ? "max-w-40" : "max-w-20")}
            />
          ))}
        </div>
      ))}
    </div>
  );
}
