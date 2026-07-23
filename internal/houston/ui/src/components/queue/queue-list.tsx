"use client";

import * as React from "react";
import { Inbox, Plus, RefreshCw, TriangleAlert } from "lucide-react";

import { Button } from "@/components/ui/button";
import { ScopeBadge } from "@/components/ui/badge";
import { EmptyState, LifecycleLegend } from "@/components/ui/empty-state";
import { InlineAlert } from "@/components/ui/feedback";
import { PageHeader } from "@/components/ui/page-header";
import { Panel, PanelHeader } from "@/components/ui/panel";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableIdentityCell,
  TableRow,
} from "@/components/ui/table";
import { Timestamp } from "@/components/ui/value";
import { api } from "@/lib/api-client";
import { formatClock, formatCount, formatDuration, truncateId } from "@/lib/format";
import type { Queue } from "@/lib/types";
import { cn } from "@/lib/utils";
import { QueueCreateDialog } from "./queue-create-dialog";
import { QueuePagination } from "./queue-pagination";
import { DEAD_LETTER, evictionLabel } from "./list/eviction";
import { QueueRowActions } from "./list/queue-row-actions";
import { QueueTableSkeleton } from "./list/queue-table-skeleton";

/** The design's canonical request size; the transport's `limit`, not a page size. */
const DEFAULT_ROWS_PER_REQUEST = 20;

interface QueueListProps {
  /**
   * Purge is a distinct server permission and the transport exposes no
   * capability list, so the shell supplies it. The server stays the authority.
   */
  canPurge?: boolean;
}

export function QueueList({ canPurge = true }: QueueListProps) {
  const [queues, setQueues] = React.useState<Queue[]>([]);
  const [rowsPerRequest, setRowsPerRequest] = React.useState(DEFAULT_ROWS_PER_REQUEST);
  const [pageIndex, setPageIndex] = React.useState(0);
  const [hasMore, setHasMore] = React.useState(false);
  const [pending, setPending] = React.useState(true);
  const [error, setError] = React.useState<string | null>(null);
  const [loadedAt, setLoadedAt] = React.useState<Date | null>(null);
  const [reloadToken, setReloadToken] = React.useState(0);
  const [createOpen, setCreateOpen] = React.useState(false);

  // Cursors are transport bookkeeping, not view state: they must not re-render.
  const cursors = React.useRef<string[]>([""]);
  const requestId = React.useRef(0);

  const load = React.useCallback(async (index: number, limit: number) => {
    const id = requestId.current + 1;
    requestId.current = id;
    setPending(true);

    try {
      const response = await api.queues.list({
        cursor: cursors.current[index] ?? "",
        limit,
      });
      if (id !== requestId.current) return;

      setQueues(response.queues ?? []);
      setHasMore(Boolean(response.hasMore));
      setLoadedAt(new Date());
      setError(null);

      if (response.hasMore && response.nextCursor) {
        const next = cursors.current.slice(0, index + 1);
        next[index + 1] = response.nextCursor;
        cursors.current = next;
      }
    } catch (err) {
      if (id !== requestId.current) return;
      // Rule: a failed refresh keeps the last good rows on screen.
      setError(err instanceof Error ? err.message : "Could not load queues");
    } finally {
      if (id === requestId.current) setPending(false);
    }
  }, []);

  React.useEffect(() => {
    void load(pageIndex, rowsPerRequest);
  }, [load, pageIndex, rowsPerRequest, reloadToken]);

  const refresh = () => setReloadToken((token) => token + 1);

  const resetToFirstPage = () => {
    cursors.current = [""];
    setPageIndex(0);
    setReloadToken((token) => token + 1);
  };

  const handleRowsPerRequestChange = (rows: number) => {
    cursors.current = [""];
    setPageIndex(0);
    setRowsPerRequest(rows);
  };

  const stale = error !== null && queues.length > 0;
  const initialLoading = pending && loadedAt === null && error === null;
  const unavailable = error !== null && queues.length === 0;
  const showTable = initialLoading || queues.length > 0;
  const showFooter = showTable || pageIndex > 0 || hasMore;

  /** Dead-letter targets are IDs; the name is only known if it is on this page. */
  const nameById = React.useMemo(
    () => new Map(queues.map((queue) => [queue.queueId, queue.queueName])),
    [queues],
  );

  return (
    <>
      <PageHeader
        title="Queues"
        description="Durable named queues. Configuration is fixed at creation."
        actions={
          <>
            <Button variant="outline" onClick={refresh} disabled={pending}>
              <RefreshCw className={cn("size-3.5", pending && "animate-spin")} aria-hidden />
              Refresh
            </Button>
            <Button onClick={() => setCreateOpen(true)}>
              <Plus aria-hidden />
              Create queue
            </Button>
          </>
        }
      />

      {error ? (
        <InlineAlert
          className="mb-4"
          action={
            <Button variant="destructive-outline" size="sm" onClick={refresh} loading={pending}>
              Retry
            </Button>
          }
        >
          {stale && loadedAt ? (
            <>
              Couldn&rsquo;t refresh queues. Showing data from{" "}
              <span className="font-mono tabular">{formatClock(loadedAt)}</span>.
            </>
          ) : (
            <>Couldn&rsquo;t load queues. {error}</>
          )}
        </InlineAlert>
      ) : null}

      <Panel>
        {stale ? (
          <PanelHeader action={<ScopeBadge>STALE</ScopeBadge>}>Queues</PanelHeader>
        ) : null}

        {showTable ? (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Name</TableHead>
                <TableHead>Eviction</TableHead>
                <TableHead numeric>Max attempts</TableHead>
                <TableHead numeric>Retention</TableHead>
                <TableHead numeric>Visibility timeout</TableHead>
                <TableHead>Created</TableHead>
                <TableHead className="w-12">
                  <span className="sr-only">Row actions</span>
                </TableHead>
              </TableRow>
            </TableHeader>

            <TableBody>
              {initialLoading ? (
                <QueueTableSkeleton />
              ) : (
                  queues.map((queue) => (
                    <TableRow key={queue.queueId} className={cn(stale && "opacity-55")}>
                      <TableIdentityCell
                        name={queue.queueName}
                        id={queue.queueId}
                        href={`/queue/${queue.queueId}`}
                      />
                      <TableCell>
                        <span className="block leading-[18px]">
                          {evictionLabel(queue.evictionPolicy)}
                        </span>
                        {queue.evictionPolicy === DEAD_LETTER && queue.deadLetterQueueId ? (
                          <span className="block text-[11px] leading-[15px] text-muted-foreground">
                            →{" "}
                            {nameById.get(queue.deadLetterQueueId) ?? (
                              <span className="font-mono tabular">
                                {truncateId(queue.deadLetterQueueId)}
                              </span>
                            )}
                          </span>
                        ) : null}
                      </TableCell>
                      <TableCell numeric>{formatCount(queue.maxReceiveAttempts)}</TableCell>
                      <TableCell numeric>
                        {formatDuration(queue.retentionPeriodSeconds)}
                      </TableCell>
                      <TableCell numeric>
                        {formatDuration(queue.visibilityTimeoutSeconds)}
                      </TableCell>
                      <TableCell>
                        <Timestamp value={queue.createdAt} />
                      </TableCell>
                      <TableCell className="py-2">
                        <QueueRowActions
                          queue={queue}
                          canPurge={canPurge}
                          onDeleted={resetToFirstPage}
                        />
                      </TableCell>
                    </TableRow>
                  ))
              )}
            </TableBody>
          </Table>
        ) : unavailable ? (
          <EmptyState
            icon={TriangleAlert}
            title="Queues unavailable"
            description="The last request failed, so there is nothing to show yet."
          />
        ) : pageIndex > 0 ? (
          <EmptyState
            title="No more queues"
            description="This request returned no rows. The queues before it are still there."
            action={
              <Button
                variant="outline"
                onClick={() => setPageIndex((index) => Math.max(0, index - 1))}
              >
                Back
              </Button>
            }
          />
        ) : (
          <EmptyState
            icon={Inbox}
            title="No queues yet"
            description="A queue stores opaque message bytes. A received message turns invisible for the visibility timeout and is acknowledged to complete — or becomes visible again and retries."
            action={
              <Button onClick={() => setCreateOpen(true)}>
                <Plus aria-hidden />
                Create queue
              </Button>
            }
          >
            <LifecycleLegend />
          </EmptyState>
        )}

        {showFooter ? (
          <QueuePagination
            rowsPerRequest={rowsPerRequest}
            hasPrevious={pageIndex > 0}
            hasMore={hasMore}
            disabled={pending}
            onPrevious={() => setPageIndex((index) => Math.max(0, index - 1))}
            onNext={() => {
              if (hasMore) setPageIndex((index) => index + 1);
            }}
            onRowsPerRequestChange={handleRowsPerRequestChange}
          />
        ) : null}
      </Panel>

      <QueueCreateDialog
        open={createOpen}
        onOpenChange={setCreateOpen}
        onCreated={resetToFirstPage}
      />
    </>
  );
}
