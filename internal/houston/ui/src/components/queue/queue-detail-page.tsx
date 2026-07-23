"use client";

import { useCallback, useEffect, useState } from "react";
import { Inbox, RefreshCw, Send, Shovel, Trash2 } from "lucide-react";

import { AppShell } from "@/components/layout/app-shell";
import { Panel } from "@/components/ui/panel";
import { PageHeader } from "@/components/ui/page-header";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Button } from "@/components/ui/button";
import { Badge, ScopeBadge } from "@/components/ui/badge";
import { Banner } from "@/components/ui/feedback";
import { EmptyState } from "@/components/ui/empty-state";
import { Skeleton } from "@/components/ui/skeleton";
import { CopyableId, Timestamp } from "@/components/ui/value";
import { api } from "@/lib/api-client";
import { formatClock } from "@/lib/format";
import type { Queue } from "@/lib/types";

import { QueueDetailOverview } from "./queue-detail-overview";
import { QueueMessages } from "./detail/queue-messages";
import { QueueMetrics } from "./detail/queue-metrics";
import { QueueAccess } from "./detail/queue-access";
import { QueueConfiguration } from "./detail/queue-configuration";
import { DeleteQueueDialog, PurgeQueueDialog } from "./detail/queue-danger-dialogs";

const TABS = ["overview", "messages", "metrics", "access", "configuration"] as const;
type TabId = (typeof TABS)[number];

function tabFromLocation(): TabId {
  if (typeof window === "undefined") return "overview";
  const requested = new URLSearchParams(window.location.search).get("tab");
  return TABS.includes(requested as TabId) ? (requested as TabId) : "overview";
}

function queueIdFromLocation(): string {
  if (typeof window === "undefined") return "";
  return window.location.pathname.split("/").filter(Boolean).pop() ?? "";
}

interface QueueDetailPageProps {
  /**
   * A restricted operator never sees Access at all — the tab is removed rather
   * than shown disabled, because an irrelevant section is noise, not guidance.
   */
  canManageAccess?: boolean;
}

export function QueueDetailPage({ canManageAccess = true }: QueueDetailPageProps) {
  const [queue, setQueue] = useState<Queue | null>(null);
  const [deadLetterLabel, setDeadLetterLabel] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [updatedAt, setUpdatedAt] = useState<number | null>(null);

  const [tab, setTab] = useState<TabId>("overview");
  const [purgeOpen, setPurgeOpen] = useState(false);
  const [deleteOpen, setDeleteOpen] = useState(false);

  const load = useCallback(async () => {
    const queueId = queueIdFromLocation();
    setRefreshing(true);
    try {
      const record = await api.queues.get(queueId);
      setQueue(record);
      setError(null);
      setUpdatedAt(Date.now());

      if (record.deadLetterQueueId) {
        // The queue record carries the DLQ's ID but not its name; resolve it
        // rather than printing an opaque ULID where a name belongs.
        try {
          const dlq = await api.queues.get(record.deadLetterQueueId);
          setDeadLetterLabel(dlq.queueName);
        } catch {
          setDeadLetterLabel(null);
        }
      } else {
        setDeadLetterLabel(null);
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load queue");
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }, []);

  /**
   * A tab the operator may not see is not a tab they may open — including via a
   * bookmarked `?tab=access`, which would otherwise select a trigger that was
   * never rendered and leave the panel area blank.
   */
  const permitted = useCallback(
    (id: TabId): TabId => (id === "access" && !canManageAccess ? "overview" : id),
    [canManageAccess],
  );

  useEffect(() => {
    setTab(permitted(tabFromLocation()));
    void load();
  }, [load, permitted]);

  const openTab = useCallback(
    (next: string) => {
      const id = permitted(TABS.includes(next as TabId) ? (next as TabId) : "overview");
      setTab(id);
      const url = new URL(window.location.href);
      url.searchParams.set("tab", id);
      window.history.replaceState(null, "", url);
    },
    [permitted],
  );

  return (
    <AppShell
      currentPath="/queue"
      title={queue ? `Queues / ${queue.queueName}` : "Queues"}
      updatedAt={updatedAt ? new Date(updatedAt) : null}
      onRefresh={() => void load()}
      refreshing={refreshing}
      canManageAccess={canManageAccess}
    >
      {loading ? (
        <QueueDetailSkeleton />
      ) : !queue ? (
        // A failure with nothing already on screen has no stale data to protect.
        <Panel>
          <EmptyState
            icon={Inbox}
            title="Queue not available"
            description={error ?? "This queue could not be read."}
            action={
              <Button variant="outline" onClick={() => void load()} loading={refreshing}>
                <RefreshCw aria-hidden />
                Try again
              </Button>
            }
          />
        </Panel>
      ) : (
        <QueueDetailBody
          queue={queue}
          deadLetterLabel={deadLetterLabel}
          error={error}
          refreshing={refreshing}
          updatedAt={updatedAt}
          onReload={() => void load()}
          tab={tab}
          onOpenTab={openTab}
          canManageAccess={canManageAccess}
          onPurge={() => setPurgeOpen(true)}
          onDelete={() => setDeleteOpen(true)}
        />
      )}

      {queue ? (
        <>
          <PurgeQueueDialog queue={queue} open={purgeOpen} onOpenChange={setPurgeOpen} />
          <DeleteQueueDialog
            queue={queue}
            open={deleteOpen}
            onOpenChange={setDeleteOpen}
            deadLetterLabel={deadLetterLabel}
          />
        </>
      ) : null}
    </AppShell>
  );
}

interface QueueDetailBodyProps {
  queue: Queue;
  deadLetterLabel: string | null;
  error: string | null;
  refreshing: boolean;
  updatedAt: number | null;
  onReload: () => void;
  tab: TabId;
  onOpenTab: (next: string) => void;
  canManageAccess: boolean;
  onPurge: () => void;
  onDelete: () => void;
}

function QueueDetailBody({
  queue,
  deadLetterLabel,
  error,
  refreshing,
  updatedAt,
  onReload,
  tab,
  onOpenTab,
  canManageAccess,
  onPurge,
  onDelete,
}: QueueDetailBodyProps) {
  const visibleTabs = TABS.filter((id) => id !== "access" || canManageAccess);

  return (
    <div>
      {/* A failed refresh keeps the last good record on screen, labelled. */}
      {error ? (
        <Banner
          tone="error"
          className="mb-4"
          action={
            <Button variant="link" size="sm" onClick={onReload} loading={refreshing}>
              Retry
            </Button>
          }
        >
          <span className="inline-flex items-center gap-2">
            <ScopeBadge tone="warning">Stale</ScopeBadge>
            {error} — showing the record read at {updatedAt ? formatClock(updatedAt) : "—"}.
          </span>
        </Banner>
      ) : null}

      <PageHeader
        title={
          <span className="inline-flex flex-wrap items-center gap-2.5">
            {queue.queueName}
            <CopyableId value={queue.queueId} label="Queue ID" className="font-normal" />
            {queue.deadLetterQueueId ? (
              <Badge className="font-normal">
                Dead-letter →{" "}
                <a
                  href={`/queue/${queue.deadLetterQueueId}`}
                  className="font-semibold hover:underline"
                >
                  {deadLetterLabel ?? queue.deadLetterQueueId}
                </a>
              </Badge>
            ) : null}
          </span>
        }
        description={
          <span className="inline-flex items-baseline gap-1.5">
            Created
            <Timestamp value={queue.createdAt} variant="inline" />
          </span>
        }
        actions={
          <>
            {/* Freshness and refresh live in the top bar, not here. */}
            <Button onClick={() => onOpenTab("messages")}>
              <Send aria-hidden />
              Send message
            </Button>
            <Button variant="outline" onClick={onPurge}>
              <Shovel aria-hidden />
              Purge
            </Button>
            <Button variant="destructive-outline" onClick={onDelete}>
              <Trash2 aria-hidden />
              Delete
            </Button>
          </>
        }
      />

      <Tabs value={tab} onValueChange={onOpenTab}>
        <TabsList>
          {visibleTabs.map((id) => (
            <TabsTrigger key={id} value={id} className="capitalize">
              {id}
            </TabsTrigger>
          ))}
        </TabsList>

        <TabsContent value="overview">
          <QueueDetailOverview
            queue={queue}
            deadLetterLabel={deadLetterLabel}
            onOpenTab={onOpenTab}
          />
        </TabsContent>

        {/*
         * Kept mounted: the workbench holds receive leases whose countdowns are
         * live, and losing them on a tab switch would leave messages hidden with
         * nothing on screen to acknowledge.
         */}
        <TabsContent value="messages" forceMount hidden={tab !== "messages"}>
          <QueueMessages queue={queue} />
        </TabsContent>

        <TabsContent value="metrics">
          <QueueMetrics queue={queue} />
        </TabsContent>

        {canManageAccess ? (
          <TabsContent value="access">
            <QueueAccess queue={queue} />
          </TabsContent>
        ) : null}

        <TabsContent value="configuration">
          <QueueConfiguration
            queue={queue}
            deadLetterLabel={deadLetterLabel}
            onPurge={onPurge}
            onDelete={onDelete}
          />
        </TabsContent>
      </Tabs>
    </div>
  );
}

/** Occupies the same space the loaded page will, so nothing reflows. */
function QueueDetailSkeleton() {
  return (
    <div>
      <Skeleton className="mb-2 h-4 w-40" />
      <div className="mb-5 flex items-end justify-between gap-6">
        <div>
          <Skeleton className="h-[30px] w-64" />
          <Skeleton className="mt-2 h-4 w-80" />
        </div>
        <div className="flex gap-2">
          <Skeleton className="h-8 w-32" />
          <Skeleton className="h-8 w-24" />
          <Skeleton className="h-8 w-24" />
        </div>
      </div>

      <div className="mb-4 flex gap-4 border-b border-border pb-2">
        {[64, 76, 60, 56, 96].map((width) => (
          <Skeleton key={width} className="h-4" style={{ width }} />
        ))}
      </div>

      <div className="grid gap-4 xl:grid-cols-[1.4fr_1fr]">
        <Skeleton className="h-56" />
        <Skeleton className="h-56" />
      </div>
      <Skeleton className="mt-4 h-64" />
    </div>
  );
}
