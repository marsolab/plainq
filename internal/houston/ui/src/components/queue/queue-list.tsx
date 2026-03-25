import { useEffect, useState, useCallback } from "react";
import {
  Table,
  TableHeader,
  TableBody,
  TableRow,
  TableHead,
  TableCell,
} from "@/components/ui/table";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { QueueCreateDialog } from "./queue-create-dialog";
import { QueuePagination } from "./queue-pagination";
import { api } from "@/lib/api-client";
import { EVICTION_POLICY_LABELS, DEFAULT_PAGE_SIZE } from "@/lib/constants";
import type { Queue } from "@/lib/types";
import { formatDistanceToNow } from "date-fns";
import { Toaster } from "sonner";

export function QueueList() {
  const [queues, setQueues] = useState<Queue[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [pageSize, setPageSize] = useState(DEFAULT_PAGE_SIZE);
  const [cursors, setCursors] = useState<string[]>([""]);
  const [currentPage, setCurrentPage] = useState(0);
  const [hasMore, setHasMore] = useState(false);

  const fetchQueues = useCallback(async (cursor: string, limit: number) => {
    setLoading(true);
    setError(null);
    try {
      const data = await api.queues.list({ cursor, limit });
      setQueues(data.queues ?? []);
      setHasMore(data.hasMore);
      if (data.hasMore && data.nextCursor) {
        setCursors((prev) => {
          const next = [...prev];
          next[currentPage + 1] = data.nextCursor;
          return next;
        });
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load queues");
    } finally {
      setLoading(false);
    }
  }, [currentPage]);

  useEffect(() => {
    fetchQueues(cursors[currentPage] ?? "", pageSize);
  }, [currentPage, pageSize]);

  const handleNext = () => {
    if (hasMore) setCurrentPage((p) => p + 1);
  };

  const handlePrevious = () => {
    if (currentPage > 0) setCurrentPage((p) => p - 1);
  };

  const handlePageSizeChange = (size: number) => {
    setPageSize(size);
    setCursors([""]);
    setCurrentPage(0);
  };

  const handleCreated = () => {
    setCursors([""]);
    setCurrentPage(0);
    fetchQueues("", pageSize);
  };

  return (
    <div>
      <Toaster position="top-right" />
      <div className="mb-6 flex items-center justify-between">
        <div>
          <h2 className="text-lg font-semibold">All Queues</h2>
          <p className="text-sm text-muted-foreground">
            Manage your message queues
          </p>
        </div>
        <QueueCreateDialog onCreated={handleCreated} />
      </div>

      {error && (
        <div className="mb-4 rounded-md bg-destructive/10 px-4 py-3 text-sm text-destructive">
          {error}
        </div>
      )}

      <div className="rounded-lg border">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Name</TableHead>
              <TableHead>Eviction Policy</TableHead>
              <TableHead>Max Attempts</TableHead>
              <TableHead>Retention</TableHead>
              <TableHead>Visibility</TableHead>
              <TableHead>Created</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {loading ? (
              Array.from({ length: 3 }).map((_, i) => (
                <TableRow key={i}>
                  {Array.from({ length: 6 }).map((_, j) => (
                    <TableCell key={j}>
                      <Skeleton className="h-4 w-24" />
                    </TableCell>
                  ))}
                </TableRow>
              ))
            ) : queues.length === 0 ? (
              <TableRow>
                <TableCell colSpan={6} className="h-24 text-center text-muted-foreground">
                  No queues found. Create one to get started.
                </TableCell>
              </TableRow>
            ) : (
              queues.map((queue) => (
                <TableRow key={queue.queueId}>
                  <TableCell>
                    <a
                      href={`/queue/${queue.queueId}`}
                      className="font-medium text-primary hover:underline"
                    >
                      {queue.queueName}
                    </a>
                  </TableCell>
                  <TableCell>
                    <Badge variant="secondary">
                      {EVICTION_POLICY_LABELS[queue.evictionPolicy] ??
                        queue.evictionPolicy}
                    </Badge>
                  </TableCell>
                  <TableCell>{queue.maxReceiveAttempts}</TableCell>
                  <TableCell>{formatSeconds(queue.retentionPeriodSeconds)}</TableCell>
                  <TableCell>{queue.visibilityTimeoutSeconds}s</TableCell>
                  <TableCell className="text-muted-foreground">
                    {formatDistanceToNow(new Date(queue.createdAt), {
                      addSuffix: true,
                    })}
                  </TableCell>
                </TableRow>
              ))
            )}
          </TableBody>
        </Table>
      </div>

      <QueuePagination
        hasMore={hasMore}
        hasPrevious={currentPage > 0}
        pageSize={pageSize}
        onNext={handleNext}
        onPrevious={handlePrevious}
        onPageSizeChange={handlePageSizeChange}
      />
    </div>
  );
}

function formatSeconds(seconds: number): string {
  if (seconds >= 86400) return `${Math.floor(seconds / 86400)}d`;
  if (seconds >= 3600) return `${Math.floor(seconds / 3600)}h`;
  if (seconds >= 60) return `${Math.floor(seconds / 60)}m`;
  return `${seconds}s`;
}
