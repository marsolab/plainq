"use client";

import { ChevronLeft, ChevronRight, Eye, RefreshCw, Trash2 } from "lucide-react";

import { Panel, PanelFooter, PanelTitleBar } from "@/components/ui/panel";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Button } from "@/components/ui/button";
import { EmptyState } from "@/components/ui/empty-state";
import { Skeleton } from "@/components/ui/skeleton";
import { Status } from "@/components/ui/status";
import { Micro } from "@/components/ui/value";
import {
  formatBytes,
  formatClock,
  formatCount,
  formatDateFull,
} from "@/lib/format";
import { cn } from "@/lib/utils";
import type { Queue } from "@/lib/types";

import type { QueueMessage } from "./message";
import { previewOf } from "./payload";

interface MessageBrowserProps {
  queue: Queue;
  messages: QueueMessage[];
  /** Queue depth as the server counted it, independent of this window. */
  total: number;
  offset: number;
  pageSize: number;
  loading: boolean;
  refreshing: boolean;
  browsedAt: number | null;
  onPage: (offset: number) => void;
  onRefresh: () => void;
  onInspect: (message: QueueMessage) => void;
  onDelete: (message: QueueMessage) => void;
}

/**
 * Browse is `GET …/messages`: a peek leaves visibility deadlines and receive
 * counts untouched, so opening this table never hides or consumes traffic.
 * The row action is Delete — a removal, not the acknowledgement the workbench
 * above performs on a message it holds.
 *
 * Paging is by offset against a server-supplied total, which is why a page
 * position appears here and nowhere that pages by cursor.
 */
export function MessageBrowser({
  queue,
  messages,
  total,
  offset,
  pageSize,
  loading,
  refreshing,
  browsedAt,
  onPage,
  onRefresh,
  onInspect,
  onDelete,
}: MessageBrowserProps) {
  const pages = Math.max(1, Math.ceil(total / pageSize));
  const page = Math.min(Math.floor(offset / pageSize), pages - 1);

  return (
    <Panel>
      <PanelTitleBar
        title={
          <span className="inline-flex items-baseline gap-2.5">
            Browse
            <span className="text-[11px] font-normal text-muted-foreground">
              without receiving · oldest first
            </span>
          </span>
        }
        action={
          <div className="flex items-center gap-2">
            <Micro>{formatCount(total)} in this queue</Micro>
            <Button variant="outline" size="sm" onClick={onRefresh} loading={refreshing}>
              <RefreshCw aria-hidden />
              Refresh
            </Button>
          </div>
        }
      />

      {loading ? (
        <BrowseSkeleton rows={6} />
      ) : messages.length === 0 ? (
        <EmptyState
          title="No messages in this queue"
          description="Send one from the composer above, or wait for a producer. Browsing never consumes, so an empty list here is simply an empty queue."
        />
      ) : (
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Message ID</TableHead>
              <TableHead>Body preview</TableHead>
              <TableHead>Created</TableHead>
              <TableHead>Visible at</TableHead>
              <TableHead numeric>Attempts</TableHead>
              <TableHead>Status</TableHead>
              <TableHead className="w-[88px]" />
            </TableRow>
          </TableHeader>
          <TableBody>
            {messages.map((message) => {
              const attempts = message.receiveAttempts;
              const atRisk =
                attempts !== null &&
                queue.maxReceiveAttempts > 0 &&
                attempts >= queue.maxReceiveAttempts - 1;
              const preview = previewOf(message.body);

              return (
                <TableRow
                  key={message.messageId}
                  className={cn(atRisk && "bg-warning-surface")}
                >
                  <TableCell className="font-mono text-[11px]">
                    {message.messageId}
                  </TableCell>
                  <TableCell className="max-w-[280px] truncate font-mono text-[11px]">
                    {preview}
                    <span className="text-subtle">
                      {" "}
                      {message.lossy ? "· not UTF-8 · " : "· "}
                      {formatBytes(message.bytes.byteLength)}
                    </span>
                  </TableCell>
                  <TableCell
                    className="font-mono text-[11px] tabular"
                    title={
                      message.createdAt
                        ? formatDateFull(message.createdAt)
                        : "Not carried by this response"
                    }
                  >
                    {message.createdAt ? formatClock(message.createdAt) : "—"}
                  </TableCell>
                  <TableCell
                    className="font-mono text-[11px] tabular"
                    title={
                      message.inFlight && message.visibleAt
                        ? formatDateFull(message.visibleAt)
                        : "Available to receive now"
                    }
                  >
                    {message.inFlight && message.visibleAt
                      ? formatClock(message.visibleAt)
                      : "now"}
                  </TableCell>
                  <TableCell
                    numeric
                    className={cn(atRisk && "font-semibold text-warning-text")}
                  >
                    {attempts === null ? "—" : `${attempts} / ${queue.maxReceiveAttempts}`}
                  </TableCell>
                  <TableCell>
                    {atRisk ? (
                      <Status tone="warning">Next failure dead-letters</Status>
                    ) : message.inFlight ? (
                      <Status tone="in-flight">In-flight</Status>
                    ) : (
                      <Status tone="visible">Visible</Status>
                    )}
                  </TableCell>
                  <TableCell>
                    <div className="flex justify-end gap-1.5">
                      <Button
                        variant="outline"
                        size="icon-sm"
                        title="Inspect payload"
                        aria-label={`Inspect payload of ${message.messageId}`}
                        onClick={() => onInspect(message)}
                      >
                        <Eye aria-hidden />
                      </Button>
                      <Button
                        variant="destructive-outline"
                        size="icon-sm"
                        title="Delete message"
                        aria-label={`Delete message ${message.messageId}`}
                        onClick={() => onDelete(message)}
                      >
                        <Trash2 aria-hidden />
                      </Button>
                    </div>
                  </TableCell>
                </TableRow>
              );
            })}
          </TableBody>
        </Table>
      )}

      <PanelFooter>
        <span className="text-[11px] text-subtle">
          Page size {pageSize} · read at{" "}
          {browsedAt ? formatClock(browsedAt) : "—"}. Status is a marker plus a word,
          never colour alone.
        </span>
        <div className="flex shrink-0 items-center gap-2">
          {/* Offset paging against a counted total, so a position is a fact. */}
          <Micro>
            Page {formatCount(page + 1)} of {formatCount(pages)}
          </Micro>
          <Button
            variant="outline"
            size="sm"
            disabled={offset <= 0}
            onClick={() => onPage(Math.max(0, offset - pageSize))}
          >
            <ChevronLeft aria-hidden />
            Previous
          </Button>
          <Button
            variant="outline"
            size="sm"
            disabled={offset + pageSize >= total}
            onClick={() => onPage(offset + pageSize)}
          >
            Next
            <ChevronRight aria-hidden />
          </Button>
        </div>
      </PanelFooter>
    </Panel>
  );
}

/** Holds the table's height so the first read does not shove the footer. */
function BrowseSkeleton({ rows }: { rows: number }) {
  return (
    <div className="flex flex-col gap-2 p-4">
      {Array.from({ length: rows }, (_, index) => (
        <Skeleton key={index} className="h-6" />
      ))}
    </div>
  );
}
