"use client";

import * as React from "react";
import { Copy, Ellipsis, Eraser, SquareArrowOutUpRight, Trash2 } from "lucide-react";
import { toast } from "sonner";

import { Button } from "@/components/ui/button";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import {
  Dialog,
  DialogClose,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { InlineAlert } from "@/components/ui/feedback";
import { MonoValue } from "@/components/ui/value";
import { api } from "@/lib/api-client";
import type { Queue } from "@/lib/types";

interface QueueRowActionsProps {
  queue: Queue;
  /**
   * Purge is a separate permission on the server. When the operator lacks it
   * the action stays on screen with the reason attached rather than vanishing.
   */
  canPurge: boolean;
  /** The queue left the list — the caller reloads the current page. */
  onDeleted: () => void;
}

type OpenDialog = "purge" | "delete" | null;

export function QueueRowActions({ queue, canPurge, onDeleted }: QueueRowActionsProps) {
  const [dialog, setDialog] = React.useState<OpenDialog>(null);
  const [pending, setPending] = React.useState(false);
  const [error, setError] = React.useState<string | null>(null);

  const close = () => {
    setDialog(null);
    setError(null);
  };

  const copyId = async () => {
    try {
      await navigator.clipboard.writeText(queue.queueId);
      toast.success("Queue ID copied");
    } catch {
      toast.error("Could not copy queue ID");
    }
  };

  const run = async (action: () => Promise<void>, done: string, after?: () => void) => {
    setPending(true);
    setError(null);
    try {
      await action();
      toast.success(done);
      close();
      after?.();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Request failed");
    } finally {
      setPending(false);
    }
  };

  return (
    <>
      <DropdownMenu>
        <DropdownMenuTrigger asChild>
          <Button
            variant="ghost"
            size="icon-sm"
            aria-label={`Actions for ${queue.queueName}`}
            className="text-muted-foreground"
          >
            <Ellipsis aria-hidden />
          </Button>
        </DropdownMenuTrigger>
        <DropdownMenuContent align="end" className="w-48">
          <DropdownMenuItem asChild>
            <a href={`/queue/${queue.queueId}`}>
              <SquareArrowOutUpRight aria-hidden />
              Open queue
            </a>
          </DropdownMenuItem>
          <DropdownMenuItem onSelect={() => void copyId()}>
            <Copy aria-hidden />
            Copy queue ID
          </DropdownMenuItem>
          <DropdownMenuSeparator />
          <DropdownMenuItem onSelect={() => setDialog("purge")}>
            <Eraser aria-hidden />
            Purge messages…
          </DropdownMenuItem>
          <DropdownMenuItem variant="destructive" onSelect={() => setDialog("delete")}>
            <Trash2 aria-hidden />
            Delete queue…
          </DropdownMenuItem>
        </DropdownMenuContent>
      </DropdownMenu>

      <Dialog
        open={dialog === "purge"}
        onOpenChange={(next) => {
          if (!next) close();
        }}
      >
        <DialogContent className="gap-4">
          <DialogHeader>
            <DialogTitle>Purge {queue.queueName}?</DialogTitle>
            <DialogDescription>
              Every message in the queue is deleted, including messages currently
              in flight with a consumer. Purging cannot be undone and the messages
              cannot be recovered.
            </DialogDescription>
          </DialogHeader>

          <MonoValue className="block border border-border bg-muted px-2.5 py-2 text-[11px] text-strong">
            {queue.queueId}
          </MonoValue>

          {error ? <InlineAlert>{error}</InlineAlert> : null}

          <DialogFooter>
            <DialogClose asChild>
              <Button variant="outline" type="button">
                Cancel
              </Button>
            </DialogClose>
            <Button
              variant="destructive"
              loading={pending}
              blockedReason={canPurge ? undefined : "Requires Purge permission"}
              onClick={() =>
                void run(
                  () => api.queues.purge(queue.queueId),
                  `Purged ${queue.queueName}`,
                )
              }
            >
              Purge queue
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <Dialog
        open={dialog === "delete"}
        onOpenChange={(next) => {
          if (!next) close();
        }}
      >
        <DialogContent className="gap-4">
          <DialogHeader>
            <DialogTitle>Delete {queue.queueName}?</DialogTitle>
            <DialogDescription>
              The queue and every message still held in it are removed. Producers
              and consumers addressing this queue will start failing. This cannot
              be undone.
            </DialogDescription>
          </DialogHeader>

          <MonoValue className="block border border-border bg-muted px-2.5 py-2 text-[11px] text-strong">
            {queue.queueId}
          </MonoValue>

          {error ? <InlineAlert>{error}</InlineAlert> : null}

          <DialogFooter>
            <DialogClose asChild>
              <Button variant="outline" type="button">
                Cancel
              </Button>
            </DialogClose>
            <Button
              variant="destructive"
              loading={pending}
              onClick={() =>
                void run(
                  () => api.queues.delete(queue.queueId),
                  `Deleted ${queue.queueName}`,
                  onDeleted,
                )
              }
            >
              Delete queue
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  );
}
