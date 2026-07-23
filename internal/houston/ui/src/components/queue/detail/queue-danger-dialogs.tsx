"use client";

import { useEffect, useState } from "react";
import { toast } from "sonner";

import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { InlineAlert } from "@/components/ui/feedback";
import { api } from "@/lib/api-client";
import { truncateId } from "@/lib/format";
import type { Queue } from "@/lib/types";

interface ConfirmProps {
  queue: Queue;
  open: boolean;
  onOpenChange: (open: boolean) => void;
}

/**
 * Both destructive queue actions are confirmed by typing the queue's name. The
 * name is the only handle an operator carries in their head; typing it is the
 * one check that catches "wrong tab, right muscle memory".
 */
function useTypedConfirmation(open: boolean) {
  const [typed, setTyped] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!open) return;
    setTyped("");
    setBusy(false);
    setError(null);
  }, [open]);

  return { typed, setTyped, busy, setBusy, error, setError };
}

export function PurgeQueueDialog({ queue, open, onOpenChange }: ConfirmProps) {
  const { typed, setTyped, busy, setBusy, error, setError } = useTypedConfirmation(open);
  const confirmed = typed === queue.queueName;

  const purge = async () => {
    setBusy(true);
    setError(null);
    try {
      await api.queues.purge(queue.queueId);
      // No count is claimed: the purge response does not return one.
      toast.success(`${queue.queueName} purged`);
      onOpenChange(false);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Purge failed");
      setBusy(false);
    }
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle className="text-[15px]">Purge {queue.queueName}?</DialogTitle>
          <DialogDescription className="text-strong">
            All messages are removed; the queue and its configuration remain. Messages
            cannot be recovered, and no exact count is promised unless the server
            returns one.
          </DialogDescription>
        </DialogHeader>

        <div className="flex flex-col gap-1.5">
          <Label htmlFor="purge-confirm">
            Type <span className="font-mono text-foreground">{queue.queueName}</span> to
            confirm
          </Label>
          <Input
            id="purge-confirm"
            value={typed}
            autoComplete="off"
            spellCheck={false}
            onChange={(event) => setTyped(event.target.value)}
            className="font-mono"
          />
        </div>

        {error ? (
          <InlineAlert>
            {error} — the result is unknown; refresh before retrying.
          </InlineAlert>
        ) : null}

        <DialogFooter className="border-t border-border pt-3">
          <Button variant="outline" onClick={() => onOpenChange(false)}>
            Cancel
          </Button>
          <Button variant="destructive" disabled={!confirmed} loading={busy} onClick={purge}>
            Purge queue
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

export function DeleteQueueDialog({
  queue,
  open,
  onOpenChange,
  deadLetterLabel,
}: ConfirmProps & { deadLetterLabel: string | null }) {
  const { typed, setTyped, busy, setBusy, error, setError } = useTypedConfirmation(open);
  const confirmed = typed === queue.queueName;

  const remove = async () => {
    setBusy(true);
    setError(null);
    try {
      await api.queues.delete(queue.queueId);
      toast.success(`${queue.queueName} deleted`);
      window.location.href = "/";
    } catch (err) {
      setError(err instanceof Error ? err.message : "Delete failed");
      setBusy(false);
    }
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle className="text-[15px]">Delete {queue.queueName}?</DialogTitle>
          <DialogDescription className="text-strong">
            The queue and all its messages are permanently removed. Producers and
            consumers using ID{" "}
            <span className="font-mono text-[11px]">{truncateId(queue.queueId)}</span>{" "}
            will start failing.
            {deadLetterLabel ? ` ${deadLetterLabel} is not affected.` : ""}
          </DialogDescription>
        </DialogHeader>

        <div className="flex flex-col gap-1.5">
          <Label htmlFor="delete-confirm">
            Type <span className="font-mono text-foreground">{queue.queueName}</span> to
            confirm
          </Label>
          <Input
            id="delete-confirm"
            value={typed}
            autoComplete="off"
            spellCheck={false}
            onChange={(event) => setTyped(event.target.value)}
            className="font-mono"
          />
        </div>

        {error ? (
          <InlineAlert>
            {error} — the result is unknown; refresh before retrying.
          </InlineAlert>
        ) : null}

        <DialogFooter className="border-t border-border pt-3">
          <Button variant="outline" onClick={() => onOpenChange(false)}>
            Cancel
          </Button>
          <Button variant="destructive" disabled={!confirmed} loading={busy} onClick={remove}>
            Delete queue
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
