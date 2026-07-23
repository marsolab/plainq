"use client";

import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import type { Queue } from "@/lib/types";

import type { QueueMessage } from "./message";

interface DeleteMessageDialogProps {
  message: QueueMessage | null;
  queue: Queue;
  open: boolean;
  removing: boolean;
  onOpenChange: (open: boolean) => void;
  onConfirm: (message: QueueMessage) => void;
}

/**
 * Browse's row action is a removal by an operator, not a consumer completing
 * work — the wording says so explicitly, because the two look identical in the
 * table and mean opposite things downstream. It reaches `…/messages/ack`
 * because that is the only removal the transport exposes, and the dialog names
 * it rather than implying a second endpoint exists.
 *
 * A dialog, never `confirm()`: this is an explicit confirmation of a
 * destructive act, so it gets the destructive treatment and a real cancel.
 */
export function DeleteMessageDialog({
  message,
  queue,
  open,
  removing,
  onOpenChange,
  onConfirm,
}: DeleteMessageDialogProps) {
  if (!message) return null;

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle className="text-[15px]">Delete this message?</DialogTitle>
          <DialogDescription className="text-strong">
            Message <span className="font-mono text-[11px]">{message.messageId}</span> will
            be permanently removed from {queue.queueName}. No consumer completes it — the
            removal goes through the same acknowledge call, which is the only deletion the
            server exposes.
            {message.inFlight
              ? " This message is currently held by a consumer; deleting it now means that consumer's acknowledgement will find nothing."
              : ""}
          </DialogDescription>
        </DialogHeader>
        <DialogFooter className="border-t border-border pt-3">
          <Button variant="outline" onClick={() => onOpenChange(false)}>
            Cancel
          </Button>
          <Button
            variant="destructive"
            loading={removing}
            onClick={() => onConfirm(message)}
          >
            Delete message
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
