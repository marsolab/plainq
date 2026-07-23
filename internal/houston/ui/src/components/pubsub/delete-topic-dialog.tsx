"use client";

import * as React from "react";
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
import { formatCount } from "@/lib/format";
import type { Topic } from "@/lib/types";
import { deleteTopic } from "./pubsub-api";

interface DeleteTopicDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  topic: Topic;
  onDeleted: () => void;
}

/**
 * Typed-name confirmation, like the destructive queue actions: the name is the
 * only handle an operator carries in their head. The copy states what survives
 * — deleting a topic stops the fan-out, it does not touch the queues it fanned
 * out to or anything already delivered to them.
 */
export function DeleteTopicDialog({
  open,
  onOpenChange,
  topic,
  onDeleted,
}: DeleteTopicDialogProps) {
  const [typed, setTyped] = React.useState("");
  const [submitting, setSubmitting] = React.useState(false);
  const [error, setError] = React.useState<string | null>(null);

  React.useEffect(() => {
    if (!open) {
      setTyped("");
      setSubmitting(false);
      setError(null);
    }
  }, [open]);

  const connected = (topic.subscriptions ?? []).length;
  const confirmed = typed === topic.topicName;

  const submit = async () => {
    if (!confirmed) return;

    setSubmitting(true);
    setError(null);
    try {
      await deleteTopic(topic.topicId);
      toast.success(`Topic ${topic.topicName} deleted`);
      onDeleted();
      onOpenChange(false);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not delete the topic");
      setSubmitting(false);
    }
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle className="text-[15px]">Delete topic {topic.topicName}?</DialogTitle>
          <DialogDescription className="text-strong">
            Publishing to this topic will stop.{" "}
            {connected === 0 ? (
              <>No queues are connected to it.</>
            ) : (
              <>
                The {formatCount(connected)} connected{" "}
                {connected === 1 ? "queue" : "queues"} and their existing messages are{" "}
                <span className="font-semibold">not</span> deleted.
              </>
            )}
          </DialogDescription>
        </DialogHeader>

        <div className="flex flex-col gap-1.5">
          <Label htmlFor="delete-topic-confirm">
            Type <span className="font-mono text-foreground">{topic.topicName}</span> to
            confirm
          </Label>
          <Input
            id="delete-topic-confirm"
            value={typed}
            autoComplete="off"
            spellCheck={false}
            onChange={(event) => setTyped(event.target.value)}
            className="font-mono"
          />
        </div>

        {error ? <InlineAlert>{error}</InlineAlert> : null}

        <DialogFooter className="border-t border-border pt-3">
          <Button variant="outline" onClick={() => onOpenChange(false)}>
            Cancel
          </Button>
          <Button
            variant="destructive"
            disabled={!confirmed}
            loading={submitting}
            onClick={submit}
          >
            Delete topic
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
