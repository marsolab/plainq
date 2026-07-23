"use client";

import * as React from "react";
import { toast } from "sonner";

import {
  Dialog,
  DialogClose,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { InlineAlert } from "@/components/ui/feedback";
import { api } from "@/lib/api-client";
import { EVICTION_POLICY_LABELS } from "@/lib/constants";
import { formatDuration } from "@/lib/format";
import { cn } from "@/lib/utils";
import type { Queue, Subscription, Topic } from "@/lib/types";

interface ConnectQueueDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  topic: Topic;
  queues: Queue[];
  onConnected: () => void;
}

/**
 * One connection per queue-topic pair, so a queue already on this topic is
 * listed but not selectable — showing it dimmed answers "why isn't it here?"
 * without the operator having to go and check.
 */
export function ConnectQueueDialog({
  open,
  onOpenChange,
  topic,
  queues,
  onConnected,
}: ConnectQueueDialogProps) {
  const [search, setSearch] = React.useState("");
  const [selectedQueueId, setSelectedQueueId] = React.useState<string | null>(null);
  const [submitting, setSubmitting] = React.useState(false);
  const [error, setError] = React.useState<string | null>(null);

  React.useEffect(() => {
    if (!open) {
      setSearch("");
      setSelectedQueueId(null);
      setError(null);
      setSubmitting(false);
    }
  }, [open]);

  const connectedIds = React.useMemo(
    () => new Set((topic.subscriptions ?? []).map((sub) => sub.queueId)),
    [topic.subscriptions],
  );

  const term = search.trim().toLowerCase();
  const matches = queues.filter(
    (queue) =>
      term.length === 0 ||
      queue.queueName.toLowerCase().includes(term) ||
      queue.queueId.toLowerCase().includes(term),
  );
  const available = matches.filter((queue) => !connectedIds.has(queue.queueId));
  const connected = matches.filter((queue) => connectedIds.has(queue.queueId));

  const submit = async () => {
    if (!selectedQueueId) return;

    setSubmitting(true);
    setError(null);
    try {
      await api.topics.subscribe(topic.topicId, selectedQueueId);
      const queue = queues.find((candidate) => candidate.queueId === selectedQueueId);
      toast.success(`${queue?.queueName ?? "Queue"} connected to ${topic.topicName}`);
      onConnected();
      onOpenChange(false);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not connect the queue");
      setSubmitting(false);
    }
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle className="text-sm">Connect a queue to {topic.topicName}</DialogTitle>
          <DialogDescription>
            One connection per queue. Queues already on this topic are listed but cannot be
            selected again.
          </DialogDescription>
        </DialogHeader>

        <Input
          value={search}
          autoFocus
          autoComplete="off"
          spellCheck={false}
          placeholder="Search queues…"
          aria-label="Search queues"
          onChange={(event) => setSearch(event.target.value)}
        />

        {queues.length === 0 ? (
          <p className="border border-border px-2.5 py-3 text-xs text-muted-foreground">
            No queues exist yet. A topic can only fan out to queues that already exist.
          </p>
        ) : matches.length === 0 ? (
          <p className="border border-border px-2.5 py-3 text-xs text-muted-foreground">
            No queue matches "{search.trim()}".
          </p>
        ) : (
          <div className="max-h-64 overflow-y-auto border border-border">
            {available.map((queue) => {
              const selected = queue.queueId === selectedQueueId;

              return (
                <button
                  key={queue.queueId}
                  type="button"
                  aria-pressed={selected}
                  onClick={() => setSelectedQueueId(queue.queueId)}
                  className={cn(
                    "flex w-full items-center justify-between gap-3 border-t border-border px-2.5 py-2 text-left transition-colors first:border-t-0",
                    selected ? "bg-muted" : "hover:bg-muted/60",
                  )}
                >
                  <span className="min-w-0">
                    <span className="block truncate text-[13px] leading-[17px] font-medium">
                      {queue.queueName}
                    </span>
                    <span className="block truncate font-mono text-[10px] text-muted-foreground">
                      {queue.queueId}
                    </span>
                  </span>
                  <span className="shrink-0 text-[11px] text-muted-foreground">
                    {formatDuration(queue.retentionPeriodSeconds)} ·{" "}
                    {EVICTION_POLICY_LABELS[queue.evictionPolicy] ?? queue.evictionPolicy}
                  </span>
                </button>
              );
            })}

            {connected.map((queue) => (
              <div
                key={queue.queueId}
                className="flex items-center justify-between gap-3 border-t border-border px-2.5 py-2 opacity-45 first:border-t-0"
              >
                <span className="min-w-0">
                  <span className="block truncate text-[13px] leading-[17px] font-medium">
                    {queue.queueName}
                  </span>
                  <span className="block font-mono text-[10px] text-muted-foreground">
                    already connected
                  </span>
                </span>
              </div>
            ))}
          </div>
        )}

        {error ? <InlineAlert>{error}</InlineAlert> : null}

        <DialogFooter>
          <DialogClose asChild>
            <Button type="button" variant="outline" size="sm">
              Cancel
            </Button>
          </DialogClose>
          <Button
            type="button"
            size="sm"
            onClick={submit}
            disabled={!selectedQueueId || submitting}
            loading={submitting}
          >
            Connect
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

interface DisconnectQueueDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  topic: Topic;
  subscription: Subscription | null;
  queueName: string;
  onDisconnected: () => void;
}

/**
 * Names both sides. "Disconnect" alone reads as though the queue itself is
 * going away; it is not, and neither is anything already delivered to it.
 */
export function DisconnectQueueDialog({
  open,
  onOpenChange,
  topic,
  subscription,
  queueName,
  onDisconnected,
}: DisconnectQueueDialogProps) {
  const [submitting, setSubmitting] = React.useState(false);
  const [error, setError] = React.useState<string | null>(null);

  React.useEffect(() => {
    if (!open) {
      setError(null);
      setSubmitting(false);
    }
  }, [open]);

  const submit = async () => {
    if (!subscription) return;

    setSubmitting(true);
    setError(null);
    try {
      await api.topics.unsubscribe(topic.topicId, subscription.subscriptionId);
      toast.success(`${queueName} disconnected from ${topic.topicName}`);
      onDisconnected();
      onOpenChange(false);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not disconnect the queue");
      setSubmitting(false);
    }
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle className="text-sm">
            Disconnect {queueName} from {topic.topicName}?
          </DialogTitle>
          <DialogDescription className="text-xs text-strong">
            New publishes will no longer be copied to {queueName}. Messages already delivered
            stay in the queue.
          </DialogDescription>
        </DialogHeader>

        {error ? <InlineAlert>{error}</InlineAlert> : null}

        <DialogFooter>
          <DialogClose asChild>
            <Button type="button" variant="outline" size="sm">
              Cancel
            </Button>
          </DialogClose>
          <Button
            type="button"
            size="sm"
            onClick={submit}
            disabled={!subscription || submitting}
            loading={submitting}
          >
            Disconnect
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
