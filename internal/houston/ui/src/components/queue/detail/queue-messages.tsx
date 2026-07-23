"use client";

import { useCallback, useEffect, useState } from "react";
import { toast } from "sonner";

import { Banner } from "@/components/ui/feedback";
import { Button } from "@/components/ui/button";
import { ScopeBadge } from "@/components/ui/badge";
import { formatClock } from "@/lib/format";
import { api } from "@/lib/api-client";
import type { Queue } from "@/lib/types";

import { MessageBrowser } from "./message-browser";
import { MessageComposer } from "./message-composer";
import { ReceiveWorkbench } from "./receive-workbench";
import { PayloadInspector } from "./payload-inspector";
import { DeleteMessageDialog } from "./delete-message-dialog";
import {
  fromPeek,
  fromReceive,
  type AcknowledgeOutcome,
  type QueueMessage,
} from "./message";

/** The browse window. The peek endpoint is offset-paginated and returns a total. */
const PAGE_SIZE = 25;

/**
 * S10, against the real message API. Two panels that must never be mistaken
 * for one another: the workbench *consumes* (receive hides a message for the
 * visibility timeout and raises its attempt count, acknowledge completes it),
 * Browse does not (peek leaves visibility and attempts untouched, and its row
 * action removes).
 *
 * Both halves talk to the same server. Receive/acknowledge is
 * `POST …/messages/receive` then `POST …/messages/ack`; browse is
 * `GET …/messages`, whose row action reaches the same ack endpoint because
 * that is the only removal the transport exposes.
 */
export function QueueMessages({ queue }: { queue: Queue }) {
  const queueId = queue.queueId;

  const [messages, setMessages] = useState<QueueMessage[]>([]);
  const [total, setTotal] = useState(0);
  const [offset, setOffset] = useState(0);
  const [loading, setLoading] = useState(true);
  const [browsing, setBrowsing] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [browsedAt, setBrowsedAt] = useState<number | null>(null);

  const [inspecting, setInspecting] = useState<QueueMessage | null>(null);
  const [deleting, setDeleting] = useState<QueueMessage | null>(null);
  const [removing, setRemoving] = useState(false);

  const browse = useCallback(async () => {
    setBrowsing(true);
    try {
      const page = await api.queues.messages.peek(queueId, {
        limit: PAGE_SIZE,
        offset,
      });

      setMessages(page.messages.map(fromPeek));
      setTotal(page.total);
      setError(null);
      setBrowsedAt(Date.now());

      // The queue can shrink under the window — acknowledgements here, or a
      // consumer draining elsewhere — which would strand the operator on a
      // page past the end. Step back to the last populated one instead.
      if (offset > 0 && offset >= page.total) {
        const lastPage = Math.max(0, Math.ceil(page.total / PAGE_SIZE) - 1) * PAGE_SIZE;
        setOffset(lastPage);
      }
    } catch (err) {
      // Stale on failure: the rows already on screen stay, labelled.
      setError(err instanceof Error ? err.message : "Failed to browse messages");
    } finally {
      setLoading(false);
      setBrowsing(false);
    }
  }, [queueId, offset]);

  useEffect(() => {
    void browse();
  }, [browse]);

  const send = useCallback(
    async (bodies: string[]): Promise<string[]> => {
      const result = await api.queues.messages.send(queueId, bodies);
      await browse();
      return result.messageIds;
    },
    [queueId, browse],
  );

  const receive = useCallback(
    async (batch: number): Promise<QueueMessage[]> => {
      const result = await api.queues.messages.receive(queueId, batch);
      // Receiving changed visibility for these ids, so the browse view is now
      // out of date whether or not anything came back.
      await browse();
      return result.messages.map(fromReceive);
    },
    [queueId, browse],
  );

  const acknowledge = useCallback(
    async (ids: string[]): Promise<AcknowledgeOutcome> => {
      const result = await api.queues.messages.ack(queueId, ids);
      await browse();
      return {
        acknowledged: result.successful,
        failed: result.failed ?? [],
      };
    },
    [queueId, browse],
  );

  const confirmDelete = async (message: QueueMessage) => {
    setRemoving(true);
    try {
      const result = await api.queues.messages.ack(queueId, [message.messageId]);
      const failure = (result.failed ?? [])[0];

      if (result.successful.length === 0) {
        toast.error("Message not deleted", {
          description: failure?.error ?? "The server removed nothing.",
        });
      } else {
        toast.success("Message deleted");
        setDeleting(null);
      }

      await browse();
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "Failed to delete message");
    } finally {
      setRemoving(false);
    }
  };

  return (
    <div className="flex flex-col gap-4">
      {error ? (
        <Banner
          tone="error"
          action={
            <Button variant="link" size="sm" onClick={() => void browse()} loading={browsing}>
              Retry
            </Button>
          }
        >
          <span className="inline-flex items-center gap-2">
            <ScopeBadge tone="warning">Stale</ScopeBadge>
            {error} —{" "}
            {browsedAt
              ? `showing the browse read at ${formatClock(browsedAt)}.`
              : "nothing has been read yet."}
          </span>
        </Banner>
      ) : null}

      <div className="grid items-stretch gap-4 xl:grid-cols-2">
        <MessageComposer onSend={send} />
        <ReceiveWorkbench
          queue={queue}
          onReceive={receive}
          onAcknowledge={acknowledge}
          onInspect={setInspecting}
        />
      </div>

      <MessageBrowser
        queue={queue}
        messages={messages}
        total={total}
        offset={offset}
        pageSize={PAGE_SIZE}
        loading={loading}
        refreshing={browsing}
        browsedAt={browsedAt}
        onPage={setOffset}
        onRefresh={() => void browse()}
        onInspect={setInspecting}
        onDelete={setDeleting}
      />

      <PayloadInspector
        queue={queue}
        message={inspecting}
        open={inspecting !== null}
        onOpenChange={(open) => !open && setInspecting(null)}
      />
      <DeleteMessageDialog
        queue={queue}
        message={deleting}
        open={deleting !== null}
        removing={removing}
        onOpenChange={(open) => !open && setDeleting(null)}
        onConfirm={(message) => void confirmDelete(message)}
      />
    </div>
  );
}
