import { useCallback, useEffect, useState } from "react";
import {
  Table,
  TableHeader,
  TableBody,
  TableRow,
  TableHead,
  TableCell,
} from "@/components/ui/table";
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { api } from "@/lib/api-client";
import type { PeekMessage, ReceiveMessage } from "@/lib/types";
import {
  RefreshCw,
  Send,
  Download,
  Trash2,
  Check,
  ChevronLeft,
  ChevronRight,
} from "lucide-react";
import { toast } from "sonner";

const PAGE_SIZE = 25;

interface QueueMessagesProps {
  queueId: string;
}

export function QueueMessages({ queueId }: QueueMessagesProps) {
  const [messages, setMessages] = useState<PeekMessage[]>([]);
  const [total, setTotal] = useState(0);
  const [offset, setOffset] = useState(0);
  const [loading, setLoading] = useState(true);

  const [body, setBody] = useState("");
  const [sending, setSending] = useState(false);

  const [batch, setBatch] = useState(1);
  const [receiving, setReceiving] = useState(false);
  const [received, setReceived] = useState<ReceiveMessage[]>([]);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const res = await api.queues.messages.peek(queueId, {
        limit: PAGE_SIZE,
        offset,
      });
      setMessages(res.messages);
      setTotal(res.total);
    } catch (err) {
      toast.error(
        err instanceof Error ? err.message : "Failed to load messages",
      );
    } finally {
      setLoading(false);
    }
  }, [queueId, offset]);

  useEffect(() => {
    load();
  }, [load]);

  const handleSend = async () => {
    if (!body.trim()) {
      toast.error("Message body is empty");
      return;
    }
    setSending(true);
    try {
      const res = await api.queues.messages.send(queueId, [body]);
      toast.success(`Sent ${res.messageIds.length} message(s)`);
      setBody("");
      if (offset === 0) {
        await load();
      } else {
        setOffset(0);
      }
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "Failed to send");
    } finally {
      setSending(false);
    }
  };

  const handleReceive = async () => {
    setReceiving(true);
    try {
      const res = await api.queues.messages.receive(queueId, batch);
      setReceived(res.messages);
      if (res.messages.length === 0) {
        toast.info("No messages available to receive");
      } else {
        toast.success(`Received ${res.messages.length} message(s)`);
      }
      await load();
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "Failed to receive");
    } finally {
      setReceiving(false);
    }
  };

  const handleAck = async (ids: string[]) => {
    if (ids.length === 0) return;
    try {
      const res = await api.queues.messages.ack(queueId, ids);
      toast.success(`Acknowledged ${res.successful.length} message(s)`);
      setReceived((prev) =>
        prev.filter((m) => !res.successful.includes(m.id)),
      );
      await load();
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "Failed to acknowledge");
    }
  };

  const hasPrev = offset > 0;
  const hasNext = offset + PAGE_SIZE < total;

  return (
    <div className="mt-4 space-y-6">
      {/* Send */}
      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="text-sm font-medium">Send a message</CardTitle>
        </CardHeader>
        <CardContent className="space-y-3">
          <textarea
            className="flex min-h-20 w-full rounded-md border border-input bg-surface px-3 py-2 text-sm shadow-sm focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
            placeholder="Message body…"
            value={body}
            onChange={(e) => setBody(e.target.value)}
          />
          <div className="flex justify-end">
            <Button size="sm" onClick={handleSend} disabled={sending}>
              <Send className="size-4" />
              {sending ? "Sending…" : "Send"}
            </Button>
          </div>
        </CardContent>
      </Card>

      {/* Receive */}
      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="text-sm font-medium">
            Receive (consume)
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-3">
          <div className="flex items-end gap-2">
            <div className="w-24">
              <label className="mb-1 block text-xs text-muted-foreground">
                Batch (1–10)
              </label>
              <Input
                type="number"
                min={1}
                max={10}
                value={batch}
                onChange={(e) =>
                  setBatch(
                    Math.min(10, Math.max(1, Number(e.target.value) || 1)),
                  )
                }
              />
            </div>
            <Button
              size="sm"
              variant="outline"
              onClick={handleReceive}
              disabled={receiving}
            >
              <Download className="size-4" />
              {receiving ? "Receiving…" : "Receive"}
            </Button>
          </div>
          <p className="text-xs text-muted-foreground">
            Received messages stay invisible for the visibility timeout until
            acknowledged.
          </p>

          {received.length > 0 && (
            <div className="space-y-2 rounded-md border p-3">
              <div className="flex items-center justify-between">
                <span className="text-xs font-medium">
                  In-flight ({received.length})
                </span>
                <Button
                  size="sm"
                  variant="ghost"
                  onClick={() => handleAck(received.map((m) => m.id))}
                >
                  <Check className="size-4" />
                  Ack all
                </Button>
              </div>
              {received.map((m) => (
                <div
                  key={m.id}
                  className="flex items-center justify-between gap-2 border-t pt-2 first:border-t-0 first:pt-0"
                >
                  <div className="min-w-0">
                    <p className="truncate font-mono text-xs text-muted-foreground">
                      {m.id}
                    </p>
                    <p className="truncate text-sm" title={m.body}>
                      {m.body}
                    </p>
                  </div>
                  <Button
                    size="sm"
                    variant="ghost"
                    onClick={() => handleAck([m.id])}
                  >
                    <Check className="size-4" />
                    Ack
                  </Button>
                </div>
              ))}
            </div>
          )}
        </CardContent>
      </Card>

      {/* Browse */}
      <div>
        <div className="mb-2 flex items-center justify-between">
          <h3 className="text-sm font-medium">
            Browse{" "}
            <span className="text-muted-foreground">({total} total)</span>
          </h3>
          <Button size="sm" variant="outline" onClick={load} disabled={loading}>
            <RefreshCw className="size-4" />
            Refresh
          </Button>
        </div>

        <div className="rounded-md border">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>ID</TableHead>
                <TableHead>Body</TableHead>
                <TableHead className="w-20 text-right">Retries</TableHead>
                <TableHead className="w-28">Status</TableHead>
                <TableHead className="w-16" />
              </TableRow>
            </TableHeader>
            <TableBody>
              {loading ? (
                <TableRow>
                  <TableCell colSpan={5} className="text-center text-muted-foreground">
                    Loading…
                  </TableCell>
                </TableRow>
              ) : messages.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={5} className="text-center text-muted-foreground">
                    No messages
                  </TableCell>
                </TableRow>
              ) : (
                messages.map((m) => (
                  <TableRow key={m.id}>
                    <TableCell className="font-mono text-xs">
                      {m.id}
                    </TableCell>
                    <TableCell className="max-w-xs truncate" title={m.body}>
                      {m.body}
                    </TableCell>
                    <TableCell className="text-right">{m.retries}</TableCell>
                    <TableCell>
                      <Badge variant={m.inFlight ? "secondary" : "default"}>
                        {m.inFlight ? "In-flight" : "Visible"}
                      </Badge>
                    </TableCell>
                    <TableCell className="text-right">
                      <Button
                        size="sm"
                        variant="ghost"
                        onClick={() => handleAck([m.id])}
                        title="Delete message"
                      >
                        <Trash2 className="size-4" />
                      </Button>
                    </TableCell>
                  </TableRow>
                ))
              )}
            </TableBody>
          </Table>
        </div>

        {total > PAGE_SIZE && (
          <div className="mt-3 flex items-center justify-end gap-2">
            <Button
              size="sm"
              variant="outline"
              disabled={!hasPrev}
              onClick={() => setOffset((o) => Math.max(0, o - PAGE_SIZE))}
            >
              <ChevronLeft className="size-4" />
              Prev
            </Button>
            <Button
              size="sm"
              variant="outline"
              disabled={!hasNext}
              onClick={() => setOffset((o) => o + PAGE_SIZE)}
            >
              Next
              <ChevronRight className="size-4" />
            </Button>
          </div>
        )}
      </div>
    </div>
  );
}
