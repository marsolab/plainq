"use client";

import * as React from "react";
import { toast } from "sonner";
import { Info, Plus, Send, X } from "lucide-react";

import {
  Dialog,
  DialogClose,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Textarea } from "@/components/ui/input";
import { InlineAlert } from "@/components/ui/feedback";
import { Status } from "@/components/ui/status";
import { Micro, MonoValue } from "@/components/ui/value";
import { formatBytes, formatCount } from "@/lib/format";
import { cn } from "@/lib/utils";
import type { PublishResponse, Topic } from "@/lib/types";
import { publishMessages } from "./pubsub-api";

/**
 * Every body reaches the wire as Base64 — the transport's message body is a
 * byte string. Text and JSON are encoded here (JSON only adds a parse check
 * first); Base64 is passed through verbatim after a decode check, which is the
 * only way to publish a payload that is not valid UTF-8.
 */
type BodyFormat = "text" | "json" | "base64";

const FORMATS: { value: BodyFormat; label: string }[] = [
  { value: "text", label: "Text" },
  { value: "json", label: "JSON" },
  { value: "base64", label: "Base64" },
];

const PLACEHOLDERS: Record<BodyFormat, string> = {
  text: "Message body",
  json: '{"orderId":"ord_10301","status":"created"}',
  base64: "eyJvcmRlcklkIjoib3JkXzEwMzAxIn0=",
};

const BASE64_PATTERN = /^[A-Za-z0-9+/]*={0,2}$/;
const BASE64_HINT =
  "Not valid Base64. Use standard Base64 — A–Z, a–z, 0–9, + / and = padding.";

function utf8ToBase64(input: string): string {
  const bytes = new TextEncoder().encode(input);
  let binary = "";
  bytes.forEach((byte) => {
    binary += String.fromCharCode(byte);
  });
  return btoa(binary);
}

interface ComposedMessage {
  /** Payload size on the wire, or null when it cannot be known yet. */
  bytes: number | null;
  error: string | null;
  /** Base64 body ready to send, or null while the message is not publishable. */
  wire: string | null;
}

function composeMessage(format: BodyFormat, body: string): ComposedMessage {
  if (format === "base64") {
    // Pasted Base64 usually arrives wrapped; the line breaks are not payload.
    const compact = body.replace(/\s+/g, "");
    if (compact.length === 0) return { bytes: 0, error: null, wire: null };
    if (compact.length % 4 !== 0 || !BASE64_PATTERN.test(compact)) {
      return { bytes: null, error: BASE64_HINT, wire: null };
    }

    try {
      return { bytes: atob(compact).length, error: null, wire: compact };
    } catch {
      return { bytes: null, error: BASE64_HINT, wire: null };
    }
  }

  const bytes = new TextEncoder().encode(body).length;
  if (body.length === 0) return { bytes: 0, error: null, wire: null };

  if (format === "json") {
    try {
      JSON.parse(body);
    } catch (err) {
      return {
        bytes,
        error: err instanceof Error ? err.message : "Body is not valid JSON",
        wire: null,
      };
    }
  }

  return { bytes, error: null, wire: utf8ToBase64(body) };
}

interface PublishDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  topic: Topic;
  /** queueId → queueName, for naming the queues a publish reached. */
  queueNames: Map<string, string>;
  /** A publish moves the topic's counters, so the readings are re-read. */
  onPublished?: () => void;
}

export function PublishDialog({
  open,
  onOpenChange,
  topic,
  queueNames,
  onPublished,
}: PublishDialogProps) {
  const [format, setFormat] = React.useState<BodyFormat>("text");
  const [bodies, setBodies] = React.useState<string[]>([""]);
  const [submitting, setSubmitting] = React.useState(false);
  const [error, setError] = React.useState<string | null>(null);
  const [result, setResult] = React.useState<
    { response: PublishResponse; messageCount: number } | null
  >(null);

  React.useEffect(() => {
    if (!open) {
      setFormat("text");
      setBodies([""]);
      setSubmitting(false);
      setError(null);
      setResult(null);
    }
  }, [open]);

  const subscriptions = topic.subscriptions ?? [];
  const connectedNames = subscriptions.map(
    (sub) => sub.queueName || queueNames.get(sub.queueId) || sub.queueId,
  );

  const composed = React.useMemo(
    () => bodies.map((body) => composeMessage(format, body)),
    [bodies, format],
  );

  const ready = composed.filter((message) => message.wire !== null);
  const canSubmit = ready.length === composed.length && !submitting;

  const setBody = (index: number, value: string) => {
    setBodies((current) => current.map((body, i) => (i === index ? value : body)));
  };

  const submit = async (event: React.FormEvent) => {
    event.preventDefault();
    if (!canSubmit) return;

    const wire = composed
      .map((message) => message.wire)
      .filter((body): body is string => body !== null);

    setSubmitting(true);
    setError(null);
    try {
      const response = await publishMessages(topic.topicId, wire);
      setResult({ response, messageCount: wire.length });
      onPublished?.();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Publish failed");
    } finally {
      setSubmitting(false);
    }
  };

  const count = bodies.length;

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="gap-0 p-0 sm:max-w-[460px]">
        <DialogHeader className="px-5 pt-5">
          <DialogTitle className="text-base leading-[22px]">
            Publish to {topic.topicName}
          </DialogTitle>
          <DialogDescription className="flex flex-wrap items-center gap-2 text-[11px]">
            <Micro className="text-[10px]">{topic.topicId}</Micro>
            <span>
              · {formatCount(subscriptions.length)} connected{" "}
              {subscriptions.length === 1 ? "queue" : "queues"}
            </span>
          </DialogDescription>
        </DialogHeader>

        {result ? (
          <PublishResult
            response={result.response}
            messageCount={result.messageCount}
            queueNames={queueNames}
            onPublishAnother={() => {
              setResult(null);
              setError(null);
            }}
          />
        ) : (
          <form onSubmit={submit}>
            <div className="flex max-h-[52vh] flex-col gap-3 overflow-y-auto px-5 pt-3.5 pb-4">
              <div className="flex w-fit border border-border">
                {FORMATS.map((option, index) => {
                  const active = option.value === format;

                  return (
                    <button
                      key={option.value}
                      type="button"
                      aria-pressed={active}
                      onClick={() => setFormat(option.value)}
                      className={cn(
                        "px-3 py-[5px] text-xs font-medium transition-colors",
                        index > 0 && "border-l border-border",
                        active
                          ? "bg-primary text-primary-foreground"
                          : "text-strong hover:bg-muted",
                      )}
                    >
                      {option.label}
                    </button>
                  );
                })}
              </div>

              {bodies.map((body, index) => {
                const message = composed[index]!;
                const last = index === bodies.length - 1;

                return (
                  <div key={index} className="flex flex-col gap-2">
                    <div className="border border-border">
                      <Textarea
                        value={body}
                        autoFocus={index === 0}
                        spellCheck={false}
                        rows={4}
                        aria-label={count === 1 ? "Message body" : `Message ${index + 1} body`}
                        aria-invalid={Boolean(message.error) || undefined}
                        placeholder={PLACEHOLDERS[format]}
                        onChange={(event) => setBody(index, event.target.value)}
                        className="min-h-[72px] resize-y border-0 p-2.5 font-mono text-xs leading-[1.5]"
                      />
                      <div className="flex items-center justify-between gap-3 border-t border-border bg-background px-2.5 py-1.5">
                        <Micro className="text-[10px]">
                          {message.bytes === null ? "—" : formatBytes(message.bytes)} · sent as
                          opaque bytes
                        </Micro>
                        <div className="flex shrink-0 items-center gap-1">
                          {count > 1 ? (
                            <Button
                              type="button"
                              variant="ghost"
                              size="sm"
                              className="h-6 px-1.5 text-[11px]"
                              aria-label={`Remove message ${index + 1}`}
                              onClick={() =>
                                setBodies((current) => current.filter((_, i) => i !== index))
                              }
                            >
                              <X aria-hidden />
                              Remove
                            </Button>
                          ) : null}
                          {last ? (
                            <Button
                              type="button"
                              variant="ghost"
                              size="sm"
                              className="h-6 px-1.5 text-[11px]"
                              onClick={() => setBodies((current) => [...current, ""])}
                            >
                              <Plus aria-hidden />
                              Add message
                            </Button>
                          ) : null}
                        </div>
                      </div>
                    </div>

                    {message.error ? <InlineAlert>{message.error}</InlineAlert> : null}
                  </div>
                );
              })}

              {subscriptions.length > 0 ? (
                <div className="flex gap-2 border border-border bg-muted px-2.5 py-2">
                  <Info className="mt-px size-3.5 shrink-0 text-strong" aria-hidden />
                  <span className="text-xs leading-relaxed text-strong">
                    Each message will be copied to{" "}
                    <span className="font-semibold">
                      {formatCount(subscriptions.length)} connected{" "}
                      {subscriptions.length === 1 ? "queue" : "queues"}
                    </span>
                    : {connectedNames.join(", ")}.
                  </span>
                </div>
              ) : (
                <InlineAlert tone="warning">
                  {topic.topicName} has no connected queues. Publishing succeeds with 0
                  deliveries — messages are not stored on the topic.
                </InlineAlert>
              )}

              {error ? (
                <InlineAlert>
                  {error}. Delivery may have partially completed — check the destination queues
                  before retrying, because a retry can duplicate delivered messages.
                </InlineAlert>
              ) : null}
            </div>

            <div className="flex justify-end gap-2 border-t border-border px-5 py-3.5">
              <DialogClose asChild>
                <Button type="button" variant="outline">
                  Cancel
                </Button>
              </DialogClose>
              <Button type="submit" disabled={!canSubmit} loading={submitting}>
                <Send aria-hidden />
                {subscriptions.length === 0
                  ? "Publish anyway"
                  : `Publish ${formatCount(count)} ${count === 1 ? "message" : "messages"}`}
              </Button>
            </div>
          </form>
        )}
      </DialogContent>
    </Dialog>
  );
}

function ResultTile({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="border-r border-border px-2.5 py-2 last:border-r-0">
      <div className="text-[10px] text-muted-foreground">{label}</div>
      <MonoValue className="text-sm">{children}</MonoValue>
    </div>
  );
}

function PublishResult({
  response,
  messageCount,
  queueNames,
  onPublishAnother,
}: {
  response: PublishResponse;
  messageCount: number;
  queueNames: Map<string, string>;
  onPublishAnother: () => void;
}) {
  const queueIds = response.queueIds ?? [];
  const messageIds = response.messageIds ?? [];
  // Fan-out is not atomic, so a 2xx can still cover a short delivery: one ID
  // per message per queue is what a complete fan-out looks like.
  const expected = queueIds.length * messageCount;
  const shortDelivery = response.deliveredCount < expected;
  // IDs arrive as one flat run per queue, in queueIds order — pairing them by
  // position only holds while that shape does.
  const paired = messageIds.length === expected;

  const copyIds = async () => {
    if (messageIds.length === 0) return;
    try {
      await navigator.clipboard.writeText(messageIds.join("\n"));
      toast.success(
        `${formatCount(messageIds.length)} message ${messageIds.length === 1 ? "ID" : "IDs"} copied`,
      );
    } catch {
      toast.error("Could not copy the message IDs");
    }
  };

  return (
    <>
      <div className="flex max-h-[52vh] flex-col gap-3 overflow-y-auto px-5 pt-3.5 pb-4">
        <Status tone={shortDelivery ? "warning" : "healthy"} className="text-[13px] font-semibold">
          {shortDelivery ? "Published, delivery incomplete" : "Published"}
        </Status>

        {shortDelivery ? (
          <InlineAlert>
            Delivery may have partially completed. Check the destination queues before
            retrying — a retry can duplicate delivered messages.
          </InlineAlert>
        ) : null}

        <div className="grid grid-cols-3 border border-border">
          <ResultTile label="Messages">{formatCount(messageCount)}</ResultTile>
          <ResultTile label="Queues reached">{formatCount(queueIds.length)}</ResultTile>
          <ResultTile label="Deliveries">{formatCount(response.deliveredCount)}</ResultTile>
        </div>

        {queueIds.length > 0 ? (
          <div className="border border-border">
            {queueIds.map((queueId, index) => {
              const ids = paired
                ? messageIds.slice(index * messageCount, (index + 1) * messageCount)
                : [];

              return (
                <div
                  key={queueId}
                  className="flex items-start justify-between gap-3 border-t border-border px-2.5 py-1.5 first:border-t-0"
                >
                  <span className="min-w-0 truncate text-xs font-medium">
                    {queueNames.get(queueId) ?? queueId}
                  </span>
                  <span className="flex shrink-0 flex-col items-end gap-0.5">
                    {ids.length > 0 ? (
                      ids.map((id) => (
                        <Micro key={id} className="text-[10px]">
                          {id}
                        </Micro>
                      ))
                    ) : (
                      <Micro className="text-[10px]">—</Micro>
                    )}
                  </span>
                </div>
              );
            })}
          </div>
        ) : (
          <p className="text-xs text-muted-foreground">
            No queue was connected, so nothing was copied anywhere. Topics do not store
            messages.
          </p>
        )}
      </div>

      <div className="flex justify-end gap-2 border-t border-border px-5 py-3.5">
        <Button
          type="button"
          variant="outline"
          size="sm"
          onClick={copyIds}
          disabled={messageIds.length === 0}
        >
          Copy IDs
        </Button>
        <Button type="button" variant="outline" size="sm" onClick={onPublishAnother}>
          Publish another
        </Button>
        <DialogClose asChild>
          <Button type="button" size="sm">
            Done
          </Button>
        </DialogClose>
      </div>
    </>
  );
}
