"use client";

import { useEffect, useState } from "react";
import { Clock, Download, RefreshCw } from "lucide-react";
import { toast } from "sonner";

import { Panel, PanelBody, PanelTitleBar } from "@/components/ui/panel";
import { Button } from "@/components/ui/button";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Status } from "@/components/ui/status";
import { formatBytes, formatDuration } from "@/lib/format";
import type { Queue } from "@/lib/types";

import type { AcknowledgeOutcome, QueueMessage } from "./message";
import { previewOf } from "./payload";

/** The receive endpoint accepts 1–10 per call; the server rejects anything else. */
const BATCH_SIZES = [1, 2, 5, 10];

interface ReceivedLease {
  message: QueueMessage;
  /**
   * When the lease is *estimated* to lapse. The receive response carries no
   * deadline, so this is response time + the queue's visibility timeout, and
   * it is labelled as an estimate everywhere it is shown.
   */
  estimatedDeadline: number;
}

interface ReceiveWorkbenchProps {
  queue: Queue;
  onReceive: (batch: number) => Promise<QueueMessage[]>;
  onAcknowledge: (ids: string[]) => Promise<AcknowledgeOutcome>;
  onInspect: (message: QueueMessage) => void;
}

/**
 * Receiving is not completing. `POST …/messages/receive` hides a message for
 * the visibility timeout and raises its attempt count; only `…/messages/ack`
 * removes it. The countdown is explicitly an estimate — the response carries
 * no authoritative deadline — so once it lapses this panel says ownership is
 * uncertain rather than implying the lease is still held.
 */
export function ReceiveWorkbench({
  queue,
  onReceive,
  onAcknowledge,
  onInspect,
}: ReceiveWorkbenchProps) {
  const [leases, setLeases] = useState<ReceivedLease[]>([]);
  const [batch, setBatch] = useState(2);
  const [emptyReceive, setEmptyReceive] = useState(false);
  const [receiving, setReceiving] = useState(false);
  const [acknowledging, setAcknowledging] = useState(false);
  const [now, setNow] = useState(() => Date.now());

  useEffect(() => {
    const timer = window.setInterval(() => setNow(Date.now()), 1000);
    return () => window.clearInterval(timer);
  }, []);

  const visibility = formatDuration(queue.visibilityTimeoutSeconds);
  const held = leases.filter((lease) => lease.estimatedDeadline > now);

  const receive = async () => {
    setReceiving(true);
    try {
      const claimedAt = Date.now();
      const received = await onReceive(batch);
      const estimatedDeadline = claimedAt + queue.visibilityTimeoutSeconds * 1000;

      setEmptyReceive(received.length === 0);
      if (received.length > 0) {
        setLeases((current) => [
          ...current,
          ...received.map((message) => ({ message, estimatedDeadline })),
        ]);
      }
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "Failed to receive");
    } finally {
      setReceiving(false);
    }
  };

  const acknowledge = async (target: ReceivedLease[]) => {
    if (target.length === 0) return;

    setAcknowledging(true);
    try {
      const result = await onAcknowledge(target.map((lease) => lease.message.messageId));
      const done = new Set(result.acknowledged);
      setLeases((current) => current.filter((lease) => !done.has(lease.message.messageId)));

      if (result.failed.length === 0) {
        toast.success(
          `${result.acknowledged.length} message${result.acknowledged.length === 1 ? "" : "s"} acknowledged`,
        );
      } else {
        // Partial acknowledge: only confirmed successes leave, and the
        // server's own reason travels with the ones that did not.
        toast.warning(
          `${result.acknowledged.length} acknowledged · ${result.failed.length} not acknowledged`,
          { description: result.failed[0]?.error ?? "The server did not remove them." },
        );
      }
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "Failed to acknowledge");
    } finally {
      setAcknowledging(false);
    }
  };

  const drop = (messageId: string) => {
    setLeases((current) => current.filter((lease) => lease.message.messageId !== messageId));
  };

  return (
    <Panel className="flex flex-col">
      <PanelTitleBar
        title="Receive — in-flight workbench"
        action={
          <div className="flex items-center gap-2">
            <span className="text-xs text-muted-foreground">Batch</span>
            <Select value={String(batch)} onValueChange={(value) => setBatch(Number(value))}>
              <SelectTrigger size="sm" aria-label="Receive batch size" className="font-mono">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {BATCH_SIZES.map((size) => (
                  <SelectItem key={size} value={String(size)} className="font-mono">
                    {size}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
            <Button size="sm" onClick={() => void receive()} loading={receiving}>
              <Download aria-hidden />
              Receive
            </Button>
          </div>
        }
      />

      <PanelBody className="flex flex-1 flex-col gap-2.5">
        <p className="text-[11px] leading-[15px] text-muted-foreground">
          Receiving hides messages for {visibility}; it does not complete them.
          Acknowledge finishes processing.
        </p>

        {leases.length === 0 ? (
          <div className="border border-border bg-background px-3 py-4 text-center text-xs text-muted-foreground">
            {emptyReceive
              ? "No visible messages available."
              : "Nothing received yet. Receive takes the oldest visible messages and holds them."}
          </div>
        ) : null}

        {leases.map((lease) => {
          const remaining = Math.ceil((lease.estimatedDeadline - now) / 1000);
          const preview = previewOf(lease.message.body, 38);

          if (remaining <= 0) {
            return (
              <div key={lease.message.messageId} className="border border-border bg-background">
                <div className="flex items-center justify-between gap-3 px-2.5 py-2">
                  <span className="truncate font-mono text-[11px] text-muted-foreground">
                    {lease.message.messageId}
                  </span>
                  <Status tone="warning" className="shrink-0 text-[11px]">
                    countdown expired — ownership uncertain
                  </Status>
                </div>
                <div className="flex items-center justify-between gap-2 border-t border-border px-2.5 py-2">
                  <span className="text-[11px] text-muted-foreground">
                    May be visible again and redelivered. Refresh before acting.
                  </span>
                  <Button
                    variant="outline"
                    size="sm"
                    className="shrink-0"
                    onClick={() => drop(lease.message.messageId)}
                  >
                    <RefreshCw aria-hidden />
                    Refresh
                  </Button>
                </div>
              </div>
            );
          }

          return (
            <div key={lease.message.messageId} className="border border-send/30 bg-send/5">
              <div className="flex items-center justify-between gap-3 px-2.5 py-2">
                <span className="truncate font-mono text-[11px] text-send-text">
                  {lease.message.messageId}
                </span>
                <span
                  title="Estimated from response time + visibility timeout"
                  className="inline-flex shrink-0 items-center gap-1.5 font-mono text-[11px] text-send-text tabular"
                >
                  <Clock className="size-3" aria-hidden />~{formatDuration(remaining)} est.
                </span>
              </div>
              <div className="flex items-center justify-between gap-2 border-t border-send/30 px-2.5 py-2">
                <span className="min-w-0 truncate font-mono text-[11px] text-strong">
                  {preview}
                  <span className="text-subtle">
                    {" "}
                    {lease.message.lossy ? "· not UTF-8 · " : "· "}
                    {formatBytes(lease.message.bytes.byteLength)}
                  </span>
                </span>
                <div className="flex shrink-0 gap-1.5">
                  <Button
                    variant="outline"
                    size="sm"
                    className="border-send/30 text-send-text"
                    onClick={() => onInspect(lease.message)}
                  >
                    Inspect
                  </Button>
                  <Button
                    size="sm"
                    loading={acknowledging}
                    onClick={() => void acknowledge([lease])}
                  >
                    Acknowledge
                  </Button>
                </div>
              </div>
            </div>
          );
        })}

        <div className="mt-auto flex items-center justify-between gap-3 pt-1">
          <span className="text-xs text-strong">
            {held.length} in flight
            {leases.length > held.length ? ` · ${leases.length - held.length} lapsed` : ""}
          </span>
          <Button
            variant="outline"
            size="sm"
            disabled={leases.length === 0}
            loading={acknowledging}
            onClick={() => void acknowledge(leases)}
          >
            Acknowledge all
          </Button>
        </div>

        <p className="text-[11px] leading-relaxed text-subtle">
          Acknowledging returns succeeded and failed ids separately — only confirmed
          successes leave this panel. The receive response carries no attempt count,
          so none is shown here; Browse reads it from the server.
        </p>
      </PanelBody>
    </Panel>
  );
}
