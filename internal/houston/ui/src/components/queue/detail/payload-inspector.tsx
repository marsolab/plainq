"use client";

import { useEffect, useMemo, useState } from "react";
import { toast } from "sonner";

import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { InlineAlert } from "@/components/ui/feedback";
import { Status } from "@/components/ui/status";
import { formatBytes, formatDateFull, groupDigits } from "@/lib/format";
import type { Queue } from "@/lib/types";

import type { QueueMessage } from "./message";
import { Segmented, type SegmentedOption } from "./segmented";
import { prettyJson, toBase64, toHex } from "./payload";

type Encoding = "text" | "json" | "base64" | "hex";

/** Long payloads are cut here; the true byte count is always stated alongside. */
const MAX_RENDERED_CHARS = 720;

interface PayloadInspectorProps {
  message: QueueMessage | null;
  queue: Queue;
  open: boolean;
  onOpenChange: (open: boolean) => void;
}

/**
 * Shows a payload as what it is: bytes, plus whichever decodings those bytes
 * actually support.
 *
 * The transport hands Houston the payload base64-decoded and read as UTF-8
 * text, so Base64 and Hex here are recomputed from *that* text rather than
 * from the stored bytes. For a UTF-8 body the two are identical, and the size
 * is exact; when the decode had to substitute characters the panel says so
 * instead of quoting a byte count that was never stored. Sizes use binary
 * units throughout — KiB, never KB for 1024.
 */
export function PayloadInspector({
  message,
  queue,
  open,
  onOpenChange,
}: PayloadInspectorProps) {
  const decoded = useMemo(() => {
    if (!message) return null;
    return {
      text: message.body,
      json: prettyJson(message.body),
      base64: toBase64(message.bytes),
      hex: toHex(message.bytes),
    };
  }, [message]);

  const [encoding, setEncoding] = useState<Encoding>("text");

  // A new message re-decides the default view; nothing is ever auto-labelled JSON.
  useEffect(() => {
    if (!decoded) return;
    setEncoding("text");
  }, [decoded]);

  if (!message || !decoded) return null;

  const bytes = message.bytes.byteLength;
  const options: SegmentedOption<Encoding>[] = [
    { value: "text", label: "Text" },
    {
      value: "json",
      label: "JSON",
      disabled: decoded.json === null ? "Not parseable JSON" : undefined,
    },
    { value: "base64", label: "Base64" },
    { value: "hex", label: "Hex" },
  ];

  const rendered =
    encoding === "text"
      ? decoded.text
      : encoding === "json"
        ? (decoded.json ?? "")
        : encoding === "base64"
          ? decoded.base64
          : decoded.hex;

  const truncated = rendered.length > MAX_RENDERED_CHARS;
  const size = message.lossy ? `~${formatBytes(bytes)}` : formatBytes(bytes);

  const copy = async (value: string, label: string) => {
    try {
      await navigator.clipboard.writeText(value);
      toast.success(`${label} copied`);
    } catch {
      toast.error(`Could not copy ${label.toLowerCase()}`);
    }
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="gap-0 p-0 sm:max-w-[480px]">
        <DialogHeader className="border-b border-border p-4 pr-10">
          <DialogTitle className="text-[15px]">Message payload</DialogTitle>
          <DialogDescription className="font-mono text-[11px]">
            {message.messageId} · {size}
            {message.lossy ? "" : ` · ${groupDigits(bytes)} B`}
          </DialogDescription>
        </DialogHeader>

        <div className="flex flex-col gap-2.5 p-4">
          <div className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-1 text-xs">
            <span className="text-muted-foreground">Created</span>
            <span className="font-mono text-[11px] tabular">
              {message.createdAt ? (
                formatDateFull(message.createdAt)
              ) : (
                <span className="text-subtle">not carried by this response</span>
              )}
            </span>
            <span className="text-muted-foreground">Status</span>
            <Status tone={message.inFlight ? "in-flight" : "visible"}>
              {message.inFlight ? "In-flight" : "Visible"}
              {message.receiveAttempts !== null
                ? ` · attempt ${message.receiveAttempts} of ${queue.maxReceiveAttempts}`
                : ""}
            </Status>
          </div>

          <Segmented
            label="Payload encoding"
            value={encoding}
            options={options}
            onValueChange={setEncoding}
            className="py-0.5"
          />

          {message.lossy ? (
            <InlineAlert tone="warning">
              The payload was not valid UTF-8, and the transport substituted the bytes
              it could not represent. What is shown here is that substitution, not the
              stored payload, and the size is approximate.
            </InlineAlert>
          ) : null}

          <pre className="max-h-64 overflow-auto border border-border bg-background p-2.5 font-mono text-[11px] leading-relaxed break-all whitespace-pre-wrap text-strong">
            {truncated ? rendered.slice(0, MAX_RENDERED_CHARS) : rendered}
            {truncated ? <span className="text-subtle"> (truncated · {size})</span> : null}
          </pre>

          <p className="text-[10px] leading-relaxed text-subtle">
            The server stores and returns opaque bytes and never interprets them. Base64
            and Hex are computed from the UTF-8 encoding of the body above.
          </p>

          <div className="flex gap-2">
            <Button variant="outline" size="sm" onClick={() => void copy(decoded.base64, "Base64")}>
              Copy Base64
            </Button>
            <Button
              variant="outline"
              size="sm"
              onClick={() => void copy(message.messageId, "Message ID")}
            >
              Copy message ID
            </Button>
          </div>
        </div>
      </DialogContent>
    </Dialog>
  );
}
