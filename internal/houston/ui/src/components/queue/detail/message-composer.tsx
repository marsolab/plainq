"use client";

import { useState } from "react";
import { Copy, Plus, Send, X } from "lucide-react";
import { toast } from "sonner";

import { Panel, PanelBody, PanelTitleBar } from "@/components/ui/panel";
import { Button } from "@/components/ui/button";
import { Textarea } from "@/components/ui/input";
import { CopyableId } from "@/components/ui/value";
import { formatBytes } from "@/lib/format";
import { cn } from "@/lib/utils";

import { Segmented } from "./segmented";
import { checkJson, decodeUtf8, encodeUtf8, fromBase64 } from "./payload";

type ComposerMode = "text" | "json" | "base64";

interface ComposerRow {
  key: number;
  text: string;
}

interface RowCheck {
  /** The body to hand the send endpoint, or null when the row cannot go. */
  body: string | null;
  note: string;
  error: boolean;
}

/**
 * What a row will actually put on the wire.
 *
 * `POST …/messages` carries each body base64-encoded, and the API client does
 * that encoding from a string — so a Base64 row is decoded here and must come
 * back as valid UTF-8 to survive the trip. JSON mode validates syntax and
 * nothing more: the server never interprets the bytes, which is why the note
 * says "sent as opaque bytes" on every valid row.
 */
function checkRow(text: string, mode: ComposerMode): RowCheck {
  if (text.trim().length === 0) {
    return { body: null, note: "empty — nothing to send", error: false };
  }

  if (mode === "base64") {
    const bytes = fromBase64(text);
    if (!bytes) return { body: null, note: "invalid Base64 — cannot decode", error: true };

    const decoded = decodeUtf8(bytes);
    if (decoded === null) {
      return {
        body: null,
        note: "decodes to bytes that are not valid UTF-8 — this transport carries text bodies",
        error: true,
      };
    }

    return {
      body: decoded,
      note: `${formatBytes(bytes.byteLength)} decoded · sent as opaque bytes`,
      error: false,
    };
  }

  const bytes = encodeUtf8(text);
  if (mode === "json") {
    const json = checkJson(text);
    if (!json.valid) {
      return { body: null, note: `invalid JSON — ${json.message}`, error: true };
    }
    return {
      body: text,
      note: `${formatBytes(bytes.byteLength)} · valid JSON · sent as opaque bytes`,
      error: false,
    };
  }

  return {
    body: text,
    note: `${formatBytes(bytes.byteLength)} · sent as opaque bytes`,
    error: false,
  };
}

interface MessageComposerProps {
  /** Resolves with the ids the server generated, in send order. */
  onSend: (bodies: string[]) => Promise<string[]>;
}

export function MessageComposer({ onSend }: MessageComposerProps) {
  const [mode, setMode] = useState<ComposerMode>("json");
  const [rows, setRows] = useState<ComposerRow[]>([{ key: 0, text: "" }]);
  const [nextKey, setNextKey] = useState(1);
  const [sent, setSent] = useState<string[]>([]);
  const [sending, setSending] = useState(false);

  const checks = rows.map((row) => checkRow(row.text, mode));
  const ready = checks.filter((check) => check.body !== null);
  const blocked = checks.some((check) => check.error);

  const addRow = () => {
    setRows((current) => [...current, { key: nextKey, text: "" }]);
    setNextKey((key) => key + 1);
  };

  const duplicateRow = (index: number) => {
    setRows((current) => [
      ...current.slice(0, index + 1),
      { key: nextKey, text: current[index]!.text },
      ...current.slice(index + 1),
    ]);
    setNextKey((key) => key + 1);
  };

  const removeRow = (index: number) => {
    setRows((current) =>
      current.length === 1 ? [{ key: nextKey, text: "" }] : current.filter((_, i) => i !== index),
    );
    if (rows.length === 1) setNextKey((key) => key + 1);
  };

  const updateRow = (index: number, text: string) => {
    setRows((current) => current.map((row, i) => (i === index ? { ...row, text } : row)));
  };

  const send = async () => {
    const bodies = ready.map((check) => check.body!);
    if (bodies.length === 0) return;

    setSending(true);
    try {
      const ids = await onSend(bodies);
      setSent(ids);
      // Only a confirmed send clears the composer — a failure keeps every
      // body exactly where it was so the operator can retry it.
      setRows([{ key: nextKey, text: "" }]);
      setNextKey((key) => key + 1);
      toast.success(`${ids.length} message${ids.length === 1 ? "" : "s"} sent`);
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "Failed to send");
    } finally {
      setSending(false);
    }
  };

  return (
    <Panel className="flex flex-col">
      <PanelTitleBar
        title="Send"
        action={
          <Segmented
            label="Body encoding"
            value={mode}
            options={[
              { value: "text", label: "Text" },
              { value: "json", label: "JSON" },
              { value: "base64", label: "Base64" },
            ]}
            onValueChange={setMode}
          />
        }
      />

      <PanelBody className="flex flex-1 flex-col gap-2.5">
        {rows.map((row, index) => {
          const check = checks[index]!;
          return (
            <div
              key={row.key}
              className={cn("border", check.error ? "border-destructive" : "border-border")}
            >
              <Textarea
                value={row.text}
                onChange={(event) => updateRow(index, event.target.value)}
                rows={2}
                spellCheck={false}
                aria-label={`Message body ${index + 1}`}
                placeholder={
                  mode === "base64" ? "SGVsbG8sIHF1ZXVlLg==" : '{"orderId":"ord_10301"}'
                }
                className="resize-y border-0 px-2.5 py-2 font-mono text-xs leading-relaxed"
              />
              <div
                className={cn(
                  "flex items-center justify-between gap-3 border-t px-2.5 py-1",
                  check.error
                    ? "border-destructive bg-destructive-surface"
                    : "border-border bg-background",
                )}
              >
                <span
                  className={cn(
                    "truncate font-mono text-[10px]",
                    check.error ? "text-destructive-text" : "text-muted-foreground",
                  )}
                >
                  {check.note}
                </span>
                <span className="flex shrink-0 items-center gap-0.5">
                  <Button
                    variant="ghost"
                    size="icon-sm"
                    className="size-6"
                    aria-label={`Duplicate message ${index + 1}`}
                    onClick={() => duplicateRow(index)}
                  >
                    <Copy className="size-3" aria-hidden />
                  </Button>
                  <Button
                    variant="ghost"
                    size="icon-sm"
                    className="size-6"
                    aria-label={`Remove message ${index + 1}`}
                    onClick={() => removeRow(index)}
                  >
                    <X className="size-3" aria-hidden />
                  </Button>
                </span>
              </div>
            </div>
          );
        })}

        {sent.length > 0 ? (
          <div className="border border-border">
            <div className="border-b border-border bg-background px-2.5 py-1">
              <span className="caption">
                Sent · {sent.length} message{sent.length === 1 ? "" : "s"}
              </span>
            </div>
            <div className="flex flex-wrap gap-1.5 p-2.5">
              {sent.map((id) => (
                <CopyableId key={id} value={id} label="Message ID" />
              ))}
            </div>
          </div>
        ) : null}

        <div className="mt-auto flex items-center justify-between gap-3 pt-1">
          <Button variant="ghost" size="sm" onClick={addRow}>
            <Plus aria-hidden />
            Add message
          </Button>
          <Button
            onClick={() => void send()}
            loading={sending}
            disabled={blocked || ready.length === 0}
          >
            <Send aria-hidden />
            Send {ready.length} message{ready.length === 1 ? "" : "s"}
          </Button>
        </div>

        <p className="text-[11px] leading-relaxed text-subtle">
          JSON mode validates syntax only — the server never interprets bytes. A failed
          send keeps every body for retry; a successful one lists the ids the server
          generated.
        </p>
      </PanelBody>
    </Panel>
  );
}
