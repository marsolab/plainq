"use client";

import * as React from "react";
import { toast } from "sonner";

import {
  Dialog,
  DialogClose,
  DialogContent,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { InlineAlert } from "@/components/ui/feedback";
import { api } from "@/lib/api-client";

interface CreateTopicDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  /** Names already in use, so the conflict is named before the round trip. */
  existingNames: string[];
  onCreated: (topicId: string) => void;
}

export function CreateTopicDialog({
  open,
  onOpenChange,
  existingNames,
  onCreated,
}: CreateTopicDialogProps) {
  const [name, setName] = React.useState("");
  const [submitting, setSubmitting] = React.useState(false);
  const [error, setError] = React.useState<string | null>(null);

  React.useEffect(() => {
    if (!open) {
      setName("");
      setError(null);
      setSubmitting(false);
    }
  }, [open]);

  const trimmed = name.trim();
  const conflict = existingNames.some(
    (existing) => existing.toLowerCase() === trimmed.toLowerCase(),
  );
  const canSubmit = trimmed.length > 0 && !conflict && !submitting;

  const submit = async (event: React.FormEvent) => {
    event.preventDefault();
    if (!canSubmit) return;

    setSubmitting(true);
    setError(null);
    try {
      const { topicId } = await api.topics.create({ topicName: trimmed });
      toast.success(`Topic ${trimmed} created`);
      onCreated(topicId);
      onOpenChange(false);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not create the topic");
      setSubmitting(false);
    }
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent aria-describedby={undefined}>
        <DialogHeader>
          <DialogTitle className="text-sm">Create topic</DialogTitle>
        </DialogHeader>

        <form onSubmit={submit} className="flex flex-col gap-3">
          <div className="flex flex-col gap-1.5">
            <Label htmlFor="topic-name">Topic name</Label>
            <Input
              id="topic-name"
              value={name}
              autoFocus
              autoComplete="off"
              spellCheck={false}
              placeholder="order-events"
              aria-invalid={conflict || undefined}
              aria-describedby={conflict ? "topic-name-conflict" : undefined}
              onChange={(event) => setName(event.target.value)}
            />
            {conflict ? (
              <span id="topic-name-conflict" className="text-[11px] text-destructive-text">
                A topic named "{trimmed}" already exists.
              </span>
            ) : null}
          </div>

          {error ? <InlineAlert>{error}</InlineAlert> : null}

          <DialogFooter>
            <DialogClose asChild>
              <Button type="button" variant="outline" size="sm">
                Cancel
              </Button>
            </DialogClose>
            <Button type="submit" size="sm" disabled={!canSubmit} loading={submitting}>
              Create topic
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}
