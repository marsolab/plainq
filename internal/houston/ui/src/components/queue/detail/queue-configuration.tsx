"use client";

import { Panel, PanelTitleBar, DangerZone } from "@/components/ui/panel";
import { Button } from "@/components/ui/button";
import { CopyableId, DefinitionRow, Timestamp } from "@/components/ui/value";
import { EVICTION_POLICY_LABELS } from "@/lib/constants";
import { formatCount, formatDuration, formatSecondsExact } from "@/lib/format";
import type { Queue } from "@/lib/types";

interface QueueConfigurationProps {
  queue: Queue;
  /** Resolved dead-letter queue name; null when it could not be read. */
  deadLetterLabel: string | null;
  onPurge: () => void;
  onDelete: () => void;
}

/**
 * S13. Queue settings are fixed at creation — the transport exposes no update
 * call — so this is a definition list, not a form. Rendering editable inputs
 * behind an inert Save would promise something the server cannot do.
 */
export function QueueConfiguration({
  queue,
  deadLetterLabel,
  onPurge,
  onDelete,
}: QueueConfigurationProps) {
  const policy = EVICTION_POLICY_LABELS[queue.evictionPolicy] ?? queue.evictionPolicy;

  return (
    <div className="flex max-w-[720px] flex-col gap-4">
      <Panel>
        <PanelTitleBar
          title="Configuration"
          action={<span className="text-[11px] text-muted-foreground">Fixed at creation</span>}
        />

        <DefinitionRow label="Name">
          <span className="font-sans font-semibold">{queue.queueName}</span>
        </DefinitionRow>
        <DefinitionRow label="ID" hint="Immutable — clients address the queue by this">
          <CopyableId value={queue.queueId} label="Queue ID" />
        </DefinitionRow>
        <DefinitionRow label="Created">
          <Timestamp value={queue.createdAt} variant="inline" />
        </DefinitionRow>
        <DefinitionRow label="Retention">
          {formatDuration(queue.retentionPeriodSeconds)}{" "}
          <span className="text-subtle">
            · {formatSecondsExact(queue.retentionPeriodSeconds)}
          </span>
        </DefinitionRow>
        <DefinitionRow label="Visibility timeout">
          {formatDuration(queue.visibilityTimeoutSeconds)}
        </DefinitionRow>
        <DefinitionRow label="Max receive attempts">
          {formatCount(queue.maxReceiveAttempts)}
        </DefinitionRow>
        <DefinitionRow label="Eviction policy">
          <span className="font-sans font-medium">
            {policy}
            {queue.deadLetterQueueId ? (
              <>
                {" → "}
                <a
                  href={`/queue/${queue.deadLetterQueueId}`}
                  className="underline underline-offset-2"
                >
                  {deadLetterLabel ?? queue.deadLetterQueueId}
                </a>
              </>
            ) : null}
          </span>
        </DefinitionRow>
      </Panel>

      {/*
       * One fence, two rows. Purge keeps the queue, so it gets a neutral border
       * and a plain title; only Delete is dressed in the destructive palette.
       * The `grow` override lets the fence's action slot hold stacked rows
       * rather than the single trailing button it sizes itself for.
       */}
      <DangerZone className="[&>div:last-child>div]:grow">
        <div className="flex w-full flex-col gap-3">
          <div className="flex items-center gap-4 border border-border p-3">
            <div className="min-w-0">
              <div className="text-xs leading-[17px] font-semibold">Purge queue</div>
              <p className="mt-0.5 text-[11px] leading-[15px] text-muted-foreground">
                Removes all messages. The queue and its configuration remain.
              </p>
            </div>
            <Button
              variant="outline"
              size="sm"
              className="ml-auto"
              onClick={onPurge}
            >
              Purge…
            </Button>
          </div>

          <div className="flex items-center gap-4 border border-destructive-border p-3">
            <div className="min-w-0">
              <div className="text-xs leading-[17px] font-semibold text-destructive-text">
                Delete queue
              </div>
              <p className="mt-0.5 text-[11px] leading-[15px] text-muted-foreground">
                Removes the queue and its messages. Clients using the immutable ID
                will fail.
              </p>
            </div>
            <Button
              variant="destructive-outline"
              size="sm"
              className="ml-auto"
              onClick={onDelete}
            >
              Delete…
            </Button>
          </div>
        </div>
      </DangerZone>
    </div>
  );
}
