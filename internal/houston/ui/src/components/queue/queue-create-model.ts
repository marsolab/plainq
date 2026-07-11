import { z } from "zod";
import { EVICTION_POLICY_LABELS } from "@/lib/constants";
import type { CreateQueueInput } from "@/lib/api-client";

export const DEAD_LETTER_POLICY = "EVICTION_POLICY_DEAD_LETTER";
export const CREATE_QUEUE_VALUE = "__create_queue__";

export const createQueueSchema = z
  .object({
    queueName: z
      .string()
      .min(1, "Queue name is required")
      .max(80, "Queue name must be at most 80 characters")
      .regex(
        /^[a-zA-Z0-9_-]+$/,
        "Only letters, numbers, hyphens, and underscores",
      ),
    retentionPeriodSeconds: z.coerce.number().min(60).max(1209600).optional(),
    visibilityTimeoutSeconds: z.coerce.number().min(0).max(43200).optional(),
    maxReceiveAttempts: z.coerce.number().min(1).max(1000).optional(),
    evictionPolicy: z.string().optional(),
    deadLetterQueueId: z.string().optional(),
  })
  .superRefine((data, context) => {
    if (data.evictionPolicy === DEAD_LETTER_POLICY && !data.deadLetterQueueId) {
      context.addIssue({
        code: "custom",
        path: ["deadLetterQueueId"],
        message: "Select or create a dead-letter queue",
      });
    }
  });

export type CreateQueueFormInput = z.input<typeof createQueueSchema>;
export type CreateQueueFormData = z.output<typeof createQueueSchema>;

export interface QueueOption {
  queueId: string;
  queueName: string;
}

export interface QueueListApi {
  queues: {
    list: (params: { limit?: number; cursor?: string }) => Promise<{
      queues?: ReadonlyArray<QueueOption>;
      nextCursor?: string;
      hasMore?: boolean;
    }>;
  };
}

export function getEvictionPolicyOptions(allowDeadLetter: boolean) {
  return Object.entries(EVICTION_POLICY_LABELS)
    .filter(([value]) => allowDeadLetter || value !== DEAD_LETTER_POLICY)
    .map(([value, label]) => ({ value, label }));
}

export function getQueueOptionLabel(
  options: QueueOption[],
  queueId: string | null,
): string {
  if (!queueId) {
    return "Select a queue";
  }

  return (
    options.find((option) => option.queueId === queueId)?.queueName ?? queueId
  );
}

export function toCreateQueueInput(data: CreateQueueFormData): CreateQueueInput {
  const input: CreateQueueInput = {
    queueName: data.queueName,
    retentionPeriodSeconds: data.retentionPeriodSeconds,
    visibilityTimeoutSeconds: data.visibilityTimeoutSeconds,
    maxReceiveAttempts: data.maxReceiveAttempts,
    evictionPolicy: data.evictionPolicy,
  };

  if (data.evictionPolicy === DEAD_LETTER_POLICY) {
    input.deadLetterQueueId = data.deadLetterQueueId;
  }

  return input;
}

export async function loadQueueOptions(api: QueueListApi): Promise<QueueOption[]> {
  const options: QueueOption[] = [];
  const seenCursors = new Set<string>([""]);
  let cursor = "";

  while (true) {
    const page = await api.queues.list({ limit: 100, cursor });
    options.push(
      ...(page.queues ?? []).map(({ queueId, queueName }) => ({
        queueId,
        queueName,
      })),
    );

    if (!page.hasMore || !page.nextCursor || seenCursors.has(page.nextCursor)) {
      return options;
    }

    seenCursors.add(page.nextCursor);
    cursor = page.nextCursor;
  }
}

export function mergeQueueOption(
  options: QueueOption[],
  created: QueueOption,
): QueueOption[] {
  if (options.some((option) => option.queueId === created.queueId)) {
    return options;
  }

  return [...options, created];
}

export function reconcileQueueOptions(
  loaded: QueueOption[],
  current: QueueOption[],
): QueueOption[] {
  return current.reduce(
    (options, option) => mergeQueueOption(options, option),
    loaded,
  );
}
