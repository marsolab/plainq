import { z } from "zod";

import type { CreateQueueInput } from "@/lib/api-client";
import {
  createQueueSchema,
  getEvictionPolicyOptions,
  toCreateQueueInput,
  type CreateQueueFormInput,
} from "../queue-create-model";
import { DROP } from "./eviction";

/**
 * The form layer shared by both queue-creation dialogs.
 *
 * It owns presentation only — a value plus a unit instead of raw seconds — and
 * defers every rule to `queue-create-model`, which stays the single source of
 * truth for what the server accepts and for the request that is finally sent.
 */

export const DURATION_UNITS = ["seconds", "minutes", "hours", "days"] as const;
export type DurationUnit = (typeof DURATION_UNITS)[number];

const UNIT_SECONDS: Record<DurationUnit, number> = {
  seconds: 1,
  minutes: 60,
  hours: 3600,
  days: 86400,
};

export function toSeconds(value: number, unit: DurationUnit): number {
  if (!Number.isFinite(value)) return Number.NaN;
  return Math.trunc(value) * UNIT_SECONDS[unit];
}

const formShape = {
  queueName: z.string().trim(),
  retentionValue: z.coerce.number().int("Whole numbers only"),
  retentionUnit: z.enum(DURATION_UNITS),
  visibilityValue: z.coerce.number().int("Whole numbers only"),
  visibilityUnit: z.enum(DURATION_UNITS),
  maxReceiveAttempts: z.coerce.number().int("Whole numbers only"),
  evictionPolicy: z.string(),
  deadLetterQueueId: z.string().optional(),
};

/** Model field → the control the operator would have to go back and fix. */
const FORM_PATH: Record<string, string> = {
  retentionPeriodSeconds: "retentionValue",
  visibilityTimeoutSeconds: "visibilityValue",
};

/**
 * The model states its bounds in seconds; the operator typed a value and a
 * unit. These say the same thing in the operator's terms. Anything not listed
 * here — the queue-name rules, the dead-letter requirement — keeps the model's
 * own wording.
 */
const BOUND_MESSAGE: Record<string, string> = {
  retentionPeriodSeconds: "Between 60 s and 14 d",
  visibilityTimeoutSeconds: "Between 0 s and 12 h",
  maxReceiveAttempts: "Between 1 and 1000",
};

export const queueFormSchema = z
  .object(formShape)
  .superRefine((values, ctx) => {
    const result = createQueueSchema.safeParse(toModelInput(values));
    if (result.success) return;

    for (const issue of result.error.issues) {
      const field = String(issue.path[0] ?? "");
      ctx.addIssue({
        code: "custom",
        path: [FORM_PATH[field] ?? field],
        message: BOUND_MESSAGE[field] ?? issue.message,
      });
    }
  });

export type QueueFormValues = z.input<typeof queueFormSchema>;
export type QueueFormData = z.output<typeof queueFormSchema>;

/** Resolved defaults: 7-day retention, 30-second visibility, 5 attempts. */
export const QUEUE_FORM_DEFAULTS: QueueFormValues = {
  queueName: "",
  retentionValue: 7,
  retentionUnit: "days",
  visibilityValue: 30,
  visibilityUnit: "seconds",
  maxReceiveAttempts: 5,
  evictionPolicy: DROP,
  deadLetterQueueId: "",
};

function toModelInput(values: QueueFormData): CreateQueueFormInput {
  return {
    queueName: values.queueName,
    retentionPeriodSeconds: toSeconds(values.retentionValue, values.retentionUnit),
    visibilityTimeoutSeconds: toSeconds(values.visibilityValue, values.visibilityUnit),
    maxReceiveAttempts: values.maxReceiveAttempts,
    evictionPolicy: values.evictionPolicy,
    deadLetterQueueId: values.deadLetterQueueId,
  };
}

/**
 * The request the server will receive. Built by the model so a dead-letter
 * target selected and then abandoned never rides along on a Drop queue.
 */
export function toCreateQueueRequest(values: QueueFormData): CreateQueueInput {
  return toCreateQueueInput(createQueueSchema.parse(toModelInput(values)));
}

export type QueueCreateDialogMode = "default" | "dead-letter";

/**
 * What separates the two dialogs. `allowDeadLetter` is the load-bearing part:
 * a dead-letter target must not dead-letter onward, so the child dialog is
 * never offered the policy at all.
 */
export function getQueueCreateDialogConfig(mode: QueueCreateDialogMode) {
  const allowDeadLetter = mode === "default";

  return {
    title: mode === "default" ? "Create queue" : "Create dead-letter queue",
    description:
      mode === "default"
        ? "Configuration is immutable after creation."
        : "Configure the queue that will receive evicted messages.",
    allowDeadLetter,
    policyOptions: getEvictionPolicyOptions(allowDeadLetter),
  };
}
