import { describe, expect, test } from "bun:test";
import { DEAD_LETTER_POLICY } from "../queue-create-model";
import {
  QUEUE_FORM_DEFAULTS,
  queueFormSchema,
  toCreateQueueRequest,
  toSeconds,
} from "./queue-form";

/**
 * The dialogs type a value and a unit; `queue-create-model` is still the thing
 * that decides what is valid and what gets sent. These cover that seam.
 */

const validForm = {
  ...QUEUE_FORM_DEFAULTS,
  queueName: "orders_queue",
};

function issueFor(values: unknown, path: string) {
  const result = queueFormSchema.safeParse(values);
  if (result.success) return undefined;
  return result.error.issues.find((issue) => issue.path[0] === path);
}

describe("toSeconds", () => {
  test("resolves each unit and truncates fractions", () => {
    expect(toSeconds(30, "seconds")).toBe(30);
    expect(toSeconds(2, "minutes")).toBe(120);
    expect(toSeconds(12, "hours")).toBe(43200);
    expect(toSeconds(14, "days")).toBe(1209600);
    expect(toSeconds(1.9, "minutes")).toBe(60);
    expect(Number.isNaN(toSeconds(Number.NaN, "seconds"))).toBe(true);
  });
});

describe("queueFormSchema", () => {
  test("accepts the defaults", () => {
    expect(queueFormSchema.safeParse(validForm).success).toBe(true);
  });

  test("reports the model's duration bounds on the control that owns them", () => {
    expect(
      issueFor({ ...validForm, retentionValue: 30, retentionUnit: "seconds" }, "retentionValue"),
    ).toMatchObject({ message: "Between 60 s and 14 d" });
    expect(
      issueFor({ ...validForm, retentionValue: 15, retentionUnit: "days" }, "retentionValue"),
    ).toMatchObject({ message: "Between 60 s and 14 d" });
    expect(
      issueFor({ ...validForm, visibilityValue: 13, visibilityUnit: "hours" }, "visibilityValue"),
    ).toMatchObject({ message: "Between 0 s and 12 h" });
    expect(
      issueFor({ ...validForm, maxReceiveAttempts: 1001 }, "maxReceiveAttempts"),
    ).toMatchObject({ message: "Between 1 and 1000" });
  });

  test("keeps the model's own wording for the queue name", () => {
    expect(issueFor({ ...validForm, queueName: "" }, "queueName")).toMatchObject({
      message: "Queue name is required",
    });
    expect(issueFor({ ...validForm, queueName: "orders queue" }, "queueName")).toMatchObject({
      message: "Only letters, numbers, hyphens, and underscores",
    });
  });

  test("requires a dead-letter target only for the dead-letter policy", () => {
    expect(
      issueFor({ ...validForm, evictionPolicy: DEAD_LETTER_POLICY }, "deadLetterQueueId"),
    ).toMatchObject({ message: "Select or create a dead-letter queue" });
    expect(
      queueFormSchema.safeParse({
        ...validForm,
        evictionPolicy: DEAD_LETTER_POLICY,
        deadLetterQueueId: "queue-dlq",
      }).success,
    ).toBe(true);
  });
});

describe("toCreateQueueRequest", () => {
  test("sends resolved seconds and keeps a dead-letter target", () => {
    const parsed = queueFormSchema.parse({
      ...validForm,
      retentionValue: 4,
      retentionUnit: "days",
      evictionPolicy: DEAD_LETTER_POLICY,
      deadLetterQueueId: "queue-dlq",
    });

    expect(toCreateQueueRequest(parsed)).toEqual({
      queueName: "orders_queue",
      retentionPeriodSeconds: 345600,
      visibilityTimeoutSeconds: 30,
      maxReceiveAttempts: 5,
      evictionPolicy: DEAD_LETTER_POLICY,
      deadLetterQueueId: "queue-dlq",
    });
  });

  test("omits a dead-letter target the operator abandoned", () => {
    const parsed = queueFormSchema.parse({
      ...validForm,
      deadLetterQueueId: "stale-dlq",
    });

    expect(toCreateQueueRequest(parsed)).toEqual({
      queueName: "orders_queue",
      retentionPeriodSeconds: 604800,
      visibilityTimeoutSeconds: 30,
      maxReceiveAttempts: 5,
      evictionPolicy: "EVICTION_POLICY_DROP",
    });
  });
});
