import { describe, expect, test } from "bun:test";
import {
  CREATE_QUEUE_VALUE,
  DEAD_LETTER_POLICY,
  createQueueSchema,
  getEvictionPolicyOptions,
  getQueueOptionLabel,
  loadQueueOptions,
  mergeQueueOption,
  reconcileQueueOptions,
  toCreateQueueInput,
} from "./queue-create-model";
import type { QueueListApi } from "./queue-create-model";

const validForm = {
  queueName: "orders_queue",
  retentionPeriodSeconds: "345600",
  visibilityTimeoutSeconds: "30",
  maxReceiveAttempts: "10",
  evictionPolicy: "EVICTION_POLICY_DROP",
};

describe("createQueueSchema", () => {
  test("preserves queue name validation messages", () => {
    const required = createQueueSchema.safeParse({ ...validForm, queueName: "" });
    const tooLong = createQueueSchema.safeParse({
      ...validForm,
      queueName: "a".repeat(81),
    });
    const invalidCharacters = createQueueSchema.safeParse({
      ...validForm,
      queueName: "orders queue",
    });

    expect(required.success ? undefined : required.error.issues[0]?.message).toBe(
      "Queue name is required",
    );
    expect(tooLong.success ? undefined : tooLong.error.issues[0]?.message).toBe(
      "Queue name must be at most 80 characters",
    );
    expect(
      invalidCharacters.success
        ? undefined
        : invalidCharacters.error.issues[0]?.message,
    ).toBe("Only letters, numbers, hyphens, and underscores");
  });

  test("preserves numeric bounds independently", () => {
    const bounds = [
      { field: "retentionPeriodSeconds", min: "60", max: "1209600", below: "59", above: "1209601" },
      { field: "visibilityTimeoutSeconds", min: "0", max: "43200", below: "-1", above: "43201" },
      { field: "maxReceiveAttempts", min: "1", max: "1000", below: "0", above: "1001" },
    ] as const;

    for (const { field, min, max, below, above } of bounds) {
      expect(
        createQueueSchema.safeParse({ ...validForm, [field]: min }).success,
      ).toBe(true);
      expect(
        createQueueSchema.safeParse({ ...validForm, [field]: max }).success,
      ).toBe(true);
      expect(
        createQueueSchema.safeParse({ ...validForm, [field]: below }).success,
      ).toBe(false);
      expect(
        createQueueSchema.safeParse({ ...validForm, [field]: above }).success,
      ).toBe(false);
    }
  });

  test("requires a dead-letter queue only for the dead-letter policy", () => {
    const deadLetterResult = createQueueSchema.safeParse({
      ...validForm,
      evictionPolicy: DEAD_LETTER_POLICY,
    });
    const dropResult = createQueueSchema.safeParse(validForm);

    expect(deadLetterResult.success).toBe(false);
    expect(
      deadLetterResult.success
        ? undefined
        : deadLetterResult.error.issues.find(
            (issue) => issue.path[0] === "deadLetterQueueId",
          ),
    ).toMatchObject({
      path: ["deadLetterQueueId"],
      message: "Select or create a dead-letter queue",
    });
    expect(dropResult.success).toBe(true);
  });

  test("preserves a dead-letter queue target for a dead-letter request", () => {
    const result = createQueueSchema.safeParse({
      ...validForm,
      evictionPolicy: DEAD_LETTER_POLICY,
      deadLetterQueueId: "queue-dlq",
    });

    expect(result.success).toBe(true);
    expect(result.success ? result.data.deadLetterQueueId : undefined).toBe(
      "queue-dlq",
    );
  });
});

describe("queue creation helpers", () => {
  test("uses the queue name as the selected dead-letter label", () => {
    const options = [{ queueId: "queue-dlq", queueName: "orders-dlq" }];

    expect(getQueueOptionLabel(options, "queue-dlq")).toBe("orders-dlq");
    expect(getQueueOptionLabel(options, "missing-queue")).toBe("missing-queue");
    expect(getQueueOptionLabel(options, null)).toBe("Select a queue");
  });

  test("preserves the dead-letter target in a dead-letter request", () => {
    expect(
      toCreateQueueInput({
        ...validForm,
        retentionPeriodSeconds: 345600,
        visibilityTimeoutSeconds: 30,
        maxReceiveAttempts: 10,
        evictionPolicy: DEAD_LETTER_POLICY,
        deadLetterQueueId: "queue-dlq",
      }),
    ).toEqual({
      queueName: "orders_queue",
      retentionPeriodSeconds: 345600,
      visibilityTimeoutSeconds: 30,
      maxReceiveAttempts: 10,
      evictionPolicy: DEAD_LETTER_POLICY,
      deadLetterQueueId: "queue-dlq",
    });
  });

  test("omits a stale dead-letter target from a non-dead-letter request", () => {
    expect(
      toCreateQueueInput({
        ...validForm,
        retentionPeriodSeconds: 345600,
        visibilityTimeoutSeconds: 30,
        maxReceiveAttempts: 10,
        deadLetterQueueId: "stale-dlq",
      }),
    ).toEqual({
      queueName: "orders_queue",
      retentionPeriodSeconds: 345600,
      visibilityTimeoutSeconds: 30,
      maxReceiveAttempts: 10,
      evictionPolicy: "EVICTION_POLICY_DROP",
    });
  });

  test("excludes dead-letter policy from child queue options", () => {
    expect(getEvictionPolicyOptions(false)).not.toContainEqual({
      value: DEAD_LETTER_POLICY,
      label: "Dead Letter",
    });
  });

  test("includes dead-letter policy when allowed", () => {
    expect(getEvictionPolicyOptions(true)).toContainEqual({
      value: DEAD_LETTER_POLICY,
      label: "Dead Letter",
    });
  });

  test("combines multiple queue pages", async () => {
    const calls: Array<{ limit?: number; cursor?: string }> = [];
    const api = {
      queues: {
        list: async (params: { limit?: number; cursor?: string }) => {
          calls.push(params);
          return params.cursor
            ? {
                queues: [{ queueId: "q-2", queueName: "second" }],
                nextCursor: "",
                hasMore: false,
              }
            : {
                queues: [
                  {
                    queueId: "q-1",
                    queueName: "first",
                    createdAt: "2026-01-01T00:00:00Z",
                    maxReceiveAttempts: 10,
                    retentionPeriodSeconds: 345600,
                    visibilityTimeoutSeconds: 30,
                    evictionPolicy: "EVICTION_POLICY_DROP",
                  },
                ],
                nextCursor: "next",
                hasMore: true,
              };
        },
      },
    };

    const options = await loadQueueOptions(api);

    expect(options).toEqual([
      { queueId: "q-1", queueName: "first" },
      { queueId: "q-2", queueName: "second" },
    ]);
    expect(calls).toEqual([
      { limit: 100, cursor: "" },
      { limit: 100, cursor: "next" },
    ]);
  });

  test("handles an empty protojson response", async () => {
    const api: QueueListApi = {
      queues: {
        list: async () => ({}),
      },
    };

    const options = await loadQueueOptions(api);

    expect(options).toEqual([]);
  });

  test("stops when the cursor repeats", async () => {
    const calls: Array<{ limit?: number; cursor?: string }> = [];
    const api = {
      queues: {
        list: async (params: { limit?: number; cursor?: string }) => {
          calls.push(params);
          return {
            queues: [{ queueId: `q-${calls.length}`, queueName: "queue" }],
            nextCursor: "same",
            hasMore: true,
          };
        },
      },
    };

    const options = await loadQueueOptions(api);

    expect(options).toHaveLength(2);
    expect(calls).toEqual([
      { limit: 100, cursor: "" },
      { limit: 100, cursor: "same" },
    ]);
  });

  test("stops when hasMore is false despite a next cursor", async () => {
    const calls: Array<{ limit?: number; cursor?: string }> = [];
    const api = {
      queues: {
        list: async (params: { limit?: number; cursor?: string }) => {
          calls.push(params);
          return {
            queues: [{ queueId: "q-1", queueName: "first" }],
            nextCursor: "ignored",
            hasMore: false,
          };
        },
      },
    };

    const options = await loadQueueOptions(api);

    expect(options).toEqual([
      { queueId: "q-1", queueName: "first" },
    ]);
    expect(calls).toEqual([{ limit: 100, cursor: "" }]);
  });

  test("stops when next cursor is empty despite hasMore", async () => {
    const calls: Array<{ limit?: number; cursor?: string }> = [];
    const api = {
      queues: {
        list: async (params: { limit?: number; cursor?: string }) => {
          calls.push(params);
          return {
            queues: [{ queueId: "q-1", queueName: "first" }],
            nextCursor: "",
            hasMore: true,
          };
        },
      },
    };

    const options = await loadQueueOptions(api);

    expect(options).toEqual([
      { queueId: "q-1", queueName: "first" },
    ]);
    expect(calls).toEqual([{ limit: 100, cursor: "" }]);
  });

  test("appends a newly created queue once and preserves order", () => {
    const options = [{ queueId: "q-1", queueName: "first" }];
    const created = { queueId: "q-2", queueName: "second" };
    const duplicate = { queueId: "q-1", queueName: "renamed" };

    expect(mergeQueueOption(options, created)).toEqual([options[0], created]);
    expect(mergeQueueOption(options, duplicate)).toEqual(options);
    expect(mergeQueueOption([...options, created], duplicate)).toEqual([
      options[0],
      created,
    ]);
  });

  test("reconciles loaded options without dropping a child-created queue", () => {
    const loaded = [
      { queueId: "q-1", queueName: "first" },
      { queueId: "q-2", queueName: "loaded-second" },
    ];
    const current = [
      { queueId: "q-2", queueName: "child-second" },
      { queueId: "q-3", queueName: "child-third" },
    ];

    expect(reconcileQueueOptions(loaded, current)).toEqual([
      { queueId: "q-1", queueName: "first" },
      { queueId: "q-2", queueName: "loaded-second" },
      { queueId: "q-3", queueName: "child-third" },
    ]);
  });

  test("exposes the create queue sentinel", () => {
    expect(CREATE_QUEUE_VALUE).toBe("__create_queue__");
  });
});
