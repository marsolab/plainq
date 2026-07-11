# Dead-Letter Queue Selection Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a required existing-or-new dead-letter queue selector to Houston queue creation and fix SQLite queue listing for queues whose dead-letter queue ID is NULL.

**Architecture:** Keep the existing queue API and make nested creation two ordinary queue-create requests. Put schema, pagination, policy filtering, and option-merging logic in a small frontend model module so the React dialog only coordinates UI state; fix the backend at the nullable SQL scan boundary.

**Tech Stack:** Go 1.26, SQLite/litekit, protobuf, Bun, Astro 6, React 19, react-hook-form, Zod 4, Base UI, Tailwind CSS 4.

---

## File Map

- Modify `internal/server/service/queue/litestore/storage.go`: scan nullable `dead_letter_queue_id` safely.
- Modify `internal/server/service/queue/litestore/storage_test.go`: cover NULL and non-NULL IDs.
- Create `internal/houston/ui/src/components/queue/queue-create-model.ts`: own schema, normalization, pagination, policy filtering, and option merging.
- Create `internal/houston/ui/src/components/queue/queue-create-model.test.ts`: unit-test the model.
- Modify `internal/houston/ui/src/components/queue/queue-create-dialog.tsx`: render both existing selection and nested creation.
- Modify `internal/houston/ui/src/components/queue/queue-list.tsx`: retain list refresh behavior with the richer callback.

### Task 1: Fix Nullable SQLite Queue Listing

**Files:**
- Modify: `internal/server/service/queue/litestore/storage_test.go`
- Modify: `internal/server/service/queue/litestore/storage.go:771-792`

- [ ] **Step 1: Write the failing storage regression test**

Replace the empty `storage_test.go` with a storage-level test that uses the production-shaped schema helper from `pubsub_test.go`:

```go
package litestore

import (
	"context"
	"path/filepath"
	"testing"

	v1 "github.com/marsolab/plainq/internal/server/schema/v1"
	"github.com/marsolab/servekit/dbkit/litekit"
)

func TestStorageListQueuesHandlesNullableDeadLetterQueue(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	conn, err := litekit.New(filepath.Join(t.TempDir(), "plainq.db"))
	if err != nil {
		t.Fatalf("open litekit connection: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	setupPubSubTables(t, ctx, conn)

	storage, err := New(conn)
	if err != nil {
		t.Fatalf("create storage: %v", err)
	}
	t.Cleanup(func() { _ = storage.Close() })

	created, err := storage.CreateQueue(ctx, &v1.CreateQueueRequest{
		QueueName: "orders",
		EvictionPolicy: v1.EvictionPolicy_EVICTION_POLICY_DROP,
	})
	if err != nil {
		t.Fatalf("create queue: %v", err)
	}

	listed, err := storage.ListQueues(ctx, &v1.ListQueuesRequest{Limit: 10})
	if err != nil {
		t.Fatalf("list queues: %v", err)
	}
	if len(listed.Queues) != 1 {
		t.Fatalf("listed queues = %d, want 1", len(listed.Queues))
	}
	if listed.Queues[0].QueueId != created.QueueId {
		t.Fatalf("queue id = %q, want %q", listed.Queues[0].QueueId, created.QueueId)
	}
	if listed.Queues[0].DeadLetterQueueId != "" {
		t.Fatalf("dead-letter queue id = %q, want empty", listed.Queues[0].DeadLetterQueueId)
	}
}
```

- [ ] **Step 2: Run the focused test and confirm the bug**

```bash
go test ./internal/server/service/queue/litestore -run TestStorageListQueuesHandlesNullableDeadLetterQueue -count=1
```

Expected: FAIL with `converting NULL to string is unsupported`.

- [ ] **Step 3: Scan the nullable value through `sql.NullString`**

Update the `listQueues` row variables and scan target:

```go
var (
	info              v1.DescribeQueueResponse
	createdAt         time.Time
	gcAt              time.Time
	deadLetterQueueID sql.NullString
)

if err := rows.Scan(
	&info.QueueId,
	&info.QueueName,
	&createdAt,
	&gcAt,
	&info.RetentionPeriodSeconds,
	&info.VisibilityTimeoutSeconds,
	&info.MaxReceiveAttempts,
	&info.EvictionPolicy,
	&deadLetterQueueID,
); err != nil {
	return nil, fmt.Errorf("row scan: %w", err)
}

info.CreatedAt = timestamppb.New(createdAt)
info.DeadLetterQueueId = deadLetterQueueID.String
```

- [ ] **Step 4: Add the non-NULL assertion**

Create a second queue as a DLQ, then a parent targeting it, list again, and assert the parent response contains the child ID:

```go
deadLetter, err := storage.CreateQueue(ctx, &v1.CreateQueueRequest{
	QueueName: "orders-dlq",
	EvictionPolicy: v1.EvictionPolicy_EVICTION_POLICY_DROP,
})
if err != nil {
	t.Fatalf("create dead-letter queue: %v", err)
}

_, err = storage.CreateQueue(ctx, &v1.CreateQueueRequest{
	QueueName: "payments",
	EvictionPolicy: v1.EvictionPolicy_EVICTION_POLICY_DEAD_LETTER,
	DeadLetterQueueId: deadLetter.QueueId,
})
if err != nil {
	t.Fatalf("create parent queue: %v", err)
}

listed, err = storage.ListQueues(ctx, &v1.ListQueuesRequest{Limit: 10})
if err != nil {
	t.Fatalf("list queues: %v", err)
}
for _, queue := range listed.Queues {
	if queue.QueueName == "payments" && queue.DeadLetterQueueId != deadLetter.QueueId {
		t.Fatalf("dead-letter queue id = %q, want %q", queue.DeadLetterQueueId, deadLetter.QueueId)
	}
}
```

- [ ] **Step 5: Verify, format, and commit**

```bash
gofmt -w internal/server/service/queue/litestore/storage.go internal/server/service/queue/litestore/storage_test.go
go test ./internal/server/service/queue/litestore -run TestStorageListQueuesHandlesNullableDeadLetterQueue -count=1
git add internal/server/service/queue/litestore/storage.go internal/server/service/queue/litestore/storage_test.go
git commit -m "fix(queue): list queues without dead-letter targets"
```

Expected: focused test PASS.

### Task 2: Add Tested Queue-Creation Model Logic

**Files:**
- Create: `internal/houston/ui/src/components/queue/queue-create-model.ts`
- Create: `internal/houston/ui/src/components/queue/queue-create-model.test.ts`

- [ ] **Step 1: Write failing tests**

Cover conditional validation, stale-ID removal, child policy filtering, multi-page loading, repeated-cursor protection, and deduplicated option merging:

```ts
import { describe, expect, test } from "bun:test";
import {
  createQueueSchema,
  getEvictionPolicyOptions,
  loadQueueOptions,
  mergeQueueOption,
  toCreateQueueInput,
} from "./queue-create-model";

const baseInput = {
  queueName: "orders",
  retentionPeriodSeconds: 345600,
  visibilityTimeoutSeconds: 30,
  maxReceiveAttempts: 10,
  evictionPolicy: "EVICTION_POLICY_DROP",
};

describe("queue creation model", () => {
  test("requires a target only for dead-letter policy", () => {
    expect(createQueueSchema.safeParse(baseInput).success).toBe(true);
    expect(createQueueSchema.safeParse({
      ...baseInput,
      evictionPolicy: "EVICTION_POLICY_DEAD_LETTER",
    }).success).toBe(false);
  });

  test("removes stale target and filters child policies", () => {
    expect(toCreateQueueInput({ ...baseInput, deadLetterQueueId: "old" })).toEqual(baseInput);
    expect(getEvictionPolicyOptions(false).map(([value]) => value)).not.toContain(
      "EVICTION_POLICY_DEAD_LETTER",
    );
  });

  test("loads every queue page", async () => {
    const calls: string[] = [];
    const list = async ({ cursor = "" }: { limit?: number; cursor?: string }) => {
      calls.push(cursor);
      return cursor
        ? { queues: [{ queueId: "q2", queueName: "two" }], hasMore: false, nextCursor: "" }
        : { queues: [{ queueId: "q1", queueName: "one" }], hasMore: true, nextCursor: "next" };
    };
    expect(await loadQueueOptions({ list })).toEqual([
      { queueId: "q1", queueName: "one" },
      { queueId: "q2", queueName: "two" },
    ]);
    expect(calls).toEqual(["", "next"]);
  });

  test("stops on a repeated cursor", async () => {
    let calls = 0;
    await loadQueueOptions({ list: async () => {
      calls += 1;
      return { queues: [], hasMore: true, nextCursor: "same" };
    }});
    expect(calls).toBe(2);
  });

  test("merges a created option once", () => {
    const created = { queueId: "q2", queueName: "two" };
    expect(mergeQueueOption([{ queueId: "q1", queueName: "one" }], created)).toEqual([
      { queueId: "q1", queueName: "one" },
      created,
    ]);
    expect(mergeQueueOption([created], created)).toEqual([created]);
  });
});
```

- [ ] **Step 2: Run the test and confirm the module is missing**

```bash
cd internal/houston/ui && bun test src/components/queue/queue-create-model.test.ts
```

Expected: FAIL because `queue-create-model.ts` does not exist.

- [ ] **Step 3: Implement the model module**

```ts
import { z } from "zod";
import type { CreateQueueInput } from "@/lib/api-client";
import { EVICTION_POLICY_LABELS } from "@/lib/constants";

export const DEAD_LETTER_POLICY = "EVICTION_POLICY_DEAD_LETTER";
export const CREATE_QUEUE_VALUE = "__create_queue__";

export const createQueueSchema = z.object({
  queueName: z.string().min(1, "Queue name is required")
    .max(80, "Queue name must be at most 80 characters")
    .regex(/^[a-zA-Z0-9_-]+$/, "Only letters, numbers, hyphens, and underscores"),
  retentionPeriodSeconds: z.coerce.number().min(60).max(1209600).optional(),
  visibilityTimeoutSeconds: z.coerce.number().min(0).max(43200).optional(),
  maxReceiveAttempts: z.coerce.number().min(1).max(1000).optional(),
  evictionPolicy: z.string().optional(),
  deadLetterQueueId: z.string().optional(),
}).superRefine((data, ctx) => {
  if (data.evictionPolicy === DEAD_LETTER_POLICY && !data.deadLetterQueueId) {
    ctx.addIssue({ code: "custom", path: ["deadLetterQueueId"], message: "Select or create a dead-letter queue" });
  }
});

export type CreateQueueFormInput = z.input<typeof createQueueSchema>;
export type CreateQueueFormData = z.output<typeof createQueueSchema>;
export interface QueueOption { queueId: string; queueName: string }
interface QueueListAPI {
  list(params?: { limit?: number; cursor?: string }): Promise<{
    queues?: QueueOption[];
    nextCursor?: string;
    hasMore?: boolean;
  }>;
}

export function getEvictionPolicyOptions(allowDeadLetter: boolean) {
  return Object.entries(EVICTION_POLICY_LABELS).filter(
    ([value]) => allowDeadLetter || value !== DEAD_LETTER_POLICY,
  );
}

export function toCreateQueueInput(data: CreateQueueFormData): CreateQueueInput {
  if (data.evictionPolicy === DEAD_LETTER_POLICY) return data;
  return {
    queueName: data.queueName,
    retentionPeriodSeconds: data.retentionPeriodSeconds,
    visibilityTimeoutSeconds: data.visibilityTimeoutSeconds,
    maxReceiveAttempts: data.maxReceiveAttempts,
    evictionPolicy: data.evictionPolicy,
  };
}

export async function loadQueueOptions(api: QueueListAPI): Promise<QueueOption[]> {
  const options: QueueOption[] = [];
  const seen = new Set<string>();
  let cursor = "";
  while (!seen.has(cursor)) {
    seen.add(cursor);
    const page = await api.list({ limit: 100, cursor });
    options.push(...(page.queues ?? []).map(({ queueId, queueName }) => ({ queueId, queueName })));
    if (!page.hasMore || !page.nextCursor) break;
    cursor = page.nextCursor;
  }
  return options;
}

export function mergeQueueOption(options: QueueOption[], created: QueueOption) {
  return options.some(({ queueId }) => queueId === created.queueId)
    ? options
    : [...options, created];
}
```

- [ ] **Step 4: Verify and commit the model**

```bash
cd internal/houston/ui
bun test src/components/queue/queue-create-model.test.ts
cd ../../../..
git add internal/houston/ui/src/components/queue/queue-create-model.ts internal/houston/ui/src/components/queue/queue-create-model.test.ts
git commit -m "feat(houston): model dead-letter queue creation"
```

Expected: model tests PASS.

### Task 3: Wire The Existing-Or-New Nested Dialog

**Files:**
- Modify: `internal/houston/ui/src/components/queue/queue-create-dialog.tsx`
- Modify: `internal/houston/ui/src/components/queue/queue-list.tsx`

- [ ] **Step 1: Add explicit parent and child modes**

Move schema/types to the model module, import `Controller` from react-hook-form, and replace the dialog props/state with:

```ts
type QueueCreateMode = "default" | "dead-letter";

interface QueueCreateDialogProps {
  mode?: QueueCreateMode;
  open?: boolean;
  onOpenChange?: (open: boolean) => void;
  onCreated?: (queue: QueueOption) => void;
}

export function QueueCreateDialog({
  mode = "default",
  open: controlledOpen,
  onOpenChange,
  onCreated,
}: QueueCreateDialogProps) {
  const [internalOpen, setInternalOpen] = useState(false);
  const [nestedOpen, setNestedOpen] = useState(false);
  const [queueOptions, setQueueOptions] = useState<QueueOption[]>([]);
  const [queueOptionsLoading, setQueueOptionsLoading] = useState(false);
  const [queueOptionsError, setQueueOptionsError] = useState<string | null>(null);
  const open = controlledOpen ?? internalOpen;
  const setOpen = onOpenChange ?? setInternalOpen;
  const allowDeadLetter = mode === "default";
```

Extend `useForm` destructuring with `control`, `setValue`, and `watch`. Keep the current defaults and set:

```ts
const evictionPolicy = watch("evictionPolicy");
```

- [ ] **Step 2: Load all existing options and clear stale IDs**

Add effects that only load for the open parent and that clear `deadLetterQueueId` when policy changes away from Dead Letter:

```ts
useEffect(() => {
  if (!open || !allowDeadLetter) return;
  let cancelled = false;
  setQueueOptionsLoading(true);
  setQueueOptionsError(null);

  loadQueueOptions(api.queues)
    .then((options) => { if (!cancelled) setQueueOptions(options); })
    .catch((error: unknown) => {
      if (!cancelled) {
        setQueueOptionsError(error instanceof Error ? error.message : "Failed to load queues");
      }
    })
    .finally(() => { if (!cancelled) setQueueOptionsLoading(false); });

  return () => { cancelled = true; };
}, [allowDeadLetter, open]);

useEffect(() => {
  if (evictionPolicy !== DEAD_LETTER_POLICY) {
    setValue("deadLetterQueueId", undefined, { shouldValidate: false });
  }
}, [evictionPolicy, setValue]);
```

- [ ] **Step 3: Return the created queue identity**

Normalize the request and pass ID/name to callers:

```ts
const onSubmit = async (data: CreateQueueFormData) => {
  try {
    const created = await api.queues.create(toCreateQueueInput(data));
    const option = { queueId: created.queueId, queueName: data.queueName };
    toast.success(
      mode === "dead-letter"
        ? `Dead-letter queue "${data.queueName}" created and selected`
        : `Queue "${data.queueName}" created`,
    );
    setOpen(false);
    reset();
    onCreated?.(option);
  } catch (error) {
    toast.error(error instanceof Error ? error.message : "Failed to create queue");
  }
};
```

- [ ] **Step 4: Replace the native policy control with Base UI Select**

```tsx
<Field>
  <FieldLabel>Eviction policy</FieldLabel>
  <Controller
    name="evictionPolicy"
    control={control}
    render={({ field }) => (
      <Select value={field.value} onValueChange={(value) => field.onChange(value ?? undefined)}>
        <SelectTrigger><SelectValue placeholder="Select an eviction policy" /></SelectTrigger>
        <SelectPopup>
          {getEvictionPolicyOptions(allowDeadLetter).map(([value, label]) => (
            <SelectItem key={value} value={value}>{label}</SelectItem>
          ))}
        </SelectPopup>
      </Select>
    )}
  />
</Field>
```

- [ ] **Step 5: Render the required existing-or-new selector**

When the parent policy is Dead Letter, render:

```tsx
<Field>
  <FieldLabel>Dead-letter queue</FieldLabel>
  <Controller
    name="deadLetterQueueId"
    control={control}
    render={({ field }) => (
      <Select
        value={field.value ?? null}
        onValueChange={(value) => {
          if (value === CREATE_QUEUE_VALUE) {
            setNestedOpen(true);
            return;
          }
          field.onChange(value ?? undefined);
        }}
      >
        <SelectTrigger disabled={queueOptionsLoading}>
          <SelectValue placeholder={queueOptionsLoading ? "Loading queues..." : "Select a queue"} />
        </SelectTrigger>
        <SelectPopup>
          {queueOptions.map((option) => (
            <SelectItem key={option.queueId} value={option.queueId}>
              <span className="flex flex-col">
                <span>{option.queueName}</span>
                <span className="text-xs text-muted-foreground">{option.queueId}</span>
              </span>
            </SelectItem>
          ))}
          {!queueOptionsLoading && queueOptions.length === 0 && (
            <SelectItem value="__empty__" disabled>No existing queues</SelectItem>
          )}
          <SelectItem value={CREATE_QUEUE_VALUE}>Create new queue...</SelectItem>
        </SelectPopup>
      </Select>
    )}
  />
  {queueOptionsError && (
    <FieldDescription className="text-destructive">
      Existing queues could not be loaded. You can still create a new queue.
    </FieldDescription>
  )}
  {errors.deadLetterQueueId && <FieldError>{errors.deadLetterQueueId.message}</FieldError>}
</Field>
```

The Select must remain enabled after a load error so the `Create new queue...` item is still reachable. Disable it only while loading.

- [ ] **Step 6: Render the controlled nested dialog**

Render a child dialog as a sibling of the parent popup. Child mode excludes Dead Letter through `getEvictionPolicyOptions(false)` and cannot recurse:

```tsx
{allowDeadLetter && (
  <QueueCreateDialog
    mode="dead-letter"
    open={nestedOpen}
    onOpenChange={setNestedOpen}
    onCreated={(created) => {
      setQueueOptions((options) => mergeQueueOption(options, created));
      setValue("deadLetterQueueId", created.queueId, {
        shouldDirty: true,
        shouldValidate: true,
      });
    }}
  />
)}
```

Only default mode renders the normal trigger. Child mode uses title `Create dead-letter queue` and description `Configure the queue that will receive evicted messages.` Both modes retain all numeric fields and validation.

Give both popups a stable mobile boundary so nested content scrolls instead of leaving the viewport:

```tsx
<DialogPopup className="max-h-[calc(100dvh-2rem)] max-w-md overflow-y-auto">
```

- [ ] **Step 7: Verify queue-list callback compatibility**

Keep `queue-list.tsx` refreshing after parent creation; it can ignore the new callback argument:

```ts
const handleCreated = () => {
  setCursors([""]);
  setCurrentPage(0);
  fetchQueues("", pageSize);
};
```

- [ ] **Step 8: Run frontend verification and commit**

```bash
cd internal/houston/ui
bun test
bun run check
bun run build
cd ../../../..
git add internal/houston/ui/src/components/queue/queue-create-dialog.tsx internal/houston/ui/src/components/queue/queue-list.tsx
git commit -m "feat(houston): create or select dead-letter queues"
```

Expected: tests pass, Astro reports zero errors, and production build succeeds.

### Task 4: Full Verification And Preview

**Files:**
- Verify: `internal/server/service/queue/litestore/storage.go`
- Verify: `internal/houston/ui/src/components/queue/queue-create-dialog.tsx`
- Verify: `docs/superpowers/specs/2026-07-10-dead-letter-queue-selection-design.md`

- [ ] **Step 1: Run all backend checks**

```bash
go test ./internal/server/service/queue/litestore -count=1
go test ./... -count=1
golangci-lint run --timeout=3m
```

Expected: all tests pass and lint reports `0 issues`.

- [ ] **Step 2: Run all Houston checks**

```bash
cd internal/houston/ui
bun test
bun run check
bun run build
```

Expected: all tests pass, check has zero errors, and build succeeds.

- [ ] **Step 3: Restart the embedded preview**

Stop the prior preview, rebuild Houston, and launch PlainQ on the existing preview ports with isolated storage:

```bash
go run ./cmd serve \
  --grpc.addr=:18080 \
  --http.addr=:8081 \
  --storage.path=/tmp/plainq-preview-ba47.db \
  --auth.jwt.secret=plainq-preview-local-secret
```

Expected: Houston logs `http://localhost:8081`, and `/health` returns HTTP 200.

- [ ] **Step 4: Exercise both UI flows**

At `http://localhost:8081`:

1. Select Dead Letter and verify parent submission requires a target.
2. Select an existing queue, create the parent, and verify the selected ID on queue detail.
3. Select Create new queue, configure a non-DLQ child, and create it.
4. Verify the child closes, focus returns to the parent, and the child is selected.
5. Create the parent and verify queue listing refreshes without HTTP 500.
6. Repeat at a mobile viewport and verify both dialogs fit without overlapping controls.

- [ ] **Step 5: Review the final diff**

```bash
git diff --check
git status --short
git log --oneline -5
```

Expected: only intentional feature files and the local `.superpowers/` visual-companion directory are present. Do not stage `.superpowers/`.
