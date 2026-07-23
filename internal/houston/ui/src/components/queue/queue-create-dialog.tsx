"use client";

import * as React from "react";
import { Controller, useForm, useWatch } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { Popover } from "radix-ui";
import { ChevronDown, Plus } from "lucide-react";
import { toast } from "sonner";

import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogClose,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Field, FieldDescription, FieldError, FieldLabel } from "@/components/ui/field";
import { InlineAlert } from "@/components/ui/feedback";
import { Input, MonoInput } from "@/components/ui/input";
import { Micro } from "@/components/ui/value";
import { api } from "@/lib/api-client";
import { cn } from "@/lib/utils";
import {
  CREATE_QUEUE_VALUE,
  DEAD_LETTER_POLICY,
  getQueueOptionLabel,
  loadQueueOptions,
  mergeQueueOption,
  reconcileQueueOptions,
  type QueueOption,
} from "./queue-create-model";
import { DeadLetterCreateDialog } from "./list/dead-letter-create-dialog";
import { DurationField, PolicyToggle } from "./list/queue-form-fields";
import {
  QUEUE_FORM_DEFAULTS,
  getQueueCreateDialogConfig,
  queueFormSchema,
  toCreateQueueRequest,
  toSeconds,
  type DurationUnit,
  type QueueFormData,
  type QueueFormValues,
} from "./list/queue-form";

export {
  getQueueCreateDialogConfig,
  type QueueCreateDialogMode,
} from "./list/queue-form";

interface QueueCreateDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  /** Fired once the server has accepted the queue. */
  onCreated: (queueId: string) => void;
}

export function QueueCreateDialog({ open, onOpenChange, onCreated }: QueueCreateDialogProps) {
  const fieldId = React.useId();
  const config = getQueueCreateDialogConfig("default");

  const [submitError, setSubmitError] = React.useState<string | null>(null);
  const [childOpen, setChildOpen] = React.useState(false);

  const [options, setOptions] = React.useState<QueueOption[] | null>(null);
  const [optionsLoading, setOptionsLoading] = React.useState(false);
  const [optionsError, setOptionsError] = React.useState<string | null>(null);
  const deadLetterTriggerRef = React.useRef<HTMLButtonElement>(null);

  const {
    register,
    handleSubmit,
    control,
    reset,
    setValue,
    formState: { errors, isSubmitting },
  } = useForm<QueueFormValues, unknown, QueueFormData>({
    resolver: zodResolver(queueFormSchema),
    defaultValues: QUEUE_FORM_DEFAULTS,
  });

  const [
    queueName,
    policy,
    attempts,
    deadLetterQueueId,
    retentionValue,
    retentionUnit,
    visibilityValue,
    visibilityUnit,
  ] = useWatch({
    control,
    name: [
      "queueName",
      "evictionPolicy",
      "maxReceiveAttempts",
      "deadLetterQueueId",
      "retentionValue",
      "retentionUnit",
      "visibilityValue",
      "visibilityUnit",
    ],
  });
  const wantsDeadLetter = policy === DEAD_LETTER_POLICY;

  const loadOptions = React.useCallback(async () => {
    setOptionsLoading(true);
    setOptionsError(null);
    try {
      const loaded = await loadQueueOptions(api);
      // A queue the child dialog just created is already real on the server;
      // never let a reload of the list drop it back out of the selector.
      setOptions((current) => reconcileQueueOptions(loaded, current ?? []));
    } catch (err) {
      setOptionsError(err instanceof Error ? err.message : "Could not load queues");
    } finally {
      setOptionsLoading(false);
    }
  }, []);

  React.useEffect(() => {
    if (open && wantsDeadLetter && options === null && !optionsLoading && !optionsError) {
      void loadOptions();
    }
  }, [open, wantsDeadLetter, options, optionsLoading, optionsError, loadOptions]);

  const handleOpenChange = (next: boolean) => {
    onOpenChange(next);
    if (!next) {
      reset(QUEUE_FORM_DEFAULTS);
      setSubmitError(null);
      setOptions(null);
      setOptionsError(null);
    }
  };

  /**
   * The child queue already exists on the server by the time we get here, so
   * it is merged in and selected — but the parent still needs its own submit.
   */
  const handleDeadLetterCreated = (queueId: string, queueName: string) => {
    setChildOpen(false);
    setOptions((current) => mergeQueueOption(current ?? [], { queueId, queueName }));
    setValue("deadLetterQueueId", queueId, { shouldDirty: true, shouldValidate: true });
    deadLetterTriggerRef.current?.focus();
  };

  const handleChildOpenChange = (next: boolean) => {
    setChildOpen(next);
    if (!next) deadLetterTriggerRef.current?.focus();
  };

  const onSubmit = async (data: QueueFormData) => {
    setSubmitError(null);
    try {
      const created = await api.queues.create(toCreateQueueRequest(data));
      toast.success(`Queue ${data.queueName} created`);
      handleOpenChange(false);
      onCreated(created.queueId);
    } catch (err) {
      setSubmitError(err instanceof Error ? err.message : "Could not create queue");
    }
  };

  const attemptCount = Number(attempts);
  const deadLetterHint =
    Number.isFinite(attemptCount) && attemptCount > 0
      ? `After ${attemptCount} failed receive attempts, messages are moved to the dead-letter queue.`
      : "After the last receive attempt, messages are moved to the dead-letter queue.";

  return (
    <Dialog open={open} onOpenChange={handleOpenChange}>
      <DialogContent
        showCloseButton={false}
        className="max-h-[calc(100vh-4rem)] gap-0 overflow-y-auto p-6 sm:max-w-[480px]"
      >
        <DialogHeader className="gap-0 pr-0">
          <DialogTitle className="text-base leading-[22px] tracking-[-0.01em]">
            {config.title}
          </DialogTitle>
          <DialogDescription className="mt-1.5 mb-5 leading-[17px]">
            {config.description}
          </DialogDescription>
        </DialogHeader>

        <form onSubmit={handleSubmit(onSubmit)} className="flex flex-col gap-[18px]">
          <Field>
            <FieldLabel htmlFor={`${fieldId}-name`}>Queue name</FieldLabel>
            <Input
              id={`${fieldId}-name`}
              autoComplete="off"
              spellCheck={false}
              placeholder="payment-retries"
              aria-invalid={Boolean(errors.queueName)}
              {...register("queueName")}
            />
            {errors.queueName ? (
              <FieldError>{errors.queueName.message}</FieldError>
            ) : (
              <FieldDescription>
                1–80 characters. Letters, numbers, _ and - only.
              </FieldDescription>
            )}
          </Field>

          <DurationField
            control={control}
            label="Message retention"
            hint="60 s to 14 d. Messages older than this are removed."
            error={errors.retentionValue?.message}
            valueId={`${fieldId}-retention`}
            unitField="retentionUnit"
            seconds={toSeconds(Number(retentionValue), retentionUnit as DurationUnit)}
            register={register("retentionValue")}
          />

          <DurationField
            control={control}
            label="Visibility timeout"
            hint="0 s to 12 h. How long a received message stays invisible before it can be redelivered."
            error={errors.visibilityValue?.message}
            valueId={`${fieldId}-visibility`}
            unitField="visibilityUnit"
            seconds={toSeconds(Number(visibilityValue), visibilityUnit as DurationUnit)}
            register={register("visibilityValue")}
          />

          <Field>
            <FieldLabel htmlFor={`${fieldId}-attempts`}>Maximum receive attempts</FieldLabel>
            <div className="flex">
              <MonoInput
                id={`${fieldId}-attempts`}
                type="number"
                min={1}
                max={1000}
                className="w-18"
                aria-invalid={Boolean(errors.maxReceiveAttempts)}
                {...register("maxReceiveAttempts")}
              />
            </div>
            {errors.maxReceiveAttempts ? (
              <FieldError>{errors.maxReceiveAttempts.message}</FieldError>
            ) : (
              <FieldDescription>
                1–1000. After the last attempt the eviction policy applies.
              </FieldDescription>
            )}
          </Field>

          <Field>
            <FieldLabel>Eviction policy</FieldLabel>
            <Controller
              control={control}
              name="evictionPolicy"
              render={({ field }) => (
                <PolicyToggle
                  options={config.policyOptions}
                  value={field.value}
                  onChange={field.onChange}
                />
              )}
            />
            <FieldDescription>
              {wantsDeadLetter
                ? deadLetterHint
                : "Evicted messages are handled by the selected policy."}
            </FieldDescription>
          </Field>

          {wantsDeadLetter ? (
            <Field>
              <FieldLabel htmlFor={`${fieldId}-dlq`}>Dead-letter queue</FieldLabel>
              <Controller
                control={control}
                name="deadLetterQueueId"
                render={({ field }) => (
                  <DeadLetterSelect
                    ref={deadLetterTriggerRef}
                    triggerId={`${fieldId}-dlq`}
                    value={field.value ?? ""}
                    onChange={(value) => {
                      // The sentinel is an action, not a queue: it opens the
                      // child dialog and leaves the selection untouched.
                      if (value === CREATE_QUEUE_VALUE) {
                        setChildOpen(true);
                        return;
                      }
                      field.onChange(value);
                    }}
                    options={options}
                    loading={optionsLoading}
                    error={optionsError}
                    invalid={Boolean(errors.deadLetterQueueId)}
                    onRetry={() => void loadOptions()}
                  />
                )}
              />
              {errors.deadLetterQueueId ? (
                <FieldError>{errors.deadLetterQueueId.message}</FieldError>
              ) : null}
            </Field>
          ) : null}

          {submitError ? <InlineAlert>{submitError}</InlineAlert> : null}

          <div className="flex justify-end gap-2 border-t border-border pt-4">
            <DialogClose asChild>
              <Button type="button" variant="outline">
                Cancel
              </Button>
            </DialogClose>
            <Button type="submit" loading={isSubmitting}>
              Create queue
            </Button>
          </div>
        </form>

        {childOpen ? (
          <DeadLetterCreateDialog
            parentName={typeof queueName === "string" ? queueName : ""}
            onOpenChange={handleChildOpenChange}
            onCreated={handleDeadLetterCreated}
          />
        ) : null}
      </DialogContent>
    </Dialog>
  );
}

interface DeadLetterSelectProps {
  ref?: React.Ref<HTMLButtonElement>;
  triggerId: string;
  value: string;
  /** Receives a queue ID, or `CREATE_QUEUE_VALUE` to create one. */
  onChange: (value: string) => void;
  options: QueueOption[] | null;
  loading: boolean;
  error: string | null;
  invalid: boolean;
  onRetry: () => void;
}

/**
 * Every queue is a candidate target — the server decides what it will accept,
 * not this list. A failed load keeps the create-new path reachable instead of
 * stranding the operator.
 */
function DeadLetterSelect({
  ref,
  triggerId,
  value,
  onChange,
  options,
  loading,
  error,
  invalid,
  onRetry,
}: DeadLetterSelectProps) {
  const [open, setOpen] = React.useState(false);
  const [query, setQuery] = React.useState("");

  const selected = (options ?? []).find((option) => option.queueId === value);
  const needle = query.trim().toLowerCase();
  const matches = (options ?? []).filter(
    (option) =>
      !needle ||
      option.queueName.toLowerCase().includes(needle) ||
      option.queueId.toLowerCase().includes(needle),
  );

  return (
    <Popover.Root
      open={open}
      onOpenChange={(next) => {
        setOpen(next);
        if (!next) setQuery("");
      }}
    >
      <Popover.Trigger asChild>
        <button
          ref={ref}
          id={triggerId}
          type="button"
          aria-invalid={invalid}
          className={cn(
            "flex h-8 w-full items-center justify-between gap-2 border border-border bg-surface px-2.5 text-[13px] transition-colors",
            "data-[state=open]:border-foreground aria-invalid:border-destructive",
          )}
        >
          {value ? (
            <span className={cn("truncate", !selected && "font-mono text-xs tabular")}>
              {getQueueOptionLabel(options ?? [], value)}
            </span>
          ) : (
            <span className="text-subtle">Select or create a queue</span>
          )}
          <ChevronDown className="size-3.5 shrink-0 text-muted-foreground" aria-hidden />
        </button>
      </Popover.Trigger>

      <Popover.Portal>
        <Popover.Content
          align="start"
          sideOffset={4}
          className="z-[60] w-(--radix-popover-trigger-width) border border-border bg-surface text-[13px] outline-none"
        >
          <Input
            value={query}
            onChange={(event) => setQuery(event.target.value)}
            placeholder="Search queues…"
            className="border-0 border-b border-border text-xs"
            aria-label="Search queues"
          />

          <div className="max-h-56 overflow-y-auto">
            {loading ? (
              <div className="px-2.5 py-2">
                <Micro>Loading queues…</Micro>
              </div>
            ) : error ? (
              <div className="flex items-center gap-2 px-2.5 py-2">
                <span className="min-w-0 text-xs text-destructive-text">
                  Couldn&rsquo;t load queues.
                </span>
                <Button
                  type="button"
                  variant="destructive-outline"
                  size="sm"
                  className="ml-auto"
                  onClick={onRetry}
                >
                  Retry
                </Button>
              </div>
            ) : matches.length === 0 ? (
              <div className="px-2.5 py-2">
                <Micro>
                  {options && options.length > 0
                    ? "No queue matches that search."
                    : "No queue can take dead-lettered messages yet."}
                </Micro>
              </div>
            ) : (
              matches.map((option) => (
                <button
                  key={option.queueId}
                  type="button"
                  onClick={() => {
                    onChange(option.queueId);
                    setOpen(false);
                  }}
                  className={cn(
                    "flex w-full items-center justify-between gap-3 px-2.5 py-2 text-left transition-colors hover:bg-muted",
                    option.queueId === value && "bg-muted",
                  )}
                >
                  <span className="min-w-0">
                    <span className="block truncate text-[13px] leading-[17px] font-medium">
                      {option.queueName}
                    </span>
                    <span className="block truncate font-mono text-[10px] leading-[14px] tabular text-muted-foreground">
                      {option.queueId}
                    </span>
                  </span>
                </button>
              ))
            )}
          </div>

          {/* Stays reachable even when the option list failed to load. */}
          <button
            type="button"
            onClick={() => {
              setOpen(false);
              onChange(CREATE_QUEUE_VALUE);
            }}
            className="flex w-full items-center gap-2 border-t border-border px-2.5 py-2 text-[13px] font-medium transition-colors hover:bg-muted"
          >
            <Plus className="size-3.5" aria-hidden />
            Create new queue…
          </button>
        </Popover.Content>
      </Popover.Portal>
    </Popover.Root>
  );
}
