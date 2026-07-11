import { useEffect, useRef, useState, type RefObject } from "react";
import { Controller, useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import {
  Dialog,
  DialogTrigger,
  DialogPopup,
  DialogTitle,
  DialogDescription,
  DialogClose,
} from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  Field,
  FieldLabel,
  FieldDescription,
  FieldError,
} from "@/components/ui/field";
import {
  Select,
  SelectTrigger,
  SelectValue,
  SelectPopup,
  SelectItem,
} from "@/components/ui/select";
import { api } from "@/lib/api-client";
import { Plus } from "lucide-react";
import { toast } from "sonner";
import {
  CREATE_QUEUE_VALUE,
  DEAD_LETTER_POLICY,
  createQueueSchema,
  getEvictionPolicyLabel,
  getEvictionPolicyOptions,
  getQueueOptionLabel,
  loadQueueOptions,
  mergeQueueOption,
  reconcileQueueOptions,
  toCreateQueueInput,
} from "./queue-create-model";
import type {
  CreateQueueFormData,
  CreateQueueFormInput,
  QueueOption,
} from "./queue-create-model";

export type QueueCreateDialogMode = "default" | "dead-letter";

interface QueueCreateDialogProps {
  mode?: QueueCreateDialogMode;
  open?: boolean;
  onOpenChange?: (open: boolean) => void;
  onCreated?: (queue: QueueOption) => void;
  finalFocus?: RefObject<HTMLElement | null>;
}

export function getQueueCreateDialogConfig(mode: QueueCreateDialogMode) {
  const allowDeadLetter = mode === "default";

  return {
    title: mode === "default" ? "Create Queue" : "Create dead-letter queue",
    description:
      mode === "default"
        ? "Configure a new message queue."
        : "Configure the queue that will receive evicted messages.",
    allowDeadLetter,
    policyOptions: getEvictionPolicyOptions(allowDeadLetter),
  };
}

export function QueueCreateDialog({
  mode = "default",
  open,
  onOpenChange,
  onCreated,
  finalFocus,
}: QueueCreateDialogProps) {
  const [uncontrolledOpen, setUncontrolledOpen] = useState(false);
  const [childOpen, setChildOpen] = useState(false);
  const [queueOptions, setQueueOptions] = useState<QueueOption[]>([]);
  const [isLoadingQueues, setIsLoadingQueues] = useState(false);
  const [queueLoadError, setQueueLoadError] = useState<string | null>(null);
  const deadLetterQueueTriggerRef = useRef<HTMLButtonElement>(null);
  const dialogOpen = open ?? uncontrolledOpen;
  const config = getQueueCreateDialogConfig(mode);
  const {
    register,
    control,
    handleSubmit,
    reset,
    setValue,
    watch,
    formState: { errors, isSubmitting },
  } = useForm<CreateQueueFormInput, unknown, CreateQueueFormData>({
    resolver: zodResolver(createQueueSchema),
    defaultValues: {
      retentionPeriodSeconds: 345600,
      visibilityTimeoutSeconds: 30,
      maxReceiveAttempts: 10,
      evictionPolicy: "EVICTION_POLICY_DROP",
    },
  });
  const evictionPolicy = watch("evictionPolicy");

  useEffect(() => {
    if (evictionPolicy !== DEAD_LETTER_POLICY) {
      setValue("deadLetterQueueId", undefined, { shouldValidate: false });
    }
  }, [evictionPolicy, setValue]);

  useEffect(() => {
    if (mode !== "default" || !dialogOpen) {
      return;
    }

    let active = true;
    setIsLoadingQueues(true);
    setQueueLoadError(null);
    setQueueOptions([]);

    loadQueueOptions(api)
      .then((options) => {
        if (active) {
          setQueueOptions((current) => reconcileQueueOptions(options, current));
        }
      })
      .catch((error) => {
        if (active) {
          setQueueLoadError(
            error instanceof Error ? error.message : "Failed to load queues",
          );
        }
      })
      .finally(() => {
        if (active) {
          setIsLoadingQueues(false);
        }
      });

    return () => {
      active = false;
    };
  }, [dialogOpen, mode]);

  const handleOpenChange = (nextOpen: boolean) => {
    if (open === undefined) {
      setUncontrolledOpen(nextOpen);
    }
    onOpenChange?.(nextOpen);
  };

  const handleChildCreated = (created: QueueOption) => {
    setQueueOptions((current) => mergeQueueOption(current, created));
    setValue("deadLetterQueueId", created.queueId, {
      shouldDirty: true,
      shouldValidate: true,
    });
  };

  const onSubmit = async (data: CreateQueueFormData) => {
    try {
      const { queueId } = await api.queues.create(toCreateQueueInput(data));
      const created = { queueId, queueName: data.queueName };

      toast.success(
        mode === "dead-letter"
          ? `Dead-letter queue "${data.queueName}" created and selected`
          : `Queue "${data.queueName}" created`,
      );
      handleOpenChange(false);
      reset();
      onCreated?.(created);
    } catch (error) {
      toast.error(
        error instanceof Error ? error.message : "Failed to create queue",
      );
    }
  };

  return (
    <>
      <Dialog open={dialogOpen} onOpenChange={handleOpenChange}>
        {mode === "default" && (
          <DialogTrigger render={<Button size="sm" />}>
            <Plus className="size-4" />
            Create Queue
          </DialogTrigger>
        )}
        <DialogPopup
          className="max-h-[calc(100dvh-2rem)] max-w-md overflow-y-auto"
          finalFocus={finalFocus}
        >
          <DialogTitle>{config.title}</DialogTitle>
          <DialogDescription className="mb-4">
            {config.description}
          </DialogDescription>
          <form onSubmit={handleSubmit(onSubmit)} className="space-y-4">
            <Field invalid={!!errors.queueName}>
              <FieldLabel>Name</FieldLabel>
              <Input placeholder="my-queue" {...register("queueName")} />
              <FieldDescription>
                Letters, numbers, hyphens, and underscores only.
              </FieldDescription>
              <FieldError match={!!errors.queueName}>
                {errors.queueName?.message}
              </FieldError>
            </Field>

            <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
              <Field invalid={!!errors.retentionPeriodSeconds}>
                <FieldLabel>Retention (seconds)</FieldLabel>
                <Input type="number" {...register("retentionPeriodSeconds")} />
                <FieldError match={!!errors.retentionPeriodSeconds}>
                  {errors.retentionPeriodSeconds?.message}
                </FieldError>
              </Field>
              <Field invalid={!!errors.visibilityTimeoutSeconds}>
                <FieldLabel>Visibility timeout (s)</FieldLabel>
                <Input type="number" {...register("visibilityTimeoutSeconds")} />
                <FieldError match={!!errors.visibilityTimeoutSeconds}>
                  {errors.visibilityTimeoutSeconds?.message}
                </FieldError>
              </Field>
            </div>

            <Field invalid={!!errors.maxReceiveAttempts}>
              <FieldLabel>Max receive attempts</FieldLabel>
              <Input type="number" {...register("maxReceiveAttempts")} />
              <FieldError match={!!errors.maxReceiveAttempts}>
                {errors.maxReceiveAttempts?.message}
              </FieldError>
            </Field>

            <Field>
              <FieldLabel>Eviction policy</FieldLabel>
              <Controller
                control={control}
                name="evictionPolicy"
                render={({ field }) => (
                  <Select
                    value={field.value ?? null}
                    onValueChange={(value) =>
                      field.onChange(value ?? undefined)
                    }
                  >
                    <SelectTrigger>
                      <SelectValue>
                        {(value: string | null) =>
                          getEvictionPolicyLabel(config.policyOptions, value)
                        }
                      </SelectValue>
                    </SelectTrigger>
                    <SelectPopup className="max-h-[calc(100dvh-2rem)] max-w-md overflow-y-auto">
                      {config.policyOptions.map((option) => (
                        <SelectItem key={option.value} value={option.value}>
                          {option.label}
                        </SelectItem>
                      ))}
                    </SelectPopup>
                  </Select>
                )}
              />
            </Field>

            {mode === "default" && evictionPolicy === DEAD_LETTER_POLICY && (
              <Controller
                control={control}
                name="deadLetterQueueId"
                render={({ field, fieldState }) => (
                  <Field name={field.name} invalid={fieldState.invalid}>
                    <FieldLabel>Dead-letter queue</FieldLabel>
                    <Select
                      value={field.value ?? null}
                      onValueChange={(value) => {
                        if (value === CREATE_QUEUE_VALUE) {
                          setChildOpen(true);
                          return;
                        }
                        field.onChange(value ?? undefined);
                      }}
                    >
                      <SelectTrigger ref={deadLetterQueueTriggerRef}>
                        <SelectValue>
                          {(value: string | null) =>
                            getQueueOptionLabel(queueOptions, value)
                          }
                        </SelectValue>
                      </SelectTrigger>
                      <SelectPopup className="max-h-[calc(100dvh-2rem)] max-w-md overflow-y-auto">
                        {isLoadingQueues ? (
                          <SelectItem value="__loading_queues__" disabled>
                            Loading queues...
                          </SelectItem>
                        ) : queueOptions.length > 0 ? (
                          queueOptions.map((option) => (
                            <SelectItem
                              key={option.queueId}
                              value={option.queueId}
                            >
                              <span className="flex flex-col">
                                <span>{option.queueName}</span>
                                <span className="text-xs text-muted-foreground">
                                  {option.queueId}
                                </span>
                              </span>
                            </SelectItem>
                          ))
                        ) : (
                          <SelectItem value="__no_queues__" disabled>
                            No queues available
                          </SelectItem>
                        )}
                        <SelectItem value={CREATE_QUEUE_VALUE}>
                          <Plus className="size-4" />
                          Create new queue...
                        </SelectItem>
                      </SelectPopup>
                    </Select>
                    {queueLoadError && (
                      <FieldDescription className="text-destructive" role="alert">
                        Failed to load queues: {queueLoadError}
                      </FieldDescription>
                    )}
                    <FieldError match={!!fieldState.error}>
                      {fieldState.error?.message}
                    </FieldError>
                  </Field>
                )}
              />
            )}

            <div className="flex justify-end gap-2 pt-2">
              <DialogClose render={<Button type="button" variant="outline" />}>
                Cancel
              </DialogClose>
              <Button type="submit" disabled={isSubmitting}>
                <Plus className="size-4" />
                {isSubmitting ? "Creating..." : "Create"}
              </Button>
            </div>
          </form>
        </DialogPopup>
      </Dialog>

      {mode === "default" && (
        <QueueCreateDialog
          mode="dead-letter"
          open={childOpen}
          onOpenChange={setChildOpen}
          onCreated={handleChildCreated}
          finalFocus={deadLetterQueueTriggerRef}
        />
      )}
    </>
  );
}
