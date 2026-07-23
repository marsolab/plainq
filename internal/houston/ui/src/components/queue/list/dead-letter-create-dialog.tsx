"use client";

import * as React from "react";
import { Controller, useForm, useWatch } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { CircleAlert, TriangleAlert } from "lucide-react";
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
import { api } from "@/lib/api-client";
import { DROP } from "./eviction";
import { DurationField, PolicyToggle } from "./queue-form-fields";
import {
  QUEUE_FORM_DEFAULTS,
  getQueueCreateDialogConfig,
  queueFormSchema,
  toCreateQueueRequest,
  toSeconds,
  type DurationUnit,
  type QueueFormData,
  type QueueFormValues,
} from "./queue-form";

interface DeadLetterCreateDialogProps {
  /** Only used to name the child and explain what it is for. */
  parentName: string;
  onOpenChange: (open: boolean) => void;
  onCreated: (queueId: string, queueName: string) => void;
}

/**
 * The nested child of the create-queue dialog. It creates a real queue the
 * moment it is submitted — no transaction spans both dialogs, so the
 * disclosure says so rather than implying a rollback that does not exist.
 */
export function DeadLetterCreateDialog({
  parentName,
  onOpenChange,
  onCreated,
}: DeadLetterCreateDialogProps) {
  const fieldId = React.useId();
  const config = getQueueCreateDialogConfig("dead-letter");
  const [submitError, setSubmitError] = React.useState<string | null>(null);

  const {
    register,
    handleSubmit,
    control,
    formState: { errors, isSubmitting },
  } = useForm<QueueFormValues, unknown, QueueFormData>({
    resolver: zodResolver(queueFormSchema),
    defaultValues: {
      ...QUEUE_FORM_DEFAULTS,
      queueName: /^[A-Za-z0-9_-]+$/.test(parentName)
        ? `${parentName}-dlq`.slice(0, 80)
        : "",
      retentionValue: 14,
      retentionUnit: "days",
      evictionPolicy: DROP,
    },
  });

  const [retentionValue, retentionUnit, visibilityValue, visibilityUnit] = useWatch({
    control,
    name: ["retentionValue", "retentionUnit", "visibilityValue", "visibilityUnit"],
  });

  const onSubmit = async (data: QueueFormData) => {
    setSubmitError(null);
    try {
      const created = await api.queues.create(toCreateQueueRequest(data));
      toast.success(`Queue ${data.queueName} created`);
      onCreated(created.queueId, data.queueName);
    } catch (err) {
      setSubmitError(err instanceof Error ? err.message : "Could not create queue");
    }
  };

  return (
    <Dialog open onOpenChange={onOpenChange}>
      <DialogContent className="max-h-[calc(100vh-4rem)] gap-0 overflow-y-auto p-6 sm:max-w-[480px]">
        <DialogHeader className="gap-0">
          <DialogTitle className="text-base leading-[22px] tracking-[-0.01em]">
            {config.title}
          </DialogTitle>
          <DialogDescription className="mt-1.5 mb-5 leading-[17px]">
            {parentName
              ? `Will receive messages evicted from ${parentName}.`
              : config.description}
          </DialogDescription>
        </DialogHeader>

        <form onSubmit={handleSubmit(onSubmit)} className="flex flex-col gap-[18px]">
          <Field>
            <FieldLabel htmlFor={`${fieldId}-name`}>Queue name</FieldLabel>
            <Input
              id={`${fieldId}-name`}
              autoComplete="off"
              spellCheck={false}
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
            <div className="flex items-start gap-2 text-[11px] leading-[15px] text-muted-foreground">
              <CircleAlert className="mt-px size-3.5 shrink-0" aria-hidden />
              <span>
                Dead-letter is unavailable here to prevent nested dead-letter chains.
              </span>
            </div>
          </Field>

          <div className="flex gap-2.5 border border-warning bg-warning-surface px-3 py-2.5">
            <TriangleAlert className="mt-px size-3.5 shrink-0 text-warning-text" aria-hidden />
            <span className="text-xs leading-relaxed text-warning-text">
              This queue is created immediately. It will remain if you cancel or fail to
              create the parent queue — there is no automatic rollback.
            </span>
          </div>

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
      </DialogContent>
    </Dialog>
  );
}
