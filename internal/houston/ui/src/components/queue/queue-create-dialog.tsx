import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import { z } from "zod";
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
import { Field, FieldLabel, FieldDescription, FieldError } from "@/components/ui/field";
import {
  Select,
  SelectTrigger,
  SelectValue,
  SelectPopup,
  SelectItem,
} from "@/components/ui/select";
import { api } from "@/lib/api-client";
import { EVICTION_POLICY_LABELS } from "@/lib/constants";
import { Plus } from "lucide-react";
import { useState } from "react";
import { toast } from "sonner";

const createQueueSchema = z.object({
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
});

type CreateQueueFormData = z.infer<typeof createQueueSchema>;

interface QueueCreateDialogProps {
  onCreated?: () => void;
}

export function QueueCreateDialog({ onCreated }: QueueCreateDialogProps) {
  const [open, setOpen] = useState(false);
  const {
    register,
    handleSubmit,
    reset,
    formState: { errors, isSubmitting },
  } = useForm<CreateQueueFormData>({
    resolver: zodResolver(createQueueSchema),
    defaultValues: {
      retentionPeriodSeconds: 345600,
      visibilityTimeoutSeconds: 30,
      maxReceiveAttempts: 10,
      evictionPolicy: "EVICTION_POLICY_DROP",
    },
  });

  const onSubmit = async (data: CreateQueueFormData) => {
    try {
      await api.queues.create(data);
      toast.success(`Queue "${data.queueName}" created`);
      setOpen(false);
      reset();
      onCreated?.();
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "Failed to create queue");
    }
  };

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger render={<Button size="sm" />}>
        <Plus className="size-4" />
        Create Queue
      </DialogTrigger>
      <DialogPopup className="max-w-md">
        <DialogTitle>Create Queue</DialogTitle>
        <DialogDescription className="mb-4">
          Configure a new message queue.
        </DialogDescription>
        <form onSubmit={handleSubmit(onSubmit)} className="space-y-4">
          <Field>
            <FieldLabel>Name</FieldLabel>
            <Input placeholder="my-queue" {...register("queueName")} />
            <FieldDescription>
              Letters, numbers, hyphens, and underscores only.
            </FieldDescription>
            {errors.queueName && (
              <FieldError>{errors.queueName.message}</FieldError>
            )}
          </Field>

          <div className="grid grid-cols-2 gap-4">
            <Field>
              <FieldLabel>Retention (seconds)</FieldLabel>
              <Input
                type="number"
                {...register("retentionPeriodSeconds")}
              />
              {errors.retentionPeriodSeconds && (
                <FieldError>
                  {errors.retentionPeriodSeconds.message}
                </FieldError>
              )}
            </Field>
            <Field>
              <FieldLabel>Visibility timeout (s)</FieldLabel>
              <Input
                type="number"
                {...register("visibilityTimeoutSeconds")}
              />
              {errors.visibilityTimeoutSeconds && (
                <FieldError>
                  {errors.visibilityTimeoutSeconds.message}
                </FieldError>
              )}
            </Field>
          </div>

          <Field>
            <FieldLabel>Max receive attempts</FieldLabel>
            <Input
              type="number"
              {...register("maxReceiveAttempts")}
            />
            {errors.maxReceiveAttempts && (
              <FieldError>{errors.maxReceiveAttempts.message}</FieldError>
            )}
          </Field>

          <Field>
            <FieldLabel>Eviction policy</FieldLabel>
            <select
              className="flex h-9 w-full rounded-md border border-input bg-surface px-3 py-1 text-sm shadow-sm focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
              {...register("evictionPolicy")}
            >
              {Object.entries(EVICTION_POLICY_LABELS).map(([value, label]) => (
                <option key={value} value={value}>
                  {label}
                </option>
              ))}
            </select>
          </Field>

          <div className="flex justify-end gap-2 pt-2">
            <DialogClose
              render={<Button type="button" variant="outline" />}
            >
              Cancel
            </DialogClose>
            <Button type="submit" disabled={isSubmitting}>
              {isSubmitting ? "Creating..." : "Create"}
            </Button>
          </div>
        </form>
      </DialogPopup>
    </Dialog>
  );
}
