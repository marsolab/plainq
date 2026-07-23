"use client";

import { Controller, type Control, type UseFormRegisterReturn } from "react-hook-form";

import { Field, FieldDescription, FieldError, FieldLabel } from "@/components/ui/field";
import { MonoInput } from "@/components/ui/input";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Micro } from "@/components/ui/value";
import { formatSecondsExact } from "@/lib/format";
import { cn } from "@/lib/utils";
import { DURATION_UNITS, type QueueFormData, type QueueFormValues } from "./queue-form";

/** Both creation dialogs drive the same form shape, so they share one control type. */
export type QueueFormControl = Control<QueueFormValues, unknown, QueueFormData>;

interface DurationFieldProps {
  control: QueueFormControl;
  label: string;
  hint: string;
  error?: string;
  valueId: string;
  unitField: "retentionUnit" | "visibilityUnit";
  /** Already resolved by the form owner so the preview tracks every keystroke. */
  seconds: number;
  register: UseFormRegisterReturn;
}

/** Value + unit, with the exact second count the server will store spelled out. */
export function DurationField({
  control,
  label,
  hint,
  error,
  valueId,
  unitField,
  seconds,
  register,
}: DurationFieldProps) {
  return (
    <Field>
      <FieldLabel htmlFor={valueId}>{label}</FieldLabel>
      <div className="flex items-center gap-2">
        <MonoInput
          id={valueId}
          type="number"
          min={0}
          className="w-18"
          aria-invalid={Boolean(error)}
          {...register}
        />
        <Controller
          control={control}
          name={unitField}
          render={({ field }) => (
            <Select value={field.value} onValueChange={field.onChange}>
              <SelectTrigger className="w-28 justify-between" aria-label={`${label} unit`}>
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {DURATION_UNITS.map((option) => (
                  <SelectItem key={option} value={option}>
                    {option}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          )}
        />
        <Micro className="shrink-0">= {formatSecondsExact(seconds)}</Micro>
      </div>
      {error ? <FieldError>{error}</FieldError> : <FieldDescription>{hint}</FieldDescription>}
    </Field>
  );
}

interface PolicyToggleProps {
  /** Every policy the server accepts for this dialog, already labelled. */
  options: ReadonlyArray<{ value: string; label: string }>;
  value: string;
  onChange: (value: string) => void;
}

/**
 * The eviction policy is a small closed set, so it is shown in full rather
 * than hidden behind a menu. Labels come from the model's option list, which
 * reads the one project-wide policy label table.
 */
export function PolicyToggle({ options, value, onChange }: PolicyToggleProps) {
  return (
    <div className="flex border border-border" role="group">
      {options.map((option, index) => {
        const selected = value === option.value;
        return (
          <button
            key={option.value}
            type="button"
            aria-pressed={selected}
            onClick={() => onChange(option.value)}
            className={cn(
              "h-8 min-w-0 flex-1 truncate px-2 text-[13px] font-medium transition-colors",
              index > 0 && "border-l border-border",
              selected
                ? "bg-primary text-primary-foreground"
                : "bg-surface text-strong hover:bg-muted",
            )}
          >
            {option.label}
          </button>
        );
      })}
    </div>
  );
}
