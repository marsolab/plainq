"use client";

import * as React from "react";
import { Eye, EyeOff } from "lucide-react";

import { Field, FieldLabel, FieldDescription, FieldError } from "@/components/ui/field";
import { Input } from "@/components/ui/input";
import { cn } from "@/lib/utils";

interface AuthFieldProps extends React.ComponentProps<"input"> {
  label: string;
  /** Marks a value the request works without. */
  optional?: boolean;
  /** Only ever a rule this form itself enforces — never a guess at the server's. */
  hint?: string;
  error?: string;
  /**
   * Marks the field as suspect without attaching a message — the request was
   * rejected as a whole and the reason belongs to the form, not the field.
   */
  invalid?: boolean;
}

function useFieldId(id: string | undefined): string {
  const generated = React.useId();
  return id ?? generated;
}

function AuthFieldLabel({ label, optional, htmlFor }: {
  label: string;
  optional?: boolean;
  htmlFor: string;
}) {
  return (
    <FieldLabel htmlFor={htmlFor}>
      {label}
      {optional ? <span className="font-normal text-subtle">optional</span> : null}
    </FieldLabel>
  );
}

function TextField({
  label,
  optional,
  hint,
  error,
  invalid,
  id,
  className,
  ...props
}: AuthFieldProps) {
  const inputId = useFieldId(id);
  const hintId = `${inputId}-hint`;
  const flagged = Boolean(error) || Boolean(invalid);

  return (
    <Field data-invalid={flagged ? true : undefined}>
      <AuthFieldLabel label={label} optional={optional} htmlFor={inputId} />
      <Input
        id={inputId}
        aria-invalid={flagged ? true : undefined}
        aria-describedby={hint && !error ? hintId : undefined}
        className={className}
        {...props}
      />
      {hint && !error ? <FieldDescription id={hintId}>{hint}</FieldDescription> : null}
      <FieldError>{error}</FieldError>
    </Field>
  );
}

function PasswordField({
  label,
  optional,
  hint,
  error,
  invalid,
  id,
  className,
  ...props
}: AuthFieldProps) {
  const inputId = useFieldId(id);
  const hintId = `${inputId}-hint`;
  const flagged = Boolean(error) || Boolean(invalid);
  const [revealed, setRevealed] = React.useState(false);

  return (
    <Field data-invalid={flagged ? true : undefined}>
      <AuthFieldLabel label={label} optional={optional} htmlFor={inputId} />
      <div className="relative">
        <Input
          id={inputId}
          type={revealed ? "text" : "password"}
          aria-invalid={flagged ? true : undefined}
          aria-describedby={hint && !error ? hintId : undefined}
          className={cn("pr-8", className)}
          {...props}
        />
        <button
          type="button"
          onClick={() => setRevealed((value) => !value)}
          aria-label={revealed ? "Hide password" : "Show password"}
          aria-pressed={revealed}
          className="absolute top-0 right-0 inline-flex size-8 cursor-pointer items-center justify-center text-muted-foreground transition-colors hover:text-foreground"
        >
          {revealed ? (
            <EyeOff className="size-3.5" aria-hidden />
          ) : (
            <Eye className="size-3.5" aria-hidden />
          )}
        </button>
      </div>
      {hint && !error ? <FieldDescription id={hintId}>{hint}</FieldDescription> : null}
      <FieldError>{error}</FieldError>
    </Field>
  );
}

export { TextField, PasswordField };
