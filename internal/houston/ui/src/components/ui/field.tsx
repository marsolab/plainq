import { Field as BaseField } from "@base-ui/react/field";
import { cn } from "@/lib/utils";
import type { ComponentPropsWithoutRef } from "react";

function Field({
  className,
  ...props
}: ComponentPropsWithoutRef<typeof BaseField.Root>) {
  return <BaseField.Root className={cn("space-y-2", className)} {...props} />;
}

function FieldLabel({
  className,
  ...props
}: ComponentPropsWithoutRef<typeof BaseField.Label>) {
  return (
    <BaseField.Label
      className={cn(
        "text-sm font-medium leading-none peer-disabled:cursor-not-allowed peer-disabled:opacity-70",
        className,
      )}
      {...props}
    />
  );
}

function FieldDescription({
  className,
  ...props
}: ComponentPropsWithoutRef<typeof BaseField.Description>) {
  return (
    <BaseField.Description
      className={cn("text-xs text-muted-foreground", className)}
      {...props}
    />
  );
}

function FieldError({
  className,
  ...props
}: ComponentPropsWithoutRef<typeof BaseField.Error>) {
  return (
    <BaseField.Error
      className={cn("text-xs text-destructive", className)}
      {...props}
    />
  );
}

export { Field, FieldLabel, FieldDescription, FieldError };
