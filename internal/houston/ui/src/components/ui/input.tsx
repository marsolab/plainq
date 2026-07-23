import * as React from "react";

import { cn } from "@/lib/utils";

function Input({ className, type, ...props }: React.ComponentProps<"input">) {
  return (
    <input
      type={type}
      data-slot="input"
      className={cn(
        "h-8 w-full min-w-0 border border-input bg-surface px-2.5 text-[13px] transition-colors outline-none",
        "placeholder:text-subtle",
        "focus-visible:border-ring",
        "disabled:pointer-events-none disabled:cursor-not-allowed disabled:bg-muted disabled:text-subtle",
        "aria-invalid:border-destructive",
        "file:inline-flex file:h-6 file:border-0 file:bg-transparent file:text-xs file:font-medium file:text-foreground",
        className,
      )}
      {...props}
    />
  );
}

/** Monospaced input for IDs, payloads and numeric values. */
function MonoInput({ className, ...props }: React.ComponentProps<"input">) {
  return <Input className={cn("font-mono tabular", className)} {...props} />;
}

function Textarea({ className, ...props }: React.ComponentProps<"textarea">) {
  return (
    <textarea
      data-slot="textarea"
      className={cn(
        "w-full min-w-0 border border-input bg-surface px-2.5 py-2 text-[13px] transition-colors outline-none",
        "placeholder:text-subtle",
        "focus-visible:border-ring",
        "disabled:pointer-events-none disabled:cursor-not-allowed disabled:bg-muted disabled:text-subtle",
        "aria-invalid:border-destructive",
        className,
      )}
      {...props}
    />
  );
}

export { Input, MonoInput, Textarea };
