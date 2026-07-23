"use client";

import * as React from "react";
import { Toaster as SonnerToaster } from "sonner";
import { Check, Info, TriangleAlert } from "lucide-react";

import { cn } from "@/lib/utils";

type ToasterProps = React.ComponentProps<typeof SonnerToaster>;

/**
 * Toasts report a background action that already finished — never a question,
 * never a validation error. One square black chip, mono-free 12px prose, with
 * the only colour being the success tick.
 *
 * Mounted once globally by Layout.astro — sonner's store is a module-level
 * singleton shared across Astro islands, so a second mount would render every
 * toast twice. Raise them with `toast()` from sonner anywhere.
 */
function Toaster({ position = "bottom-right", toastOptions, ...props }: ToasterProps) {
  return (
    <SonnerToaster
      position={position}
      gap={8}
      icons={{
        success: <Check className="size-3.5 text-success" strokeWidth={2.5} aria-hidden />,
        error: <TriangleAlert className="size-3.5 text-destructive" aria-hidden />,
        warning: <TriangleAlert className="size-3.5 text-warning" aria-hidden />,
        info: <Info className="size-3.5 text-subtle" aria-hidden />,
      }}
      toastOptions={{
        ...toastOptions,
        unstyled: true,
        classNames: {
          toast: cn(
            "flex w-full items-center gap-2.5 border border-primary bg-primary px-3 py-2 text-xs text-primary-foreground",
            toastOptions?.classNames?.toast,
          ),
          icon: cn("flex shrink-0 items-center", toastOptions?.classNames?.icon),
          content: cn("flex min-w-0 flex-col gap-0.5", toastOptions?.classNames?.content),
          title: cn("text-xs", toastOptions?.classNames?.title),
          description: cn("text-[11px] text-subtle", toastOptions?.classNames?.description),
          actionButton: cn(
            "ml-auto shrink-0 border border-primary-foreground/30 px-2 py-0.5 text-[11px] font-medium text-primary-foreground",
            toastOptions?.classNames?.actionButton,
          ),
          cancelButton: cn(
            "shrink-0 px-2 py-0.5 text-[11px] font-medium text-subtle",
            toastOptions?.classNames?.cancelButton,
          ),
          closeButton: cn(
            "shrink-0 border border-primary-foreground/30 bg-primary text-primary-foreground",
            toastOptions?.classNames?.closeButton,
          ),
        },
      }}
      {...props}
    />
  );
}

export { Toaster };
